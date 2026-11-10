# Architecture

> **Programmable, auditable, ephemeral machine authority.**
> An agent never receives a credential that outlives, out-scopes or out-places the
> one action a policy approved — and no SSH certificate authority key exists
> anywhere to steal.

## The flow

```
Request → Evaluate → Approve → Issue → Execute → Observe → Expire
```

```mermaid
sequenceDiagram
    autonumber
    participant A as AI agent (SDK / CLI / MCP)
    participant C as Policy contract (NEAR)
    participant H as Human approver (console, device key)
    participant M as NEAR MPC network (TEE nodes, threshold Ed25519)
    participant S as Host: sshd + sbc-gate

    A->>A: generate ephemeral Ed25519 SSH key (never leaves the agent)
    A->>C: request_access(resource, action, 10m, key, reason, context_hash)
    C->>C: evaluate deny/allow policies → checks[] (identity, resource, action, target, duration, uses, schedule, approval)
    H->>C: approve(request_id)   (signed by a non-extractable WebCrypto device key)
    C->>C: build OpenSSH certificate body (TBS): serial = request id,<br/>principal sbc-<resource>, valid now-60s…now+10m,<br/>force-command sbc-gate, no extensions
    C->>M: sign({payload_v2: {Eddsa: TBS}, path: sbc/ssh-user-ca/v1/production, domain_id: 1})
    M-->>C: Ed25519 signature (threshold, inside TEEs)
    C->>C: ed25519_verify(sig, TBS, environment CA key) → certificate → Active
    A->>C: get_request → certificate
    A->>S: ssh -i ephemeral -o CertificateFile=… sbc-agent@host "sudo systemctl restart checkout-api"
    S->>S: sshd: CA trusted? principal listed? within validity? not in KRL?
    S->>S: ForceCommand sbc-gate: re-verify cert, parse command → service.restart:checkout-api
    S->>C: consume(request_id, "service.restart:checkout-api")  (gate's role key)
    C-->>S: {allowed: true, uses: 1/1}  → state Exhausted
    S->>S: execve(/usr/bin/sudo -n /usr/bin/systemctl restart checkout-api)
    S-->>A: exit code
    Note over C,S: time passes: sshd rejects the expired certificate itself;<br/>consume() would answer "expired" anyway
```

## Components

| Component | Where | What it is trusted for |
|---|---|---|
| **Policy contract** `contracts/sbc-policy` | NEAR (Rust → wasm) | Identities, policies, request state machine, building every certificate body, verifying MPC signatures, per-action authorisation (`consume`), revocation, hash-chained audit. |
| **NEAR MPC network** `v1.signer-prod.testnet` / `v1.signer` | NEAR + TEE nodes | Threshold Ed25519 signing (FROST, domain 1). Holds key shares; signs only payloads requested *by the contract account*, under keys derived for that account. |
| **sbc-gate** `crates/sbc-gate` | Every enrolled host | sshd `ForceCommand`. Re-verifies the presented certificate, maps the command to one typed action, enforces the host-local ceiling, calls `consume` before executing a fixed argv, fails closed. Also `enroll` and `sync` (heartbeat + KRL). |
| **sbc-core** `crates/sbc-core` | Contract *and* gate | OpenSSH certificate encoding/parsing, the closed command grammar, identifier grammars, redaction. One definition of "what was approved" and "what is enforced". |
| **@sbc/client** `packages/sbc-client` | Browser + Node | Borsh transactions + WebCrypto Ed25519 (no wallet, no SDK), typed contract client, OpenSSH key/cert helpers, shared human phrasing. |
| **Agent SDK / sudoctl / MCP server** | Agent runtimes, terminals | Request capabilities programmatically, wait, execute over SSH with the ephemeral key, release. |
| **Relay** `apps/relay` | Operator-run | Private context documents (rationale/evidence, committed on-chain by hash), redacted gate reports, notifications (SSE, Slack-style webhooks). Never in the authorisation path. |
| **Console** `apps/console` | Browser (PWA) | Human surface: approvals, active access, revocation, policy builder, enrollment, audit. Signs with a non-extractable device key. |

## NEAR is load-bearing, not decorative

### 1. A certificate authority with no private key

Every environment (`production`, `staging`, …) has an SSH user CA whose public key is

```
derived_public_key(path = "sbc/ssh-user-ca/v1/<env>", predecessor = <policy contract>, domain_id = 1)
```

on the MPC contract. We verified against the live testnet signer (`v1.signer-prod.testnet`):
domain 1 is `Frost` (Ed25519) with reconstruction threshold 11; `sign` accepts
`payload_v2: {"Eddsa": "<hex>"}` up to **1232 bytes** and returns
`{"scheme":"Ed25519","signature":[64 bytes]}`, which the MPC contract itself checks with
*standard* Ed25519 verification against the derived key. An OpenSSH Ed25519 user
certificate body is ~330 bytes, and OpenSSH verifies it with standard Ed25519 — so the
MPC signature can be dropped straight into the certificate. No format transformation,
no wrapper CA.

Consequences:

* **No `SSH_CA_PRIVATE_KEY` anywhere.** Not in this repo, not on a server, not in an HSM
  we operate. Shares live inside the MPC network's TEEs.
* **Only the contract can obtain signatures under its CA keys**, because MPC key
  derivation binds the derived key to the calling account (`predecessor`).
* **The contract signs only what it constructs.** `begin_signing` builds the certificate
  body from the approved request; agents supply only their ephemeral public key (and,
  if policy allows, a source address). There is no "sign this blob" entry point.
* **The signature is verified before issuance** (`env::ed25519_verify` in `on_signed`). A
  wrong or forged response marks the request `Failed`; nothing is issued.

### 2. Identities are scoped NEAR access keys

NEAR accounts can hold many *function-call access keys*, each restricted by the protocol
to specific methods on a specific receiver. Sudo by Contract uses that as its identity
layer: every admin device, approver device, agent and host gate is a key **on the
contract account itself**, added by the contract when an enrollment token is spent.

| Role | Methods the protocol allows the key to call |
|---|---|
| Admin | policies, resources, agents, approvers, enrollment tokens, environments, approve/deny/revoke |
| Approver | `approve`, `deny`, `revoke` |
| Agent | `request_access`, `cancel_request` |
| Gate | `consume`, `report_denial`, `heartbeat` |
| Enrollment token | `complete_enrollment` (one-shot, expiring) |

The contract additionally maps `env::signer_account_pk()` → role + principal and checks
both. Keys cannot attach deposits and have gas allowances, which bounds abuse. Humans
use WebCrypto Ed25519 keys generated **non-extractable** in the browser: no wallet, no
seed phrase, nothing to copy out of the page.

### 3. Enforcement is anchored on-chain per action

The gate calls `consume(request_id, action)` before every execution. That single call is
where these become real, for every host, with no host-local state to tamper with:

* **scope** — `action` must equal the approved canonical action;
* **single use / N uses** — the counter lives in the contract;
* **expiry** — checked against block time (sshd also checks the certificate window);
* **revocation** — immediate on the next command; sshd also gets a KRL within ~30 s;
* **host binding** — the caller's gate key must belong to the capability's resource;
* **kill switch** — a `Disabled` resource refuses everything.

### 4. Audit with integrity

Every transition emits a NEP-297 `EVENT_JSON` log and extends a hash chain
(`audit_head = sha256(audit_head ‖ event)`), stored in contract state alongside a
per-request event history. Policies are versioned and hashed; each request records the
policy id, version and hash it was evaluated against.

## Host enforcement in depth

The agent connects as `sbc-agent`, a user with no password, no `authorized_keys` and no
shell access:

| Layer | Mechanism | Stops |
|---|---|---|
| sshd | `TrustedUserCAKeys` = environment CA (MPC-derived) | any key not certified by policy |
| sshd | `AuthorizedPrincipalsFile` → only `sbc-<resource>` | certificates for other hosts |
| sshd | certificate validity window | use after expiry |
| sshd | `RevokedKeys` KRL (serials synced from `list_revocations`) | revoked certificates, even at login |
| sshd | `ForceCommand sbc-gate` (and the certificate's own `force-command`) | arbitrary commands, shells |
| sshd | no PTY/forwarding: `PermitTTY no`, `AllowTcpForwarding no`, …; certificate carries **no** extensions | tunnels, agent forwarding, interactive sessions |
| gate | independent certificate verification from `SSH_USER_AUTH` | misconfigured sshd |
| gate | closed command grammar (`sbc-core::action`) | `;`, `|`, `$()`, quotes, `--` option injection, `sudo -u/-s/-i`, path tricks |
| gate | host-local service ceiling (`services` in gate.toml) | a compromised policy admin widening what a host exposes |
| gate | `consume()` before execution | scope, uses, expiry, revocation, host binding |
| OS | `sudo -n` with **exact** sudoers lines, no wildcards | anything beyond the enrolled actions, even from the gate |
| OS | `execve` of a fixed argv, scrubbed env, timeout | shell interpretation, env injection, runaway processes |

**Root is not the default.** The agent never has root or a shell. For a service restart
it holds, for the duration of one command, a path through sudo to exactly
`/usr/bin/systemctl restart checkout-api`.

## Capability state machine

```
                    ┌──────────── Rejected (policy)
request_access ─────┤
                    ├── PendingApproval ──approve(n of m)──┐
                    │        │  │                          │
                    │        │  └─ deny ──▶ Denied         │
                    │        └─ (ttl) ──▶ ApprovalExpired  │
                    └── (auto) ─────────────────────────────┴──▶ Signing ──MPC ok──▶ Active
                                                                   │                  │
                                                     MPC fail ─▶ Failed     consume ×N ─▶ Exhausted
                                                                                      │
                                              revoke (any live state) ─▶ Revoked      ├─ (time) ─▶ Expired
                                              cancel_request (agent)  ─▶ Cancelled    │
```

`Expired` and `ApprovalExpired` are computed lazily from block time in every view and
persisted (with their audit event) the next time the request is touched.

## Policy model

See [POLICY.md](POLICY.md). In short: who (agents) × what (typed actions and targets) ×
where (resource ids, environments, tags) × how long × how many uses × which approvals ×
conditions (UTC window, source-address binding). Deny wins; nothing is allowed by
default; over-asks are rejected rather than clamped.

## The abstraction: capabilities, with SSH as the first adapter

The contract never reasons about SSH except when it builds the certificate. The core
objects — typed action, resource, capability (window × uses × scope × approvals) and the
`consume` check — are protocol-agnostic. Adding Kubernetes means a new action family
(`k8s.rollout_restart:<ns>/<deployment>`), a credential format the MPC network can sign
(e.g. a short-lived JWT for a projected service-account token exchange, or an X.509
client certificate once a suitable signature domain exists), and an enforcement point
that calls `consume`. See [COMPARISON.md](COMPARISON.md#roadmap).

## Performance

| Step | Typical latency (testnet) |
|---|---|
| `request_access` (included) | ~1–2 s |
| final `approve` → MPC signature → `Active` | a few seconds (yield/resume round trip) |
| per command: `consume` before execution | ~1–2 s (one transaction) |

Per-command on-chain authorisation is the price of making single-use and revocation
authoritative across hosts. It is the right trade for privileged, infrequent actions —
the ones that need this — and the wrong one for high-frequency reads (see roadmap:
locally-verifiable read-only capabilities).
