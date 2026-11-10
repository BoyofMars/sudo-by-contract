# Sudo by Contract

**Give agents permission, not credentials.**

An AI agent asks to restart one service on one server for ten minutes. A policy on NEAR
approves exactly that, a human taps approve, and the NEAR MPC network signs a short-lived
OpenSSH certificate that the contract itself built. The agent restarts the service. It
cannot read `/etc/shadow`, cannot restart `sshd`, cannot restart the service a second
time, and cannot do anything at all after ten minutes. **No SSH certificate authority
private key exists anywhere** to leak, steal or misuse.

```
Request → Evaluate → Approve → Issue → Execute → Observe → Expire
```

| | |
|---|---|
| **Contract** | [`bagyard-sexton.testnet`](https://testnet.nearblocks.io/address/bagyard-sexton.testnet) (NEAR testnet) |
| **MPC signer** | [`v1.signer-prod.testnet`](https://testnet.nearblocks.io/address/v1.signer-prod.testnet) (Chain Signatures, Ed25519 domain) |
| **Production SSH CA** | `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICA7lQ5yFKYgWPJFZuI9RVDrWMKp6z/qtIgOw2AHU2qR` — derived by the MPC network for the contract; no private key exists |
| **Live verification** | 22/22 checks against testnet: [docs/LIVE_RUN.md](docs/LIVE_RUN.md) |

| | Mechanism |
|---|---|
| **No standing privilege** | Agents hold no credential until a capability is approved; it carries one typed action, one host, N uses, a window. |
| **No CA key** | Each environment's SSH user CA is an Ed25519 key the NEAR MPC network derives for the policy contract's account. Only the contract can request signatures, and it only signs certificate bodies it constructs from approved requests. |
| **Enforced on the host** | sshd (CA, principal, validity, KRL, ForceCommand, no PTY/forwarding) → `sbc-gate` (closed command grammar, host ceiling) → `consume()` on-chain before every execution → exact sudoers lines. Denials do not come from a UI. |
| **Auditable** | Policy versions + hashes, approvals, issuance, every allowed and denied command — on-chain, hash-chained. Private evidence stays off-chain, committed by hash. |
| **Agent-native** | SDK, CLI and an MCP server: agents request capabilities with a reason and evidence; humans approve exactly what will run. |

## What is verified, and how

| Claim | Evidence |
|---|---|
| The NEAR MPC network can act as an OpenSSH CA | Read the MPC contract source (`sign` with `payload_v2.Eddsa`, ≤ 1232 bytes; standard Ed25519 verification against the derived key) and queried the live testnet signer: domain 1 = Frost/Ed25519, threshold 11. |
| Our certificates are real OpenSSH certificates | `ssh-keygen -L` accepts certificates built by `sbc-core` (the code the contract runs); a single flipped bit is rejected with `incorrect signature`; re-encoding an `ssh-keygen -s` certificate reproduces its signed bytes exactly (`crates/sbc-core/examples/interop.rs`). |
| Policy, approvals, signing, consume, expiry, revocation, host binding, admin quorum | 28 contract tests with a simulated MPC callback carrying real Ed25519 signatures (`contracts/sbc-policy/src/tests.rs`). |
| The gate enforces it | 8 unit + 5 end-to-end gate tests against a mock NEAR RPC that verifies every transaction signature: hero sequence, independent certificate checks, host ceiling, serial 0, fail-closed (`crates/sbc-gate/tests/exec_flow.rs`). |
| Revocation reaches sshd | KRL produced from revoked serials makes `ssh-keygen -Q` report `REVOKED`. |
| No wallet needed | Hand-written borsh transactions match `@near-js/transactions` byte-for-byte; WebCrypto Ed25519 signing in browser and Node. |
| SDK, CLI, relay, MCP | 33 offline tests; `tsc` clean. |
| Live testnet end-to-end | **22/22** with `scripts/e2e-testnet.ts`: the testnet MPC network signed the certificate 6.7 s after approval, `ssh-keygen` verified it, and the real gate binary enforced scope, single use, revocation (→ KRL) and expiry through the deployed contract. The first live run caught two bugs the offline tests missed; both are fixed ([docs/LIVE_RUN.md](docs/LIVE_RUN.md)). |
| Real sshd | `sandbox/ci/sshd-integration.sh` runs OpenSSH with the generated config in CI (Linux). Not run on the Windows machine this was built on. |

Run everything that runs offline:

```bash
cargo test --workspace
```

```bash
npm test
```

## Repository

| Path | |
|---|---|
| `contracts/sbc-policy` | NEAR policy contract (Rust): identities as scoped access keys, policy evaluation, capability state machine, certificate construction, MPC signing + verification, `consume`, revocation, audit chain |
| `crates/sbc-core` | Shared by contract and gate: OpenSSH certificate encoding/parsing, closed command grammar, identifier grammars, redaction |
| `crates/sbc-gate` | Host enforcement binary: sshd forced command, `enroll`, `sync` (heartbeat + KRL), `check`, `sudoers`, `sshd-config` |
| `packages/sbc-client` | Isomorphic NEAR + OpenSSH client (borsh, WebCrypto Ed25519, typed contract API) |
| `packages/sbc-agent` | Agent SDK: request → wait → exec → release |
| `apps/sudoctl` | CLI for agents, approvers and admins |
| `apps/relay` | Private evidence + redacted gate reports + notifications (never in the authorisation path) |
| `apps/sbc-mcp` | MCP server exposing capability tools to AI agents |
| `apps/demo-agent` | The narrated "Deploy Agent" for the hero demo |
| `apps/console` | Web console + landing page (PWA, mobile approvals, policy builder, enrollment, audit) |
| `sandbox/` | Docker: real OpenSSH demo server, relay, console, agent |
| `scripts/` | `bootstrap-testnet.ts`, `e2e-testnet.ts` |
| `docs/` | [Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [Failure modes](docs/FAILURE_MODES.md) · [Privacy](docs/PRIVACY.md) · [Policy model](docs/POLICY.md) · [API](docs/API.md) · [Demo](docs/DEMO.md) · [Comparison & roadmap](docs/COMPARISON.md) |

## Honest limits

* **Contract upgradeability.** Whoever can deploy code to the contract account controls the
  CA. Production must lock the account or govern upgrades with a multisig + timelock.
* **Latency.** Each privileged command costs one NEAR transaction (~1–2 s). The right
  trade for rare, dangerous actions, not for chatty reads.
* **Availability.** If NEAR or the MPC network is unavailable, nothing new is issued and
  the gate denies everything. That is deliberate.
* **Scope.** SSH with three typed actions today (`service.restart`, `service.status`,
  `logs.read`). The capability model is protocol-agnostic; Kubernetes, databases and cloud
  APIs are roadmap adapters.
* **Public metadata.** Resource and service identifiers are on-chain; use aliases where
  topology is sensitive ([PRIVACY.md](docs/PRIVACY.md)).

License: Apache-2.0.
