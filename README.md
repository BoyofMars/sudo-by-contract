<div align="center">

# `[-]` Sudo by Contract

### Give AI agents permission, not credentials.

One action. One server. A few minutes.<br>
Approved by a contract on NEAR. Signed by NEAR's MPC network.<br>
**No SSH certificate authority key exists. Anywhere.**

[![live on NEAR testnet](https://github.com/BoyofMars/sudo-by-contract/actions/workflows/live-hero.yml/badge.svg)](https://github.com/BoyofMars/sudo-by-contract/actions/workflows/live-hero.yml)
[![ci](https://github.com/BoyofMars/sudo-by-contract/actions/workflows/ci.yml/badge.svg)](https://github.com/BoyofMars/sudo-by-contract/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-3dd6b5)](LICENSE)

[**Live console**](https://sudo-by-contract.vercel.app/#/console) ·
[**Verify it yourself**](https://sudo-by-contract.vercel.app/#/proof) ·
[**Try to escape**](https://sudo-by-contract.vercel.app/#/escape) ·
[**How it works**](#how-it-works) ·
[**Roadmap**](#where-this-goes)

</div>

![A live run: the agent's terminal, the on-chain record of the approval and the MPC-signed certificate 4.3 s later, and the approval on a phone](docs/media/live-demo.png)

## AI agents are getting the keys to production

Agents restart services, read logs and fix incidents. To do it, they are handed what humans
were handed: a long-lived SSH key, a root password in an env file, a cloud role that never
expires. It outlives the task, can be copied, and can do anything the account can.
**One prompt injection, and the agent can do anything you can.**

Today you choose between **standing access** (and hope the model behaves) and **a human
approving every command** (and lose the point of an agent). Short-lived certificates help,
but someone still holds the CA key that signs them.

**Sudo by Contract is the third option.** The agent asks for exactly one thing:

> restart `checkout-api` on `prod-web-02`, for 10 minutes, once

A policy contract on NEAR decides. Production needs a person, who approves from a phone.
NEAR's MPC network then signs a short-lived OpenSSH certificate that the contract built itself.
Real OpenSSH accepts it, the restart runs, and that's all it can ever do:

| The agent tries | What happens |
|---|---|
| `sudo systemctl restart checkout-api` | ✅ allowed: exactly what was approved |
| `sudo cat /etc/shadow` | ❌ denied: not an action anyone can authorise |
| `sudo systemctl restart sshd` | ❌ denied: out of scope |
| `sudo systemctl restart checkout-api` (again) | ❌ denied: the single use is spent |
| anything, 10 minutes later | ❌ **refused by sshd itself**: the certificate has expired |

Every allowed and denied command is an event on NEAR. Nothing here is decided by a UI.

## It's live. Not a mock.

This happened on NEAR testnet on 13 November 2026, in a GitHub Actions run against a real
OpenSSH server ([run 43384973437](https://github.com/BoyofMars/sudo-by-contract/actions/runs/43384973437)),
approved from a phone ([request #10 in the console](https://sudo-by-contract.vercel.app/#/console/requests/10?contract=bagyard-sexton.testnet)):

| UTC | Event, read back from the contract |
|---|---|
| 07:20:57 | Deploy Agent requests one restart of `checkout-api`; policy `prod-remediation` requires 1 approval |
| 07:34:24 | **Approved by Tobi** from a phone |
| 07:34:28 | **SSH certificate issued**, serial 11, threshold-signed by the NEAR MPC network **4.3 s** after the approval |
| 07:34:31 | Restart allowed on the host, use 1 of 1; the capability closes |
| 07:34:35 | `cat …` denied: no adapter |
| 07:34:36 | `restart sshd` denied: out of scope |
| 07:34:38 | `restart checkout-api` denied: exhausted |

![The live console for request #10: activity on the host and the full on-chain timeline](docs/media/console-request-10.png)

### A real model, a poisoned log

In a second run ([43387844615](https://github.com/BoyofMars/sudo-by-contract/actions/runs/43387844615))
a real model (`gemini-3.5-flash-lite`) works the incident with capability tools, and the
server's own log carries an indirect prompt injection telling it to run `sudo cat /etc/shadow`
and restart another service. The model flagged it (*"Someone's trying a prompt injection! …
I'm treating this like inert text."*) and didn't act on it.

**It doesn't have to.** The run then replays the injected commands verbatim as a compromised
agent. Every one is denied, and every denial is on-chain:

![The live audit log: the injected commands denied as on-chain events #157 to #159](docs/media/audit-injection-denied.png)

## How it works

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent
    participant C as Contract
    participant H as Human
    participant M as NEAR MPC
    participant S as Server
    A->>C: ask: restart checkout-api, 10 min, once
    C->>C: check policy
    H->>C: approve
    C->>M: sign certificate
    M-->>C: signature (11 of 16)
    C-->>A: SSH certificate
    A->>S: ssh
    S->>C: consume(action)
    C-->>S: allowed, 1 of 1
    S-->>A: restarted
```

![Authority exists only inside a window: request, evaluate, approve, issue, execute, observe, expire](docs/media/how-it-works.png)

| | |
|---|---|
| **No standing privilege** | Agents hold nothing until a capability is approved: one typed action, one host, N uses, one window. |
| **No CA key** | Each environment's SSH CA is an Ed25519 key the NEAR MPC network derives for the contract's account. Only the contract can ask for signatures, and it signs only certificate bodies it builds from approved requests. |
| **Enforced on the host** | sshd checks the CA, principal, validity and revocation list and forces every session into `sbc-gate`. The gate parses commands with a closed grammar (no shell, ever) and calls `consume()` on-chain before each one. Exact `sudoers` lines do the rest. |
| **Auditable by anyone** | Policy versions and hashes, approvals, certificates and every allowed or denied command are NEP-297 events in a hash-chained, on-chain log. Private evidence stays off-chain, committed by hash. |
| **Agent-native** | SDK, CLI and an MCP server. The agent asks with a reason; the approver sees exactly what will run. |

## Why it only works on NEAR

* **Chain Signatures make the CA a program, not a party.** The CA key is derived by NEAR's MPC
  network for the policy contract's account (FROST Ed25519, 11 of 16 independent nodes in TEEs).
  No person, server or company ever holds it, and the rules for what gets signed are public
  contract code anyone can read and re-execute.
* **Function-call access keys are the identity layer.** Agent, approver, admin and server each
  hold a key the NEAR protocol itself restricts to a few methods and a gas allowance. None can
  move funds, deploy code or add keys:

  | Role | Held by | Can call | Gas allowance |
  |---|---|---|---|
  | Agent | the AI agent | `request_access`, `cancel_request` | 1 NEAR |
  | Approver | a person's phone or browser (non-extractable WebCrypto key) | `approve`, `deny`, `revoke` | 1 NEAR |
  | Admin | a person's device | policy, identity and resource management; `approve`, `deny`, `revoke` | 2 NEAR |
  | Gate | `sbc-gate` on one host | `consume`, `report_denial`, `heartbeat` | 2 NEAR |
  | Enrollment | a one-time join link (expires within 7 days) | `complete_enrollment`, which swaps it for the real key | 0.25 NEAR |

  So the agent's key can only *ask*. It cannot approve its own request, reach a host, or get a
  certificate any other way.
* **The audit trail lives on a public ledger.** A customer, an auditor or a regulator can check
  what was allowed and what happened without trusting the operator's database.

## Verify it yourself

| Do | See |
|---|---|
| Open [**/#/proof**](https://sudo-by-contract.vercel.app/#/proof) | Your browser asks NEAR directly: the CA key the MPC network derives for the contract, that another account gets a different key, and a real issued certificate's Ed25519 signature. **7 of 7 checks in ~2 s**, no account, no server of ours. |
| Open [**Try to escape**](https://sudo-by-contract.vercel.app/#/escape) | You are the agent, with one capability. Try `sudo cat /etc/shadow`, `sudo -i`, `…; id`, `restart sshd`. The parser and the executed argv are the gate's real Rust code compiled to WebAssembly. `0 escaped`. |
| Open the [**console**](https://sudo-by-contract.vercel.app/#/console) | Every capability, approval, certificate and denial, read live from the contract. **Try simulation** opens a labelled sandbox where you can approve, deny and revoke. |
| Open the latest [**live-hero run**](https://github.com/BoyofMars/sudo-by-contract/actions/workflows/live-hero.yml) | Every 8 hours, unattended: a real host on a GitHub runner, a real agent, the deployed contract and MPC signer. After the window closes, **sshd itself** refuses the certificate. The job summary reads it all back from the chain. |
| `npm ci && npm run judge` | Everything that runs from a clone, in one command: the Rust and TypeScript suites and the live testnet check, each claim printed next to its evidence. `--offline` skips the network. Needs Node ≥ 23.6 (`.nvmrc`) and Rust (`rust-toolchain.toml`). |
| `npm ci && npm run verify:live` | The proof page's seven checks from a terminal, plus OpenSSH's own `ssh-keygen -L` accepting the MPC-signed certificate. |

![The public proof page: 7 of 7 checks verified live from the browser](docs/media/proof-page.png)

### What is tested, and how

| Claim | Evidence |
|---|---|
| NEAR's MPC network can act as an OpenSSH CA | The MPC contract's `sign` with `payload_v2.Eddsa` (≤ 1232 bytes) and standard Ed25519 verification against the derived key; the live testnet signer reports domain 1 = FROST Ed25519, threshold 11. |
| Our certificates are real OpenSSH certificates | `ssh-keygen -L` accepts certificates built by `sbc-core` (the code the contract runs); one flipped bit is rejected with `incorrect signature`; re-encoding an `ssh-keygen -s` certificate reproduces its signed bytes exactly (`crates/sbc-core/examples/interop.rs`). |
| Policy, approvals, signing, `consume`, expiry, revocation, host binding, admin quorum, identity removal | 32 contract tests with a simulated MPC callback carrying real Ed25519 signatures (`contracts/sbc-policy/src/tests.rs`). |
| The gate enforces it | 10 unit and 11 integration tests against mock NEAR RPCs that verify every transaction signature: the hero sequence, independent certificate checks, host ceiling, serial 0, fail-closed, re-provisioning from an enrolled key, and resending only transactions that were never executed (`crates/sbc-gate/tests/`). |
| Revocation reaches sshd | A KRL built from revoked serials makes `ssh-keygen -Q` report `REVOKED`. |
| No wallet needed | Hand-written borsh transactions match `@near-js/transactions` byte for byte; WebCrypto Ed25519 signing in the browser and Node. |
| Real sshd | **14 of 14** in CI on Linux (`sandbox/ci/sshd-integration.sh`): the approved restart runs; `cat /etc/shadow`, out-of-scope, second-use and injected commands are denied; shells, PTYs and port forwarding are refused; sshd itself rejects expired, wrong-host, revoked and certificate-less logins. |
| Live testnet, end to end | **22 of 22** with `scripts/e2e-testnet.ts`, then the scheduled live-hero runs. The first live run caught two bugs the offline tests missed; both are fixed ([docs/LIVE_RUN.md](docs/LIVE_RUN.md)). |
| All of it | **74 Rust tests** (`cargo test --workspace`) and **43 TypeScript tests** (`npm test`); `tsc` clean. |

## Where this goes

SSH is the start. The capability (one typed action, one target, N uses, one window, approved
by policy and people, enforced by `consume`) doesn't care about the protocol. Anywhere an
agent needs power for a moment, not forever, the same loop fits.

**Shipped**
* SSH with typed actions: `service.restart`, `service.status`, `logs.read`
* SDK, CLI and MCP server for agents; phone approvals with device keys (no wallet)
* k-of-n admin quorum, revocation down to sshd's KRL, a public proof page, live CI on testnet

**Next**
* **Kubernetes:** `k8s.rollout_restart:<namespace>/<deployment>` through an admission webhook
  or exec proxy that calls `consume` before anything changes.
* **Databases:** one migration or one query class, for one window, on one database.
* **Cloud consoles and APIs:** short-lived role sessions on AWS, GCP and Azure, minted only for
  an approved action and gated by `consume`.
* **Approvals where on-call already lives:** Slack and PagerDuty cards that show exactly what
  will run; web push for the console.
* **Attested conditions:** "only while an incident is open", "only after CI passed", checked by
  the contract from signed attestations.

**Later**
* **Mainnet**, with the contract account locked and upgrades behind a multisig and timelock.
* **Cross-organisation agents:** enroll a vendor's SRE agent under *your* policy, with no
  identity federation and no trust in their CA. Both sides can verify what happened.
* **Private targets:** service names committed by hash, so infrastructure topology never
  appears on-chain.
* **Break-glass** policies with stricter approvals and mandatory review; **TPM-bound** host keys.
* **A verified policy library:** audited, reusable policies ("restart one service with one
  approval") referenced by on-chain hash.

More in [docs/COMPARISON.md](docs/COMPARISON.md), including what Teleport, Vault, StrongDM and
others do well and where trust sits in each.

## Honest limits

* **Contract upgradeability.** Whoever can deploy code to the contract account controls the CA.
  Production must lock the account or govern upgrades with a multisig and timelock.
* **Latency.** Each privileged command costs one NEAR transaction (~1–2 s): the right trade for
  rare, dangerous actions, not for chatty reads.
* **Availability.** If NEAR or the MPC network is unavailable, nothing new is issued and the gate
  denies everything. Fail-closed is deliberate.
* **Scope.** SSH with three typed actions today. Kubernetes, databases and cloud APIs are the
  roadmap above.
* **Public metadata.** Resource and service identifiers are on-chain; use aliases where topology
  is sensitive ([docs/PRIVACY.md](docs/PRIVACY.md)).

## Repository

| Path | |
|---|---|
| [`contracts/sbc-policy`](contracts/sbc-policy) | NEAR policy contract (Rust): identities as scoped access keys, policy evaluation, capability state machine, certificate construction, MPC signing and verification, `consume`, revocation, audit chain |
| [`crates/sbc-core`](crates/sbc-core) | Shared by contract and gate: OpenSSH certificate encoding, the closed command grammar, identifier grammars, redaction |
| [`crates/sbc-gate`](crates/sbc-gate) | Host enforcement: sshd forced command, `enroll`, `sync` (heartbeat + KRL), `check`, `sudoers`, `sshd-config` |
| [`crates/sbc-wasm`](crates/sbc-wasm) | The gate's logic compiled to WebAssembly (72 KB) for the in-browser escape playground |
| [`packages/sbc-client`](packages/sbc-client) | Isomorphic NEAR and OpenSSH client: borsh, WebCrypto Ed25519, typed contract API |
| [`packages/sbc-agent`](packages/sbc-agent) | Agent SDK: request → wait → exec → release |
| [`apps/sbc-mcp`](apps/sbc-mcp) | MCP server exposing capability tools to AI agents |
| [`apps/sudoctl`](apps/sudoctl) | CLI for agents, approvers and admins |
| [`apps/console`](apps/console) | Web console and landing page: phone approvals, policy builder, enrollment, audit, proof |
| [`apps/relay`](apps/relay) | Private evidence, redacted gate reports, notifications (never in the authorisation path) |
| [`apps/demo-agent`](apps/demo-agent) | The narrated Deploy Agent, including the real-model prompt-injection act |
| [`sandbox/`](sandbox) | Docker: a real OpenSSH server, relay, console and agent |
| [`docs/`](docs) | [Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md) · [Failure modes](docs/FAILURE_MODES.md) · [Privacy](docs/PRIVACY.md) · [Policy model](docs/POLICY.md) · [API](docs/API.md) · [Demo](docs/DEMO.md) · [Comparison](docs/COMPARISON.md) · [Live run](docs/LIVE_RUN.md) |

| | |
|---|---|
| **Contract** | [`bagyard-sexton.testnet`](https://testnet.nearblocks.io/address/bagyard-sexton.testnet) (NEAR testnet) |
| **MPC signer** | [`v1.signer-prod.testnet`](https://testnet.nearblocks.io/address/v1.signer-prod.testnet) (Chain Signatures, Ed25519 domain) |
| **Production SSH CA** | `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICA7lQ5yFKYgWPJFZuI9RVDrWMKp6z/qtIgOw2AHU2qR`, derived by the MPC network for the contract; no private key exists |

## Hackathon

* Built at **NEAR HACKATHON** (November 2026) for the **AI Security & Defense** and **Open Innovation** tracks.
* **All code in this repository was written during the hackathon** (first commit 2026-11-10). No pre-existing code, starter template or boilerplate.
* **Built with:** Rust: `near-sdk` 5.30 (contract); `ed25519-dalek`, `sha2`, `base64`, `bs58`, `hex`, `serde`/`serde_json`, `toml`, `ureq` (gate). TypeScript on Node 26: borsh, NEAR transactions and OpenSSH encoding are hand-written (`@near-js/crypto` and `@near-js/transactions` are dev-only, to check our bytes match); the only runtime npm dependencies are the model SDKs for the demo agent's model act, `@google/genai` (Gemini) and `@anthropic-ai/sdk` (Claude). Console: React 19, Vite 8, Inter and JetBrains Mono via Fontsource. Tooling: `cargo-near`, `near-cli-rs`, OpenSSH, Docker, GitHub Actions, Vercel.
* **NEAR integration:** the policy contract runs on NEAR testnet; **NEAR Chain Signatures** (MPC, Ed25519 domain) is the SSH certificate authority, with the CA key derived for the contract's account; **function-call access keys** on the contract account are the identity layer for admins, approvers, agents and hosts; every authorisation event is a NEP-297 event in a hash-chained, on-chain audit log.
* The author's other, independent submission is **[Necropolis](https://github.com/BoyofMars/necropolis)**: a graveyard for dead memecoins on Solana and Base, with burials verified by NEAR's MPC network.

License: [MIT](LICENSE).
