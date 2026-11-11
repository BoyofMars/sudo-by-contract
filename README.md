# Sudo by Contract

[![live on NEAR testnet](https://github.com/BoyofMars/sudo-by-contract/actions/workflows/live-hero.yml/badge.svg)](https://github.com/BoyofMars/sudo-by-contract/actions/workflows/live-hero.yml)
[![ci](https://github.com/BoyofMars/sudo-by-contract/actions/workflows/ci.yml/badge.svg)](https://github.com/BoyofMars/sudo-by-contract/actions/workflows/ci.yml)

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
| **Live site** | [sudo-by-contract.vercel.app](https://sudo-by-contract.vercel.app) — landing, [proof page](https://sudo-by-contract.vercel.app/#/proof), and the [console](https://sudo-by-contract.vercel.app/#/console) on the real testnet contract (read-only for visitors; a labelled interactive simulation is one click away) |
| **Tracks** | AI Security & Defense · Open Innovation |
| **Contract** | [`bagyard-sexton.testnet`](https://testnet.nearblocks.io/address/bagyard-sexton.testnet) (NEAR testnet) |
| **MPC signer** | [`v1.signer-prod.testnet`](https://testnet.nearblocks.io/address/v1.signer-prod.testnet) (Chain Signatures, Ed25519 domain) |
| **Production SSH CA** | `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICA7lQ5yFKYgWPJFZuI9RVDrWMKp6z/qtIgOw2AHU2qR` — derived by the MPC network for the contract; no private key exists |
| **Live verification** | 22/22 checks against testnet: [docs/LIVE_RUN.md](docs/LIVE_RUN.md). Every 8 hours, unattended: [live-hero](https://github.com/BoyofMars/sudo-by-contract/actions/workflows/live-hero.yml) boots `prod-web-02` (real OpenSSH + `sbc-gate`) on a GitHub runner and runs an agent against the deployed contract and MPC signer |

## Try it in two minutes

| Do | See |
|---|---|
| Open [sudo-by-contract.vercel.app](https://sudo-by-contract.vercel.app) → **Try to escape** | You hold one capability (restart `checkout-api`, once, 10 min). Type `sudo cat /etc/shadow`, `sudo -i`, `…; id`, `restart sshd`. Each layer decides in turn; the parser and the executed argv are the gate's real Rust code (`sbc-core`) compiled to WebAssembly. `0 escaped`. |
| Open [/#/proof](https://sudo-by-contract.vercel.app/#/proof) | Your browser asks NEAR's MPC contract for the CA key, checks it matches what the policy contract uses, shows another account derives a different key, and verifies a real issued certificate's Ed25519 signature. **7/7 in ~2 s**, no account. |
| `npm ci && npm run verify:live` | The same seven checks from a terminal, plus `ssh-keygen -L` (OpenSSH) accepting the MPC-signed certificate. No keys, no accounts. |
| Open the latest [live-hero run](https://github.com/BoyofMars/sudo-by-contract/actions/workflows/live-hero.yml) | A real host on a GitHub runner: the agent asks for a 60-second status capability, the MPC network signs the certificate (~4 s), the command runs through the gate, and after the window closes **sshd itself** refuses the certificate. The job summary reads every capability back from the contract. |
| `cargo test --workspace` and `npm test` | 71 Rust tests (contract lifecycle with a simulated MPC callback, gate end-to-end against a signature-checking mock RPC, OpenSSH encoding) and 34 TypeScript tests. |
| [Console](https://sudo-by-contract.vercel.app/#/console) | Real capabilities, denials and certificates, read straight from the contract (test fixtures from the end-to-end run are one click away). **Try the simulation** opens a labelled sandbox where you can approve, deny and revoke. |

| | Mechanism |
|---|---|
| **No standing privilege** | Agents hold no credential until a capability is approved; it carries one typed action, one host, N uses, a window. |
| **No CA key** | Each environment's SSH user CA is an Ed25519 key the NEAR MPC network derives for the policy contract's account. Only the contract can request signatures, and it only signs certificate bodies it constructs from approved requests. |
| **Enforced on the host** | sshd (CA, principal, validity, KRL, ForceCommand, no PTY/forwarding) → `sbc-gate` (closed command grammar, host ceiling) → `consume()` on-chain before every execution → exact sudoers lines. Denials do not come from a UI. |
| **Auditable** | Policy versions + hashes, approvals, issuance, every allowed and denied command — on-chain, hash-chained. Private evidence stays off-chain, committed by hash. |
| **Agent-native** | SDK, CLI and an MCP server: agents request capabilities with a reason and evidence; humans approve exactly what will run. |

## What each key can do

Every identity is a NEAR function-call access key on the contract account. The NEAR protocol itself refuses any call outside a key's method list, and a key can spend only its gas allowance: none can transfer funds, deploy code or add keys. The contract then checks which identity the key is bound to.

| Role | Held by | Can call | Gas allowance |
|---|---|---|---|
| Agent | the AI agent | `request_access`, `cancel_request` | 1 NEAR |
| Approver | a person's phone or browser (non-extractable WebCrypto key) | `approve`, `deny`, `revoke` | 1 NEAR |
| Admin | a person's device | policy, identity and resource management; `approve`, `deny`, `revoke` | 2 NEAR |
| Gate | `sbc-gate` on one host | `consume`, `report_denial`, `heartbeat` | 2 NEAR |
| Enrollment | a one-time join link (expires within 7 days) | `complete_enrollment`, which swaps it for the real key | 0.25 NEAR |

So the agent's key can only ask. It cannot approve its own request, cannot reach a host, and cannot obtain a certificate except through a request a policy and a person have approved.

## Fit with the tracks

* **AI Security & Defense.** The track asks for policy engines, sandboxed keys and limits on what an agent can do. Here the policy engine is the contract, the sandboxed keys are the function-call keys above, and each capability is limited to one typed action on one host, N uses, and a time window. Out-of-scope attempts are refused by sshd, the gate and the contract, and recorded on-chain (try them in the [escape playground](https://sudo-by-contract.vercel.app/#/escape)).
* **Open Innovation.** NEAR Chain Signatures used as an OpenSSH certificate authority: the MPC network signs Ed25519 certificate bodies that the contract builds from approved requests. No CA private key exists, and the rules for what gets signed are public contract code anyone can audit.

## What is verified, and how

| Claim | Evidence |
|---|---|
| The NEAR MPC network can act as an OpenSSH CA | Read the MPC contract source (`sign` with `payload_v2.Eddsa`, ≤ 1232 bytes; standard Ed25519 verification against the derived key) and queried the live testnet signer: domain 1 = Frost/Ed25519, threshold 11. |
| Our certificates are real OpenSSH certificates | `ssh-keygen -L` accepts certificates built by `sbc-core` (the code the contract runs); a single flipped bit is rejected with `incorrect signature`; re-encoding an `ssh-keygen -s` certificate reproduces its signed bytes exactly (`crates/sbc-core/examples/interop.rs`). |
| Policy, approvals, signing, consume, expiry, revocation, host binding, admin quorum, identity removal | 32 contract tests with a simulated MPC callback carrying real Ed25519 signatures (`contracts/sbc-policy/src/tests.rs`). |
| The gate enforces it | 9 unit + 9 integration gate tests against mock NEAR RPCs that verify every transaction signature: hero sequence, independent certificate checks, host ceiling, serial 0, fail-closed, re-provisioning from an enrolled key (`crates/sbc-gate/tests/`). |
| Revocation reaches sshd | KRL produced from revoked serials makes `ssh-keygen -Q` report `REVOKED`. |
| No wallet needed | Hand-written borsh transactions match `@near-js/transactions` byte-for-byte; WebCrypto Ed25519 signing in browser and Node. |
| SDK, CLI, relay, MCP | 34 offline tests; `tsc` clean. |
| Live testnet end-to-end | **22/22** with `scripts/e2e-testnet.ts`: the testnet MPC network signed the certificate 6.7 s after approval, `ssh-keygen` verified it, and the real gate binary enforced scope, single use, revocation (→ KRL) and expiry through the deployed contract. The first live run caught two bugs the offline tests missed; both are fixed ([docs/LIVE_RUN.md](docs/LIVE_RUN.md)). |
| Real sshd | **14/14** in CI on Linux (`sandbox/ci/sshd-integration.sh`): OpenSSH with the generated config and the real gate executes the approved restart; denies `cat /etc/shadow`, out-of-scope, second use and injected commands; refuses shells, PTYs and port forwarding; and sshd itself rejects expired, wrong-host, revoked and certificate-less logins. |

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
| `crates/sbc-wasm` | `sbc-core`'s gate logic compiled to WebAssembly (72 KB, no bindgen) for the in-browser "Try to escape" playground |
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

## Hackathon

* Built at **NEAR HACKATHON** (November 2026) for **AI Security & Defense** and **Open Innovation**.
* **All code in this repository was written during the hackathon** (first commit 2026-11-10). There is no pre-existing code, starter template or boilerplate.
* **Built with:** Rust: `near-sdk` 5.30 (contract); `ed25519-dalek`, `sha2`, `base64`, `bs58`, `hex`, `serde`/`serde_json`, `toml`, `ureq` (gate). TypeScript on Node 26 with no runtime npm dependencies: borsh, NEAR transactions and OpenSSH encoding are hand-written (`@near-js/crypto` and `@near-js/transactions` are dev-only, used to check our bytes match). Console: React 19, Vite 8, Inter and JetBrains Mono via Fontsource. Tooling: `cargo-near`, `near-cli-rs`, OpenSSH, Docker, GitHub Actions, Vercel.
* **NEAR integration:** the policy contract runs on NEAR testnet; **NEAR Chain Signatures** (MPC, Ed25519 domain) is the SSH certificate authority, with the CA key derived for the contract's account; **function-call access keys** on the contract account are the identity layer for admins, approvers, agents and hosts; every authorisation event is a NEP-297 event in a hash-chained, on-chain audit log.
* The author's other, independent submission is **[Necropolis](https://github.com/BoyofMars/necropolis)** — a graveyard for dead memecoins on Solana and Base, with burials verified by NEAR's MPC network.

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

License: [MIT](LICENSE).
