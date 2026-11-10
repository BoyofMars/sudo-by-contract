# Live run on NEAR testnet

Run on 2026-11-10 against the deployed contract and the production NEAR MPC signer for
testnet, with `scripts/e2e-testnet.ts`. Everything is real except sshd itself (the gate
binary ran with its dry-run backend on a Windows workstation; sshd is covered by
`sandbox/ci/sshd-integration.sh` and the Docker sandbox).

| | |
|---|---|
| Policy contract | [`bagyard-sexton.testnet`](https://testnet.nearblocks.io/address/bagyard-sexton.testnet) (owner `bagyard.testnet`) |
| MPC signer | [`v1.signer-prod.testnet`](https://testnet.nearblocks.io/address/v1.signer-prod.testnet), domain 1 (Frost / Ed25519, threshold 11) |
| Production SSH user CA (derived by the MPC network for the contract; no private key exists) | `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICA7lQ5yFKYgWPJFZuI9RVDrWMKp6z/qtIgOw2AHU2qR sbc-ca:production` |
| Deployed wasm (sha256) | `4a93b6c77a25bf7bc69981dbad7b489854eeab916ae9e4e8331a491ee2495b43` |
| Deploy / upgrade | [`9ifydVRX…eN2M`](https://testnet.nearblocks.io/txns/9ifydVRXztFR53DXQpnmj3SsM4phKkny1gKxx7p5eN2M) · [`F9Lgdoo6…31Sk`](https://testnet.nearblocks.io/txns/F9Lgdoo6XkUX1arLwa1HTL8Kd8hpUk6buiJ2T2SN31Sk) |
| Environment + CA derivation | [`DDy5nCdt…CxSJh`](https://testnet.nearblocks.io/txns/DDy5nCdt3uAraf1c9Kdy9WaVHhGrANmgaBEsPzjCxSJh) |

## Result: 22 / 22

```
✓ contract reachable and configured — MPC v1.signer-prod.testnet, audit seq 30
✓ sbc-gate enroll (one-time token → gate key on-chain)
✓ resource active with enrolled gate key — ed25519:BUwP2xcYuYpewY5SPXoKSweEDHggM9uDSeigt3rFLdBF
✓ agent and approver identities enrolled
✓ request evaluated by policy → awaiting approval — policy prod-remediation v1, 8 checks ✓
✓ approval → MPC threshold signature → certificate — 6.7 s from approval to Active
✓ ssh-keygen parses and verifies the MPC-signed certificate — Signing CA: ED25519 SHA256:n1JNeFXanaaT4zvxWl5zCLMMOtLTEBD2W3d6TRRO1kA (using ssh-ed25519) | Serial: 2 | Valid: from 2026-11-10T05:03:53 to 2026-11-10T05:14:53
✓ certificate is signed by the environment CA the MPC network derived for this contract
✓ certificate is bounded: one principal, force-command, no extensions, ~10 min
✓ gate: approved restart executes (consume → allowed) — sbc-gate: ✓ authorized service.restart:checkout-api — capability #1, use 1/1
✓ gate: `sudo cat /etc/shadow` denied (no adapter) — sbc-gate: DENIED (no_adapter) `cat` is not an action Sudo by Contract can authorise
✓ gate: `sudo systemctl restart sshd` denied (out of scope, decided on-chain) — sbc-gate: DENIED (out_of_scope) capability #1: capability permits only service.restart:checkout-api
✓ gate: second restart denied (single use consumed) — sbc-gate: DENIED (exhausted) capability #1: all permitted uses are consumed
✓ on-chain record: Exhausted, 1 use, denials counted — events: request_created → policy_evaluated → approval_granted → credential_signing → credential_issued → command_allowed → authorization_used → command_denied → command_denied → command_denied
✓ auto-approved read-only capability issued — policy status-checks
✓ gate: status allowed before revocation
✓ gate: denied immediately after revoke (next command) — sbc-gate: DENIED (revoked) capability #2: authorization was revoked
✓ sbc-gate sync → KRL: sshd would refuse the revoked certificate at login — REVOKED
✓ gate: allowed inside the window
✓ gate: denied after expiry — sbc-gate: DENIED (expired) presented certificate is not valid for this host
✓ contract reports Expired from block time
✓ audit chain advanced — seq 30 → 64, head 444d92610b3f4ffd…
22/22 checks passed in 151.0 s
```

## What the first live run caught

The first run passed 11 checks and stopped at the 12th. It found two real bugs that the
unit tests and the mock-chain tests had not:

1. **Scope escalation mislabelled.** After the single use was consumed, `sudo systemctl
   restart sshd` was denied as `exhausted` instead of `out_of_scope`, so the audit trail
   hid the escalation attempt. `consume()` now checks scope before use/expiry state
   (regression test `scope_escalation_is_labelled_even_after_the_capability_is_spent`).
2. **Serial 0.** The first capability was issued certificate serial 0, and `ssh-keygen -k`
   refuses to revoke serial 0, which would have broken every host's KRL sync the moment
   capability #0 was revoked. Certificate serials are now capability id + 1, and the gate
   refuses serial 0 (`serial_zero_is_never_honoured`).

Both were fixed, the contract was upgraded in place (state layout unchanged), and the
second run above passed in full.
