# Failure modes

The rule: **no authority beats uncertain authority.** When something cannot be verified,
the system denies.

| Situation | Behaviour | Why |
|---|---|---|
| **NEAR RPC / chain unavailable** | New requests and approvals cannot be submitted. The gate cannot `consume`, so **every command is denied** (`policy_unreachable`, exit 69). Already-issued certificates still pass sshd, but sshd only reaches the gate. | Per-action authorisation is the point; executing without it would make single-use and revocation unenforceable. |
| **MPC network slow** | Request sits in `Signing`; console shows "Requesting threshold signature…". The validity window started at approval, so a slow signature shortens, never extends, the usable window. | Window is computed by the contract from block time at approval. |
| **MPC network fails / times out** | The MPC contract's yield times out → our callback receives an error → request becomes `Failed` with the reason. Nothing is issued. | `on_signed` handles `Err` explicitly. Tested (`mpc_timeout_fails_closed`). |
| **MPC returns a wrong/forged signature** | `env::ed25519_verify` fails → `Failed`. | Tested (`bad_mpc_signature_fails_closed`). |
| **Revoked while signing** | The signature is discarded on arrival; request stays `Revoked`. | Tested (`revoked_while_signing_discards_signature`). |
| **Policy backend unavailable** | There is no separate policy backend: policy lives in the contract. If the chain is unavailable, see row 1. | |
| **Relay unavailable** | Authorisation is unaffected. Console shows on-chain facts and "private context unavailable (hash committed on-chain)". Gate reports are dropped with a note; the on-chain record (`consume` / `report_denial`) remains authoritative. | The relay is never in the authorisation path. |
| **Server cannot reach the policy contract** | Denies all commands (fail closed). KRL sync and heartbeats stop; the console shows the host as stale. | |
| **Authorisation expires during execution** | The running action continues until it exits or hits the gate timeout (default 120 s). New commands are refused (sshd + `consume`). | Killing a half-done restart is usually worse than letting it finish; the timeout bounds it. Configurable. |
| **Admin revokes during a session** | Each command is its own SSH session, so the *next* command is refused by `consume` immediately, and by sshd once the KRL syncs (≤ 30 s in the sandbox). An in-flight command is not interrupted. | |
| **Gate misconfigured / key missing / CA file unreadable** | Denies everything (`gate_misconfigured`, exit 78). | |
| **`ExposeAuthInfo` not enabled** | Denies (`no_auth_info`): the gate cannot identify the capability. | |
| **Agent retries requests repeatedly** | Bounded by `max_pending_per_agent` (live requests), 60 requests/hour, and the agent key's gas allowance. Repeated *denied commands* are counted (`denied_attempts`) and visible on the agent profile. | |
| **Approval never arrives** | `ApprovalExpired` after `approval_ttl_secs` (default 15 min). | Stale approvals are a classic way to approve something the context no longer justifies. |
| **Clock skew between chain and host** | Certificates are valid from issuance − 60 s. Expiry is enforced by three clocks (block time in `consume`, sshd, gate); the strictest wins. | |
| **CA rotation** | `sbc-gate sync` warns when the contract's CA for the host's environment differs from the pinned file and does **not** auto-trust the new key. Re-enroll to rotate. | Silent CA changes are an attack vector. |
| **Malformed input anywhere** | Contract panics (transaction fails, no state change) on malformed requests; the gate rejects unparseable commands; the parser rejects unknown certificate fields. | |
