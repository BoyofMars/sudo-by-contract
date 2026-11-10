# Privacy and what goes on-chain

An auditable authorisation system on a public chain must not become a public map of your
infrastructure or a surveillance log. Sudo by Contract records **decisions and
commitments** on-chain and keeps **content** private.

| Data | Where | Notes |
|---|---|---|
| Resource id (e.g. `prod-web-02`) | On-chain, in certificates | Choose opaque aliases (`r-7f3a9c`) if hostnames are sensitive; keep the real name as the console label off-chain. The console warns when creating resources. |
| Environment name, tags | On-chain | Same advice. |
| Service names (`checkout-api`) | On-chain | Needed for the contract to check targets. Use aliases if sensitive. Roadmap: target commitments (`sha256(org_salt ‖ target)`) checked by the gate, so the contract compares commitments it cannot read. |
| Agent id, label, owner, runtime | On-chain | Display metadata only. Never used for authorisation. |
| Short `reason` (≤ 280 chars) | On-chain | Public. The SDK and console guide agents to keep it non-sensitive ("Service unhealthy after deploy; requesting one restart"). |
| Rationale + evidence document | **Relay (private)**; only its SHA-256 on-chain (`context_hash`) | Approvers fetch it with an authenticated, signed request; the console re-hashes it and shows "matches on-chain hash". Neither the relay operator nor anyone else can alter it undetected. |
| Allowed command | On-chain as the canonical action (`service.restart:checkout-api`) | No free text. |
| Denied command | On-chain: program (`cat`), reason code, **SHA-256 of the full line**. Relay: redacted text. | The hash proves *which* command was attempted without disclosing it. Redaction masks `KEY=…`, `-p<password>`, `--token X`, bearer headers and high-entropy strings before anything leaves the host. |
| Command output (stdout/stderr) | **Nowhere.** Streamed to the agent over SSH only. | Sudo by Contract does not record terminal output. Session recording, if ever added, would be opt-in, host-local, encrypted to the operator, with retention limits. |
| Exit codes, durations | Relay | |
| Certificates | On-chain | Public by design; useless without the agent's ephemeral private key. They do contain the principal (resource id) and key id. |
| Approver identities | On-chain (approver ids, device public keys) | Use pseudonymous ids if required. |

Relay retention defaults to 30 days (`SBC_RETENTION_DAYS`) and it never logs request
bodies. The relay is optional: without it, approvers see on-chain facts and the
committed hash only.
