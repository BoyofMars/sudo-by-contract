# Threat model

Sudo by Contract exists to make an AI agent's authority **bounded by construction**:
the worst a compromised agent can do is the one approved action, on the one approved
host, a bounded number of times, inside the approved window.

Legend: **Prevented** — the architecture makes it impossible under the trust
assumptions below. **Reduced** — possible but bounded. **Detectable** — not prevented,
but leaves a durable, attributable record. **Out of scope** — not addressed.

## Trust assumptions

1. **The NEAR MPC network** does not collude above its threshold (11 on testnet) and its
   TEEs are sound. If it fails, an attacker could sign arbitrary certificates under our
   CA keys. This is the same root of trust NEAR Chain Signatures relies on for
   cross-chain custody.
2. **The policy contract code** is what its deployed code hash says it is, and nobody can
   change it unilaterally. *During the prototype the contract account is upgradeable by
   whoever holds its full-access key.* Whoever can deploy code to the contract account
   can make it sign any certificate. Production must lock the account (delete full-access
   keys) or put upgrades behind a multisig/DAO with a timelock — see "Malicious
   administrator".
3. **Enrolled hosts run unmodified sshd and sbc-gate** with the generated configuration.
   A host's root user can always do anything on that host.
4. **NEAR consensus** orders and finalises transactions (block time is used for expiry).

## Threats

| # | Threat | Status | How |
|---|---|---|---|
| 1 | **Compromised AI agent** (malicious instructions, jailbreak) | **Reduced** | The agent holds no standing credential. Its only authority is what policy + approvers granted: one typed action, one host, N uses, a window. It cannot approve its own requests (agent keys cannot call `approve`; contract checks role). |
| 2 | **Prompt injection** convinces the agent to attempt unauthorised actions | **Prevented** beyond the grant; **Detectable** | Injected commands either fail the closed grammar (`cat /etc/shadow`, `bash`, `;`, `$()` → no adapter), the host ceiling, or `consume` (out of scope). Every attempt is recorded (`command_denied`, `denied_attempts`, agent stats). An injection that asks for a *new* capability still needs policy and, for mutating production actions, a human who sees the request and its rationale. |
| 3 | **Credential exfiltration** | **Reduced** | There is nothing long-lived to steal. The ephemeral private key never leaves the agent; the certificate is public by design (useless without the key). If key + certificate are both exfiltrated, the thief gets exactly the remaining uses of that one action on that one host until expiry; binding to `source-address` (policy condition) closes even that. |
| 4 | **Credential replay** | **Prevented** | Certificates expire (sshd); uses are counted on-chain (`consume`); revoked serials are in the KRL. NEAR transaction nonces prevent replaying the gate's `consume`. Enrollment tokens are single-use (key deleted on use) and expire. Relay requests carry a timestamp and are replay-cached. |
| 5 | **Scope escalation** (approved `restart checkout-api`, attempts `restart sshd` or `systemctl edit`) | **Prevented** | Closed grammar + canonical action compared by `consume`; sudoers lists exact commands only. Tested: `hero_flow…`, `hero_sequence_at_the_gate`, `argument_injection_is_rejected`. |
| 6 | **Time escalation** (10 minutes keeps working) | **Prevented** | Certificate `valid_before` (sshd), block-time check in `consume`, gate's own clock check. Long-running actions are killed at the gate timeout. |
| 7 | **Host escalation** (use a prod-web-02 capability on prod-web-03) | **Prevented** | Certificate principal `sbc-prod-web-02` is only accepted by that host's `AuthorizedPrincipalsFile`; gate re-checks; `consume` requires the caller's gate key to belong to the capability's resource (`wrong_resource`). |
| 8 | **Identity spoofing** (another actor uses the agent's authority) | **Prevented** | Requests are NEAR transactions signed by the agent's enrolled key; the certificate binds the agent's ephemeral SSH key; the gate key, approver keys and agent keys are distinct roles checked by the protocol *and* the contract. |
| 9 | **Policy bypass** (execution without required approval) | **Prevented** | No certificate exists until the contract has the required approvals; even with a certificate, `consume` refuses anything not `Active`. Hosts trust no other CA. |
| 10 | **Compromised frontend** (UI shows "restart checkout-api for 5 min", submits something else) | **Reduced** | The console can only submit `approve(request_id, max_duration)` — the request contents were fixed by the agent's transaction and the contract; approvers can narrow, never widen. A malicious UI could approve the *wrong request id*: mitigations are short approval TTLs, multi-approval for sensitive policies, and approving from the CLI or a second device. Device keys are non-extractable, so a compromised page cannot steal them — it can only misuse them while open. |
| 11 | **Compromised enrolled server** | **Reduced** to that host | A dishonest gate can lie about execution, burn uses of its own capabilities, or run anything (it is root's machine). It cannot act on other hosts, issue certificates, or approve. Its reports are attributable to its key. |
| 12 | **Malicious administrator** changes policy | **Prevented** for a single admin when `policy_quorum ≥ 2`; **Detectable** always; **Reduced** by host ceilings | With a quorum, `upsert_policy` only records a proposal; it takes effect when enough *distinct* admins `confirm_policy` (24 h expiry). Disabling a policy is immediate (it only removes authority); re-enabling goes through the quorum. Every change is versioned, hashed and logged with all approving admins; requests record the policy version/hash they were evaluated against. Hosts enforce a local service ceiling. *Not prevented:* a colluding quorum, or an approver approving a bad request. A *contract-account* owner who redeploys code is outside the model (assumption 2). |
| 13 | **Signing compromise** (one participant issues certificates alone) | **Prevented** | There is no single signing participant: threshold MPC (11-of-N) inside TEEs; the derived key is usable only via the contract account; the contract verifies every signature against the environment CA before issuing. |
| 14 | **Spam / request flooding** | **Reduced** | ≤ `max_pending_per_agent` live requests, 60 requests/hour per agent, gas allowances on every role key, storage paid by the contract only for authenticated callers. |
| 15 | **Denial of service** of NEAR or the MPC network | **Out of scope** (fail closed) | New issuance stops; per-action authorisation stops (gate fails closed). See [FAILURE_MODES.md](FAILURE_MODES.md). Availability is traded for safety on purpose. |
| 16 | **Sensitive data leakage via audit** | **Reduced** | On-chain: identifiers, typed actions, hashes. Rationale/evidence and redacted command text stay in the relay; see [PRIVACY.md](PRIVACY.md). |
| 17 | **Root on the host** abusing the gate's key | **Out of scope** | Root owns the host. The gate key can only call `consume`/`report_denial`/`heartbeat` for its own resource. |

## What a successful attack still requires

To run `sudo cat /etc/shadow` on `prod-web-02` through Sudo by Contract, an attacker must
get the contract to **build and the MPC network to sign** a certificate whose path ends
in a command that reads `/etc/shadow`. No adapter does that, the gate's grammar rejects
it, sudoers does not allow it, and the contract only builds certificates whose single
permitted action was approved under policy. The remaining paths are outside the system:
host root, a malicious contract upgrade, or a broken MPC threshold.

## Residual risks we are explicit about

* **Contract upgradeability during the prototype** (assumption 2).
* **Approver judgement.** A human can approve a bad request. The product's job is to make
  the request legible (rationale, evidence verified against its on-chain hash, policy
  evaluation, risk, exact command) and the grant minimal.
* **Agent-held key + certificate theft inside the window** (threat 3) unless source-address
  binding is required.
* **Gate key file is readable by `sbc-agent`** (the forced command runs as that user). The
  agent cannot read it because it never gets a shell; a future version moves NEAR signing
  into a separate local signer daemon under its own user.
