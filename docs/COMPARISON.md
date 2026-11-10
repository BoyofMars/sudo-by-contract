# Why this should exist

Short-lived infrastructure access is a solved problem for *humans inside one
organisation*. Teleport, Vault, Boundary, StrongDM, Cloudflare Access and the cloud
providers' JIT tools all do it well, and several are moving fast on AI agents. Sudo by
Contract does not claim otherwise. It differs in **who has to be trusted** and **who can
verify it**.

## What the incumbents do well (and what we learned from them)

| Product | Strength we learned from | Where trust sits |
|---|---|---|
| **Teleport** | Short-lived certificates bound to identity instead of keys; access requests with Slack/PagerDuty approval plugins; session recording; Machine & Workload ID. In Jan 2026 it announced an *Agentic Identity Framework* (agents as distinct identities with short-lived, task-scoped credentials) and agent runtimes ("Beams"). | Teleport Auth Service holds the CAs (optionally in HSM/KMS). Policy and audit live in the operator's cluster. |
| **HashiCorp Vault** (SSH secrets engine) | Signed SSH certificates per role with TTLs, allowed principals, default critical options (e.g. `force-command`); Control Groups (Enterprise) for multi-party approval. | The Vault cluster holds the CA key; policy is Vault policy, private to the operator. |
| **Boundary** | Session brokering with credential injection: the user never sees the credential. | Boundary controllers + Vault. |
| **StrongDM** | Proxy that evaluates each command/query against policy before it runs; *Leash* (open source) enforces Cedar policy on agent syscalls via eBPF; shadow-mode rollout. | StrongDM gateway in the data path; vendor-operated control plane. |
| **Akeyless** | SSH certificate issuer on *Distributed Fragments Cryptography*: by Akeyless's own description no complete private key ever exists, with an optional customer-held fragment. | Akeyless-operated fragments (+ customer fragment). |
| **Cloudflare Access for Infrastructure**, **Okta Privileged Access**, **Tailscale SSH** | Identity-aware SSH without long-lived keys; command logging; re-authentication ("check mode"). | Vendor control plane / CA. |
| **AWS SSM + Identity Center**, **GCP PAM + IAP**, **Azure Entra PIM** | JIT role elevation with approvals and expiry; SSM documents restricting commands. | The cloud provider; scoped to that cloud. |
| **CyberArk** | Vaulting, session isolation, JIT elevation; now positioning identity security for AI agents. | CyberArk vault / SaaS. |

Lessons adopted: certificates over keys (Teleport/Vault); never handing over the
credential (Boundary); per-command decisions (StrongDM); one-time enrollment tokens
(Tailscale auth keys); JIT with expiry by default (PIM/PAM); approval in chat tools.

What operators still struggle with — and what we designed for:

* "Temporary" access that is really a role for 8 hours, with a full shell.
* Approval prompts that say *"agent wants prod access"* instead of *exactly* what will run.
* Audit trails held by the same party whose actions they audit.
* Granting a **third party's** agent (a vendor's SRE agent, an MSP) access without
  federating identity providers or trusting the vendor's CA.

## What NEAR enables that these do not naturally provide

1. **The CA is a program, not a party.** The SSH CA key is derived by the NEAR MPC
   network for the policy contract's account and is usable *only* by that contract,
   which signs only certificate bodies it constructs from approved requests. Akeyless also
   avoids a whole key, but its fragments are operated by one vendor and its signing
   decision is vendor logic. Here the signing decision is public contract code anyone can
   inspect and re-execute, and the threshold is held by independent TEE operators.
2. **Externally verifiable policy and audit.** Policy versions, hashes, approvals,
   issuances, per-action `consume` decisions and denials are on a public ledger with a
   hash-chained audit head. An auditor, a customer or a regulator can verify *what was
   allowed and what happened* without trusting the operator's database.
3. **Cross-organisation authority without identity federation.** A customer can enroll a
   vendor's agent as an identity (a scoped key on the customer's contract), grant it one
   action under the customer's policy, and both sides can verify the result. The vendor
   cannot exceed it; the customer cannot later misstate what was approved.
4. **Agent-native capability requests.** The request object carries the typed action,
   window, uses, a public reason and a commitment to private evidence. Approvers see exactly
   what will run. Agents integrate via SDK, CLI or MCP.
5. **Per-action authorisation without a proxy in the data path.** Enforcement is on the
   host (sshd + gate), consulting the contract per action. No traffic flows through us.

Where we are weaker, honestly:

* Latency: ~1–2 s per privileged command (one NEAR transaction).
* Availability depends on NEAR and the MPC network; we fail closed.
* Public metadata needs care ([PRIVACY.md](PRIVACY.md)).
* Trust in contract upgrade governance ([THREAT_MODEL.md](THREAT_MODEL.md) assumption 2).
* Breadth: one protocol adapter (SSH) and three action types today. Incumbents cover
  databases, Kubernetes, desktops, session recording and compliance reporting.

## Potential moat

* **Authorization protocol for agents.** A standard capability-request object and
  `consume` semantics that any agent framework (MCP, Agent SDKs) and any enforcement
  point can speak. The value grows with each adapter and each agent integration.
* **Verified policy library.** Reusable, audited policies ("restart one service with one
  approval") with on-chain hashes that organisations can adopt and reference.
* **Agent behaviour history.** Per-agent, cross-organisation records of requests,
  approvals and *denied attempts*, attributable to an enrolled identity. Useful for
  deciding which agents get auto-approval, without reducing it to a naive score.
* **Distributed CA as a service.** Programmable certificate issuance for SSH today and
  other credential formats as MPC signature domains allow.

## Roadmap

1. **Admin quorum + timelock** on policy and contract changes; lock the contract account.
2. **Target commitments** so service names never appear on-chain (gate compares hashes).
3. **Kubernetes adapter** (`k8s.rollout_restart:<ns>/<deploy>`) via a validating admission
   webhook / exec proxy that calls `consume`.
4. **Database adapter** (one migration, one query class) and **cloud API adapter**
   (short-lived role assumption gated by `consume`).
5. **Attested conditions:** "only while an incident is open", "only after CI passed" via
   signed attestations from PagerDuty / CI checked by the contract.
6. **Break-glass:** emergency policy class with stricter approvals and post-hoc review.
7. **Local signer daemon** for the gate key; TPM-bound host keys.
8. **Read-only fast path:** locally verifiable read-only capabilities (no per-command
   transaction) with periodic on-chain settlement.
9. **Slack / PagerDuty approval cards** with deep links; web push for the PWA.
