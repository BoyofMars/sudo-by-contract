//! Persistent and wire types for the policy contract.

use near_sdk::json_types::U128;
use near_sdk::{near, PublicKey};

/// What an access key bound to this contract account is allowed to be.
///
/// Every identity in Sudo by Contract (admins, human approvers' devices,
/// agents, host gates, one-time enrollment tokens) is a NEAR *function-call
/// access key on the contract account itself*. The protocol restricts which
/// methods each key can call; the contract additionally maps the signing key
/// (`env::signer_account_pk()`) to a role and principal and checks both.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Admin,
    Approver,
    Agent,
    Gate,
    Enrollment,
}

impl Role {
    /// Methods the NEAR protocol will let a key of this role call.
    pub fn method_names(&self) -> &'static str {
        match self {
            Role::Admin => "upsert_policy,confirm_policy,set_policy_status,create_resource,update_resource,set_resource_status,create_agent,set_agent_status,create_approver,set_approver_status,remove_approver,create_enrollment,remove_key,add_environment,approve,deny,revoke",
            Role::Approver => "approve,deny,revoke",
            Role::Agent => "request_access,cancel_request",
            Role::Gate => "consume,report_denial,heartbeat",
            Role::Enrollment => "complete_enrollment",
        }
    }
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct KeyBinding {
    pub role: Role,
    /// agent id, approver id or resource id (for enrollment keys: the subject being enrolled)
    pub principal: String,
    pub added_at_ms: u64,
    /// Enrollment keys only: what role the enrolled key will receive.
    pub enrolls_as: Option<Role>,
    /// Enrollment keys only.
    pub expires_at_ms: Option<u64>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Active,
    Suspended,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, Default)]
pub struct AgentStats {
    pub requests: u32,
    pub auto_approved: u32,
    pub approved: u32,
    pub denied: u32,
    pub rejected: u32,
    pub revoked: u32,
    pub actions_allowed: u32,
    pub actions_denied: u32,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Agent {
    pub id: String,
    pub label: String,
    /// Who is accountable for this agent (team or person). Display metadata.
    pub owner: String,
    /// Self-described runtime ("claude-opus-5-5 / Agent SDK"). Display metadata
    /// only: never used for authorisation.
    pub runtime: String,
    pub keys: Vec<PublicKey>,
    pub status: Status,
    pub created_at_ms: u64,
    pub stats: AgentStats,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Approver {
    pub id: String,
    pub label: String,
    pub is_admin: bool,
    pub keys: Vec<PublicKey>,
    pub status: Status,
    pub created_at_ms: u64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceStatus {
    /// Created; waiting for the host gate to enroll.
    Pending,
    Active,
    Disabled,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Resource {
    /// Opaque id. Appears in certificate principals and on-chain records, so
    /// operators who consider topology sensitive should use an alias here and
    /// keep the real hostname in `label` off-chain (see docs/PRIVACY.md).
    pub id: String,
    pub label: String,
    pub environment: String,
    pub tags: Vec<String>,
    /// Targets the host actually exposes through its gate (systemd units /
    /// supervisor programs). Requests for anything else are rejected before
    /// policy is even consulted.
    pub services: Vec<String>,
    /// `sbc-<id>`: the only principal this host accepts.
    pub principal: String,
    pub gate_key: Option<PublicKey>,
    pub gate_version: Option<String>,
    pub host_fingerprint: Option<String>,
    pub status: ResourceStatus,
    pub created_at_ms: u64,
    pub enrolled_at_ms: Option<u64>,
    pub last_seen_ms: Option<u64>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, Default)]
pub struct SubjectSelector {
    pub all_agents: bool,
    pub agents: Vec<String>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, Default)]
pub struct ResourceSelector {
    pub ids: Vec<String>,
    pub environments: Vec<String>,
    pub tags: Vec<String>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct ActionRule {
    /// `service.restart`, `service.status`, `logs.read`
    pub kind: String,
    /// Exact targets, or `["*"]` for any target the resource exposes.
    pub targets: Vec<String>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, Default)]
pub struct ApprovalRule {
    /// 0 = policy alone approves ("auto").
    pub required: u8,
    /// Approver ids eligible to approve. Empty = any active approver.
    pub approvers: Vec<String>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, Default)]
pub struct Conditions {
    /// `[start, end)` hours in UTC during which requests may be made.
    pub utc_hours: Option<[u8; 2]>,
    /// Require the agent to bind its certificate to a source address.
    pub require_source_address: bool,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Policy {
    pub id: String,
    pub version: u32,
    pub name: String,
    pub description: String,
    pub effect: Effect,
    pub subjects: SubjectSelector,
    pub resources: ResourceSelector,
    pub actions: Vec<ActionRule>,
    pub max_duration_secs: u32,
    pub max_uses: u32,
    pub approval: ApprovalRule,
    pub conditions: Conditions,
    pub status: Status,
    pub updated_at_ms: u64,
    pub updated_by: String,
    /// sha256 of the borsh encoding of this version, recorded on every
    /// request evaluated against it.
    pub hash: String,
}

/// What an admin submits; versioning and hashing are done by the contract.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct PolicyInput {
    pub id: String,
    pub name: String,
    pub description: String,
    pub effect: Effect,
    pub subjects: SubjectSelector,
    pub resources: ResourceSelector,
    pub actions: Vec<ActionRule>,
    pub max_duration_secs: u32,
    pub max_uses: u32,
    pub approval: ApprovalRule,
    pub conditions: Conditions,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestState {
    /// Waiting for human approval.
    PendingApproval,
    /// Approved; the NEAR MPC network is signing the certificate.
    Signing,
    /// Certificate issued and usable.
    Active,
    /// All permitted uses consumed.
    Exhausted,
    /// Validity window elapsed (computed lazily from block time).
    Expired,
    /// Revoked by an approver/admin.
    Revoked,
    /// A human denied it.
    Denied,
    /// Policy rejected it.
    Rejected,
    /// Not approved in time.
    ApprovalExpired,
    /// Signing failed or timed out. Fail closed: nothing was issued.
    Failed,
    /// The agent released it.
    Cancelled,
}

impl RequestState {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, RequestState::PendingApproval | RequestState::Signing | RequestState::Active)
    }
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Check {
    /// identity | resource | environment | action | target | duration | uses | schedule | source | approval | deny
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Approval {
    pub approver_id: String,
    pub at_ms: u64,
    /// Approvers may narrow, never widen, the window.
    pub max_duration_secs: Option<u32>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct RequestEvent {
    pub seq: u64,
    pub at_ms: u64,
    pub kind: String,
    pub actor: String,
    pub detail: String,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct AccessRequest {
    pub id: u64,
    pub agent_id: String,
    pub resource_id: String,
    pub environment: String,
    /// Canonical action, e.g. `service.restart:checkout-api`.
    pub action: String,
    pub requested_duration_secs: u32,
    pub requested_uses: u32,
    /// The agent's ephemeral Ed25519 SSH public key (base64 of 32 bytes).
    pub ssh_public_key: String,
    pub source_address: Option<String>,
    /// Short, public, agent-supplied justification. Never affects policy.
    pub reason: String,
    /// sha256 (hex) of the private context document (evidence, full rationale)
    /// held off-chain by the relay. Lets approvers verify it was not altered.
    pub context_hash: Option<String>,
    pub created_at_ms: u64,
    pub approval_deadline_ms: u64,

    pub policy_id: Option<String>,
    pub policy_version: Option<u32>,
    pub policy_hash: Option<String>,
    pub checks: Vec<Check>,
    pub required_approvals: u8,
    pub eligible_approvers: Vec<String>,
    pub approvals: Vec<Approval>,

    pub state: RequestState,
    pub state_reason: Option<String>,

    pub granted_duration_secs: u32,
    pub max_uses: u32,
    pub uses: u32,
    pub denied_attempts: u32,
    /// Unix seconds.
    pub valid_after: u64,
    pub valid_before: u64,
    /// Hex of the certificate body awaiting an MPC signature.
    pub pending_tbs: Option<String>,
    /// The issued OpenSSH certificate line. Certificates are public by
    /// design: they are useless without the agent's ephemeral private key.
    pub certificate: Option<String>,
    pub signed_at_ms: Option<u64>,
    pub revoked_by: Option<String>,

    pub events: Vec<RequestEvent>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct RequestAccessArgs {
    pub resource_id: String,
    /// Canonical action, e.g. `service.restart:checkout-api`.
    pub action: String,
    pub duration_secs: u32,
    pub uses: Option<u32>,
    /// `ssh-ed25519 AAAA...` line or base64 of the raw 32-byte key.
    pub ssh_public_key: String,
    pub source_address: Option<String>,
    pub reason: String,
    pub context_hash: Option<String>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Environment {
    pub name: String,
    /// MPC derivation path. The CA key is derived from (this contract's
    /// account id, path) by the NEAR MPC network; no party holds it.
    pub path: String,
    /// Raw Ed25519 CA public key, base64. None until the MPC network answered.
    pub ca_public_key: Option<String>,
    /// `ssh-ed25519 AAAA... sbc-ca:<env>` for TrustedUserCAKeys.
    pub ca_public_key_ssh: Option<String>,
    pub created_at_ms: u64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Revocation {
    pub serial: u64,
    pub resource_id: String,
    pub at_ms: u64,
    /// After this the certificate is dead anyway and the entry can be dropped from KRLs.
    pub valid_before: u64,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Config {
    pub owner: String,
    pub mpc_contract: String,
    pub mpc_domain_id: u64,
    pub ca_version: u32,
    /// Forced into every certificate as the `force-command` critical option.
    pub force_command: String,
    /// Clock-skew allowance: certificates become valid this many seconds before issuance.
    pub skew_secs: u32,
    pub approval_ttl_secs: u32,
    pub max_pending_per_agent: u32,
    pub max_duration_secs: u32,
    /// Allowances (yoctoNEAR) for the access keys the contract adds to itself.
    pub allowance_admin: U128,
    pub allowance_approver: U128,
    pub allowance_agent: U128,
    pub allowance_gate: U128,
    pub allowance_enrollment: U128,
    pub sign_gas_tgas: u64,
    pub callback_gas_tgas: u64,
    /// Distinct admins that must agree before a policy change takes effect.
    /// 1 = any admin alone (default); >1 turns `upsert_policy` into a proposal.
    pub policy_quorum: u8,
}

/// A policy change waiting for `policy_quorum` distinct admins.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct PolicyProposal {
    pub id: u64,
    pub policy: PolicyInput,
    pub proposer: String,
    pub approvals: Vec<String>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct ConsumeResult {
    pub allowed: bool,
    pub code: String,
    pub message: String,
    pub uses: u32,
    pub max_uses: u32,
    pub valid_before: u64,
    pub action: String,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct WhoAmI {
    pub public_key: PublicKey,
    pub binding: Option<KeyBinding>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct Overview {
    pub config: Config,
    pub environments: Vec<Environment>,
    pub audit_seq: u64,
    pub audit_head: String,
    pub request_count: u64,
    pub agent_count: u32,
    pub resource_count: u32,
    pub policy_count: u32,
    pub approver_count: u32,
    pub revocation_count: u64,
    pub now_ms: u64,
}

/// The MPC contract's `SignatureResponse`, `#[serde(tag = "scheme")]`.
#[near(serializers = [json])]
#[serde(tag = "scheme")]
#[derive(Clone, Debug)]
pub enum MpcSignatureResponse {
    Secp256k1 {},
    Ed25519 { signature: Vec<u8> },
}
