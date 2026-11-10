//! # Sudo by Contract — policy contract
//!
//! Request → Evaluate → Approve → Issue → Execute → Observe → Expire.
//!
//! This contract is the *only* party able to obtain signatures from its
//! NEAR-MPC-derived Ed25519 keys (derivation is bound to the calling account),
//! and those keys are the SSH user certificate authorities enrolled hosts
//! trust. The contract only ever asks for signatures over certificate bodies
//! it builds itself from an approved request, so:
//!
//! * no SSH CA private key exists anywhere — the MPC network holds threshold
//!   shares inside TEEs and signs only what this contract requests;
//! * every certificate is short-lived, bound to one host principal, forced
//!   through the host gate, and carries no PTY/forwarding extensions;
//! * every execution is checked against this contract (`consume`) by the
//!   gate before it runs, which is what makes single-use, revocation and
//!   scope enforcement real.

pub mod policy;
pub mod types;

use near_sdk::json_types::U128;
use near_sdk::serde_json::{self, json};
use near_sdk::store::{IterableMap, LookupMap, Vector};
use near_sdk::{
    env, near, require, AccountId, Allowance, CurveType, Gas, NearToken, PanicOnDefault, Promise,
    PromiseError, PublicKey,
};
use sbc_core::action::Action;
use sbc_core::ssh;
use sbc_core::validate;
use std::str::FromStr;
use types::*;

const STANDARD: &str = "sudo-by-contract";
const STANDARD_VERSION: &str = "1.0.0";
const MAX_EVENTS_PER_REQUEST: usize = 48;
const MAX_LIST: u32 = 100;
const CA_PATH_PREFIX: &str = "sbc/ssh-user-ca";

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct SudoByContract {
    config: Config,
    keys: LookupMap<PublicKey, KeyBinding>,
    agents: IterableMap<String, Agent>,
    approvers: IterableMap<String, Approver>,
    resources: IterableMap<String, Resource>,
    policies: IterableMap<String, Policy>,
    policy_history: LookupMap<String, Policy>,
    environments: IterableMap<String, Environment>,
    requests: Vector<AccessRequest>,
    revocations: Vector<Revocation>,
    agent_live: LookupMap<String, Vec<u64>>,
    agent_rate: LookupMap<String, (u64, u32)>,
    audit_seq: u64,
    audit_head: [u8; 32],
    policy_proposals: IterableMap<u64, PolicyProposal>,
    next_proposal_id: u64,
}

const PROPOSAL_TTL_MS: u64 = 24 * 3600 * 1000;

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct EnrollMeta {
    pub gate_version: Option<String>,
    pub host_fingerprint: Option<String>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct EnrollResult {
    pub ok: bool,
    pub role: Option<Role>,
    pub principal: String,
    pub message: String,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct SimulateResult {
    pub outcome: String,
    pub policy_id: Option<String>,
    pub policy_name: Option<String>,
    pub required_approvals: u8,
    pub checks: Vec<Check>,
}

fn now_ms() -> u64 {
    env::block_timestamp_ms()
}

fn yocto(v: &U128) -> NearToken {
    NearToken::from_yoctonear(v.0)
}

fn printable(s: &str, max_chars: usize) -> bool {
    s.chars().count() <= max_chars && !s.chars().any(|c| c.is_control())
}

#[near]
impl SudoByContract {
    // ================================================================ init

    #[init]
    pub fn new(owner: AccountId, mpc_contract: AccountId, mpc_domain_id: Option<u64>) -> Self {
        require!(
            owner != env::current_account_id(),
            "owner must be a separate account from the contract (role keys live on the contract account)"
        );
        Self {
            config: Config {
                owner: owner.to_string(),
                mpc_contract: mpc_contract.to_string(),
                mpc_domain_id: mpc_domain_id.unwrap_or(1),
                ca_version: 1,
                force_command: "/usr/local/sbin/sbc-gate".into(),
                skew_secs: 60,
                approval_ttl_secs: 15 * 60,
                max_pending_per_agent: 4,
                max_duration_secs: 4 * 3600,
                allowance_admin: U128(NearToken::from_near(2).as_yoctonear()),
                allowance_approver: U128(NearToken::from_near(1).as_yoctonear()),
                allowance_agent: U128(NearToken::from_near(1).as_yoctonear()),
                allowance_gate: U128(NearToken::from_near(2).as_yoctonear()),
                allowance_enrollment: U128(NearToken::from_millinear(250).as_yoctonear()),
                sign_gas_tgas: 50,
                callback_gas_tgas: 25,
                policy_quorum: 1,
            },
            keys: LookupMap::new(b"k"),
            agents: IterableMap::new(b"a"),
            approvers: IterableMap::new(b"p"),
            resources: IterableMap::new(b"r"),
            policies: IterableMap::new(b"o"),
            policy_history: LookupMap::new(b"h"),
            environments: IterableMap::new(b"e"),
            requests: Vector::new(b"q"),
            revocations: Vector::new(b"v"),
            agent_live: LookupMap::new(b"l"),
            agent_rate: LookupMap::new(b"t"),
            audit_seq: 0,
            audit_head: [0u8; 32],
            policy_proposals: IterableMap::new(b"x"),
            next_proposal_id: 0,
        }
    }

    // ======================================================== auth helpers

    fn is_owner_call(&self) -> bool {
        env::predecessor_account_id().as_str() == self.config.owner
    }

    /// The binding of the access key that signed this transaction. Only keys
    /// on the contract account itself, used directly (not via another
    /// contract), are identities.
    fn caller_binding(&self) -> KeyBinding {
        let me = env::current_account_id();
        require!(
            env::predecessor_account_id() == me && env::signer_account_id() == me,
            "call with a Sudo by Contract access key"
        );
        self.keys
            .get(&env::signer_account_pk())
            .cloned()
            .unwrap_or_else(|| env::panic_str("this access key is not bound to any identity"))
    }

    fn require_role(&self, role: Role) -> KeyBinding {
        let b = self.caller_binding();
        require!(b.role == role, format!("this key has role {:?}, not {:?}", b.role, role));
        b
    }

    /// Owner account, or an admin's device key. Returns the actor id for audit.
    fn require_admin(&self) -> String {
        if self.is_owner_call() {
            return format!("owner:{}", self.config.owner);
        }
        let b = self.require_role(Role::Admin);
        let a = self.approvers.get(&b.principal).unwrap_or_else(|| env::panic_str("admin not found"));
        require!(a.is_admin && a.status == Status::Active, "admin is not active");
        a.id.clone()
    }

    /// An approver's or admin's device key (or the owner). Returns approver id.
    fn require_approver(&self) -> String {
        if self.is_owner_call() {
            return format!("owner:{}", self.config.owner);
        }
        let b = self.caller_binding();
        require!(matches!(b.role, Role::Approver | Role::Admin), "only approvers can do this");
        let a = self.approvers.get(&b.principal).unwrap_or_else(|| env::panic_str("approver not found"));
        require!(a.status == Status::Active, "approver is suspended");
        a.id.clone()
    }

    fn allowance_for(&self, role: Role) -> NearToken {
        match role {
            Role::Admin => yocto(&self.config.allowance_admin),
            Role::Approver => yocto(&self.config.allowance_approver),
            Role::Agent => yocto(&self.config.allowance_agent),
            Role::Gate => yocto(&self.config.allowance_gate),
            Role::Enrollment => yocto(&self.config.allowance_enrollment),
        }
    }

    fn add_key_promise(&self, pk: PublicKey, role: Role) -> Promise {
        let me = env::current_account_id();
        Promise::new(me.clone()).add_access_key_allowance(
            pk,
            Allowance::limited(self.allowance_for(role)).unwrap(),
            me,
            role.method_names().to_string(),
        )
    }

    // ================================================================ audit

    /// Append to the global hash-chained audit log, emit a NEP-297 event, and
    /// return the event sequence number.
    fn audit(&mut self, kind: &str, actor: &str, data: serde_json::Value) -> u64 {
        self.audit_seq += 1;
        let at = now_ms();
        let mut body = data;
        if let Some(o) = body.as_object_mut() {
            o.insert("seq".into(), json!(self.audit_seq));
            o.insert("at_ms".into(), json!(at));
            o.insert("actor".into(), json!(actor));
        }
        let line = json!({
            "standard": STANDARD,
            "version": STANDARD_VERSION,
            "event": kind,
            "data": [body],
        })
        .to_string();
        let mut pre = Vec::with_capacity(32 + line.len());
        pre.extend_from_slice(&self.audit_head);
        pre.extend_from_slice(line.as_bytes());
        self.audit_head = env::sha256_array(&pre);
        env::log_str(&format!("EVENT_JSON:{}", line));
        self.audit_seq
    }

    fn event(&mut self, r: &mut AccessRequest, kind: &str, actor: &str, detail: String) {
        let seq = self.audit(
            kind,
            actor,
            json!({
                "request_id": r.id,
                "agent_id": r.agent_id,
                "resource_id": r.resource_id,
                "action": r.action,
                "state": r.state,
                "detail": detail,
            }),
        );
        if r.events.len() >= MAX_EVENTS_PER_REQUEST {
            // keep the first event (creation) and the most recent history
            r.events.remove(1);
        }
        r.events.push(RequestEvent { seq, at_ms: now_ms(), kind: kind.into(), actor: actor.into(), detail });
    }

    fn load(&self, id: u64) -> AccessRequest {
        require!(id < self.requests.len() as u64, "unknown request");
        self.requests.get(id as u32).cloned().unwrap()
    }

    fn save(&mut self, r: AccessRequest) {
        let id = r.id as u32;
        self.requests.set(id, r);
    }

    fn effective_state(r: &AccessRequest, now: u64) -> RequestState {
        match r.state {
            RequestState::Active if now >= r.valid_before.saturating_mul(1000) => RequestState::Expired,
            RequestState::PendingApproval if now >= r.approval_deadline_ms => RequestState::ApprovalExpired,
            s => s,
        }
    }

    /// Persist a lazily-computed terminal state, emitting its event once.
    fn settle(&mut self, r: &mut AccessRequest) {
        let eff = Self::effective_state(r, now_ms());
        if eff != r.state {
            r.state = eff;
            let kind = match eff {
                RequestState::Expired => "authorization_expired",
                RequestState::ApprovalExpired => "approval_expired",
                _ => "state_changed",
            };
            self.event(r, kind, "clock", "validity window elapsed".into());
            self.drop_live(&r.agent_id.clone(), r.id);
        }
    }

    fn drop_live(&mut self, agent_id: &str, id: u64) {
        if let Some(v) = self.agent_live.get_mut(agent_id) {
            v.retain(|x| *x != id);
        }
    }

    fn bump_stats(&mut self, agent_id: &str, f: impl FnOnce(&mut AgentStats)) {
        if let Some(a) = self.agents.get_mut(agent_id) {
            f(&mut a.stats);
        }
    }

    // ===================================================== configuration

    /// Owner-only tuning. Fields left `null` are unchanged.
    pub fn set_config(
        &mut self,
        approval_ttl_secs: Option<u32>,
        max_pending_per_agent: Option<u32>,
        max_duration_secs: Option<u32>,
        sign_gas_tgas: Option<u64>,
        callback_gas_tgas: Option<u64>,
        force_command: Option<String>,
        policy_quorum: Option<u8>,
    ) {
        require!(self.is_owner_call(), "owner only");
        if let Some(q) = policy_quorum {
            require!((1..=5).contains(&q), "policy quorum must be 1-5");
            self.config.policy_quorum = q;
        }
        if let Some(v) = approval_ttl_secs {
            require!((60..=86_400).contains(&v), "approval ttl out of range");
            self.config.approval_ttl_secs = v;
        }
        if let Some(v) = max_pending_per_agent {
            require!((1..=50).contains(&v), "max pending out of range");
            self.config.max_pending_per_agent = v;
        }
        if let Some(v) = max_duration_secs {
            require!((60..=7 * 86_400).contains(&v), "max duration out of range");
            self.config.max_duration_secs = v;
        }
        if let Some(v) = sign_gas_tgas {
            require!((15..=200).contains(&v), "sign gas out of range");
            self.config.sign_gas_tgas = v;
        }
        if let Some(v) = callback_gas_tgas {
            require!((10..=100).contains(&v), "callback gas out of range");
            self.config.callback_gas_tgas = v;
        }
        if let Some(v) = force_command {
            require!(v.starts_with('/') && printable(&v, 200) && !v.contains(' '), "force command must be an absolute path");
            self.config.force_command = v;
        }
        let actor = format!("owner:{}", self.config.owner);
        self.audit("config_updated", &actor, json!({}));
    }

    /// Create an environment and ask the MPC network for its CA public key.
    /// The key is derived from (this account, `sbc/ssh-user-ca/v<N>/<env>`).
    pub fn add_environment(&mut self, name: String) -> Promise {
        let actor = self.require_admin();
        require!(validate::is_slug(&name), "environment must be a slug");
        require!(self.environments.get(&name).map(|e| e.ca_public_key.is_none()).unwrap_or(true), "environment exists");
        let path = format!("{}/v{}/{}", CA_PATH_PREFIX, self.config.ca_version, name);
        self.environments.insert(
            name.clone(),
            Environment { name: name.clone(), path: path.clone(), ca_public_key: None, ca_public_key_ssh: None, created_at_ms: now_ms() },
        );
        self.audit("environment_created", &actor, json!({ "environment": name, "path": path }));
        let args = json!({ "path": path, "predecessor": env::current_account_id(), "domain_id": self.config.mpc_domain_id });
        Promise::new(self.config.mpc_contract.parse().unwrap())
            .function_call("derived_public_key".to_string(), args.to_string().into_bytes(), NearToken::from_yoctonear(0), Gas::from_tgas(10))
            .then(Self::ext(env::current_account_id()).with_static_gas(Gas::from_tgas(10)).on_ca_key(name))
    }

    #[private]
    pub fn on_ca_key(&mut self, name: String, #[callback_result] result: Result<String, PromiseError>) -> bool {
        let pk = match result.ok().and_then(|s| PublicKey::from_str(&s).ok()) {
            Some(pk) if pk.curve_type() == CurveType::ED25519 => pk,
            _ => {
                self.audit("environment_ca_failed", "mpc", json!({ "environment": name }));
                return false;
            }
        };
        let raw: [u8; 32] = pk.as_bytes()[1..].try_into().unwrap();
        let line = ssh::ed25519_pubkey_line(&raw, &format!("sbc-ca:{}", name));
        if let Some(e) = self.environments.get_mut(&name) {
            e.ca_public_key = Some(ssh::b64(&raw));
            e.ca_public_key_ssh = Some(line.clone());
        }
        self.audit("environment_ca_ready", "mpc", json!({ "environment": name, "ca": line }));
        true
    }

    // ======================================================== identities

    pub fn create_approver(&mut self, id: String, label: String, is_admin: bool) {
        let actor = self.require_admin();
        require!(validate::is_slug(&id), "approver id must be a slug");
        require!(validate::is_label(&label), "label must be 1-80 printable characters");
        require!(self.approvers.get(&id).is_none(), "approver exists");
        self.approvers.insert(id.clone(), Approver { id: id.clone(), label, is_admin, keys: vec![], status: Status::Active, created_at_ms: now_ms() });
        self.audit("approver_created", &actor, json!({ "approver_id": id, "is_admin": is_admin }));
    }

    pub fn set_approver_status(&mut self, id: String, status: Status) {
        let actor = self.require_admin();
        let a = self.approvers.get_mut(&id).unwrap_or_else(|| env::panic_str("approver not found"));
        a.status = status;
        self.audit("approver_status", &actor, json!({ "approver_id": id, "status": status }));
    }

    pub fn create_agent(&mut self, id: String, label: String, owner: String, runtime: String) {
        let actor = self.require_admin();
        require!(validate::is_slug(&id), "agent id must be a slug");
        require!(validate::is_label(&label) && printable(&owner, 80) && printable(&runtime, 80), "invalid agent metadata");
        require!(self.agents.get(&id).is_none(), "agent exists");
        self.agents.insert(
            id.clone(),
            Agent { id: id.clone(), label, owner, runtime, keys: vec![], status: Status::Active, created_at_ms: now_ms(), stats: AgentStats::default() },
        );
        self.audit("agent_created", &actor, json!({ "agent_id": id }));
    }

    pub fn set_agent_status(&mut self, id: String, status: Status) {
        let actor = self.require_admin();
        let a = self.agents.get_mut(&id).unwrap_or_else(|| env::panic_str("agent not found"));
        a.status = status;
        self.audit("agent_status", &actor, json!({ "agent_id": id, "status": status }));
    }

    pub fn create_resource(&mut self, id: String, label: String, environment: String, tags: Vec<String>, services: Vec<String>) {
        let actor = self.require_admin();
        require!(validate::is_slug(&id), "resource id must be a slug");
        require!(validate::is_label(&label), "label must be 1-80 printable characters");
        require!(self.resources.get(&id).is_none(), "resource exists");
        require!(self.environments.get(&environment).is_some(), "unknown environment; add_environment first");
        Self::check_tags_services(&tags, &services);
        let principal = format!("sbc-{}", id);
        self.resources.insert(
            id.clone(),
            Resource {
                id: id.clone(),
                label,
                environment: environment.clone(),
                tags,
                services,
                principal: principal.clone(),
                gate_key: None,
                gate_version: None,
                host_fingerprint: None,
                status: ResourceStatus::Pending,
                created_at_ms: now_ms(),
                enrolled_at_ms: None,
                last_seen_ms: None,
            },
        );
        self.audit("resource_created", &actor, json!({ "resource_id": id, "environment": environment, "principal": principal }));
    }

    fn check_tags_services(tags: &[String], services: &[String]) {
        require!(tags.len() <= 8 && tags.iter().all(|t| validate::is_slug(t)), "up to 8 slug tags");
        require!(services.len() <= 32 && services.iter().all(|s| validate::is_unit_name(s)), "up to 32 valid service names");
    }

    pub fn update_resource(&mut self, id: String, label: Option<String>, tags: Option<Vec<String>>, services: Option<Vec<String>>) {
        let actor = self.require_admin();
        let r = self.resources.get_mut(&id).unwrap_or_else(|| env::panic_str("resource not found"));
        if let Some(l) = label {
            require!(validate::is_label(&l), "invalid label");
            r.label = l;
        }
        let t = tags.unwrap_or_else(|| r.tags.clone());
        let s = services.unwrap_or_else(|| r.services.clone());
        Self::check_tags_services(&t, &s);
        r.tags = t;
        r.services = s.clone();
        self.audit("resource_updated", &actor, json!({ "resource_id": id, "services": s }));
    }

    /// `Disabled` is a kill switch: the gate's `consume` refuses every action
    /// on a disabled resource, including already-issued capabilities.
    pub fn set_resource_status(&mut self, id: String, status: ResourceStatus) {
        let actor = self.require_admin();
        require!(status != ResourceStatus::Pending, "cannot return to pending");
        let r = self.resources.get_mut(&id).unwrap_or_else(|| env::panic_str("resource not found"));
        require!(r.gate_key.is_some() || status == ResourceStatus::Disabled, "resource has no enrolled gate yet");
        r.status = status;
        self.audit("resource_status", &actor, json!({ "resource_id": id, "status": status }));
    }

    /// Register a one-time enrollment token: a function-call key that can only
    /// call `complete_enrollment`, which swaps it for the subject's real key.
    pub fn create_enrollment(&mut self, role: Role, principal: String, token_public_key: PublicKey, ttl_secs: Option<u32>) -> Promise {
        let actor = self.require_admin();
        match role {
            Role::Admin => require!(
                self.approvers.get(&principal).map(|a| a.is_admin).unwrap_or(false),
                "admin enrollment needs an existing admin approver"
            ),
            Role::Approver => require!(self.approvers.get(&principal).is_some(), "unknown approver"),
            Role::Agent => require!(self.agents.get(&principal).is_some(), "unknown agent"),
            Role::Gate => require!(self.resources.get(&principal).is_some(), "unknown resource"),
            Role::Enrollment => env::panic_str("cannot enroll an enrollment key"),
        }
        require!(self.keys.get(&token_public_key).is_none(), "key already bound");
        require!(token_public_key.curve_type() == CurveType::ED25519, "ed25519 keys only");
        let ttl = ttl_secs.unwrap_or(3600).clamp(60, 7 * 86_400);
        let expires = now_ms() + ttl as u64 * 1000;
        self.keys.insert(
            token_public_key.clone(),
            KeyBinding { role: Role::Enrollment, principal: principal.clone(), added_at_ms: now_ms(), enrolls_as: Some(role), expires_at_ms: Some(expires) },
        );
        self.audit("enrollment_created", &actor, json!({ "role": role, "principal": principal, "expires_at_ms": expires }));
        self.add_key_promise(token_public_key, Role::Enrollment)
    }

    /// Called with an enrollment token key. Binds `new_public_key` (generated
    /// on the agent host / server / approver device, never seen by anyone
    /// else) to the enrolled identity and deletes the token.
    pub fn complete_enrollment(&mut self, new_public_key: PublicKey, meta: Option<EnrollMeta>) -> EnrollResult {
        let token = env::signer_account_pk();
        let b = self.require_role(Role::Enrollment);
        let me = env::current_account_id();
        self.keys.remove(&token);
        let cleanup = Promise::new(me.clone()).delete_key(token);
        if b.expires_at_ms.map(|e| now_ms() > e).unwrap_or(true) {
            self.audit("enrollment_expired", &b.principal, json!({ "principal": b.principal }));
            cleanup.detach();
            return EnrollResult { ok: false, role: None, principal: b.principal, message: "enrollment token expired".into() };
        }
        require!(new_public_key.curve_type() == CurveType::ED25519, "ed25519 keys only");
        require!(self.keys.get(&new_public_key).is_none(), "key already bound");
        let role = b.enrolls_as.unwrap();
        let p = b.principal.clone();
        let mut replaced: Option<PublicKey> = None;
        match role {
            Role::Admin | Role::Approver => {
                let a = self.approvers.get_mut(&p).unwrap();
                require!(a.keys.len() < 8, "too many devices");
                a.keys.push(new_public_key.clone());
            }
            Role::Agent => {
                let a = self.agents.get_mut(&p).unwrap();
                require!(a.keys.len() < 8, "too many keys");
                a.keys.push(new_public_key.clone());
            }
            Role::Gate => {
                let r = self.resources.get_mut(&p).unwrap();
                replaced = r.gate_key.replace(new_public_key.clone());
                if r.status == ResourceStatus::Pending {
                    r.status = ResourceStatus::Active;
                }
                r.enrolled_at_ms = Some(now_ms());
                r.last_seen_ms = Some(now_ms());
                if let Some(m) = &meta {
                    r.gate_version = m.gate_version.clone().filter(|v| printable(v, 40));
                    r.host_fingerprint = m.host_fingerprint.clone().filter(|v| printable(v, 120));
                }
            }
            Role::Enrollment => unreachable!(),
        }
        self.keys.insert(
            new_public_key.clone(),
            KeyBinding { role, principal: p.clone(), added_at_ms: now_ms(), enrolls_as: None, expires_at_ms: None },
        );
        let mut promise = cleanup.then(self.add_key_promise(new_public_key.clone(), role));
        if let Some(old) = replaced {
            self.keys.remove(&old);
            promise = promise.then(Promise::new(me).delete_key(old));
        }
        promise.detach();
        self.audit("enrollment_completed", &p, json!({ "role": role, "principal": p, "public_key": new_public_key }));
        EnrollResult { ok: true, role: Some(role), principal: p, message: "enrolled".into() }
    }

    /// Unbind and delete an identity key (lost device, rotated agent key, decommissioned host).
    pub fn remove_key(&mut self, public_key: PublicKey) -> Promise {
        let actor = self.require_admin();
        let b = self.keys.remove(&public_key).unwrap_or_else(|| env::panic_str("unknown key"));
        match b.role {
            Role::Admin | Role::Approver => {
                if let Some(a) = self.approvers.get_mut(&b.principal) {
                    a.keys.retain(|k| k != &public_key);
                }
            }
            Role::Agent => {
                if let Some(a) = self.agents.get_mut(&b.principal) {
                    a.keys.retain(|k| k != &public_key);
                }
            }
            Role::Gate => {
                if let Some(r) = self.resources.get_mut(&b.principal) {
                    if r.gate_key.as_ref() == Some(&public_key) {
                        r.gate_key = None;
                        r.status = ResourceStatus::Disabled;
                    }
                }
            }
            Role::Enrollment => {}
        }
        self.audit("key_removed", &actor, json!({ "role": b.role, "principal": b.principal, "public_key": public_key }));
        Promise::new(env::current_account_id()).delete_key(public_key)
    }

    // ============================================================ policies

    fn check_policy_input(&self, policy: &PolicyInput) {
        if let Err(e) = policy::validate_policy(policy, self.config.max_duration_secs) {
            env::panic_str(&e);
        }
        for a in &policy.subjects.agents {
            require!(self.agents.get(a).is_some(), format!("unknown agent {}", a));
        }
        for a in &policy.approval.approvers {
            require!(self.approvers.get(a).is_some(), format!("unknown approver {}", a));
        }
    }

    /// Create or update a policy. With `policy_quorum > 1` this records a
    /// proposal (returns 0) that other admins `confirm_policy`; nothing changes
    /// until the quorum is met.
    pub fn upsert_policy(&mut self, policy: PolicyInput) -> u32 {
        let actor = self.require_admin();
        self.check_policy_input(&policy);
        if self.config.policy_quorum <= 1 {
            return self.apply_policy(policy, actor);
        }
        let id = self.next_proposal_id;
        self.next_proposal_id += 1;
        let now = now_ms();
        let summary = policy::describe(&Policy {
            id: policy.id.clone(),
            version: 0,
            name: policy.name.clone(),
            description: String::new(),
            effect: policy.effect,
            subjects: policy.subjects.clone(),
            resources: policy.resources.clone(),
            actions: policy.actions.clone(),
            max_duration_secs: policy.max_duration_secs,
            max_uses: policy.max_uses,
            approval: policy.approval.clone(),
            conditions: policy.conditions.clone(),
            status: Status::Active,
            updated_at_ms: now,
            updated_by: actor.clone(),
            hash: String::new(),
        });
        self.audit("policy_proposed", &actor, json!({ "proposal_id": id, "policy_id": policy.id, "summary": summary, "quorum": self.config.policy_quorum }));
        self.policy_proposals.insert(
            id,
            PolicyProposal { id, policy, proposer: actor.clone(), approvals: vec![actor], created_at_ms: now, expires_at_ms: now + PROPOSAL_TTL_MS },
        );
        0
    }

    /// A second (third, …) admin agrees to a pending policy change. Returns
    /// the new policy version once the quorum is met, else 0.
    pub fn confirm_policy(&mut self, proposal_id: u64) -> u32 {
        let actor = self.require_admin();
        let mut p = self.policy_proposals.get(&proposal_id).cloned().unwrap_or_else(|| env::panic_str("unknown proposal"));
        if now_ms() > p.expires_at_ms {
            self.policy_proposals.remove(&proposal_id);
            self.audit("policy_proposal_expired", &actor, json!({ "proposal_id": proposal_id }));
            return 0;
        }
        require!(!p.approvals.contains(&actor), "you already approved this change");
        p.approvals.push(actor.clone());
        self.audit("policy_confirmed", &actor, json!({ "proposal_id": proposal_id, "approvals": p.approvals.len(), "quorum": self.config.policy_quorum }));
        if (p.approvals.len() as u8) < self.config.policy_quorum {
            self.policy_proposals.insert(proposal_id, p);
            return 0;
        }
        self.policy_proposals.remove(&proposal_id);
        self.check_policy_input(&p.policy);
        let by = p.approvals.join("+");
        self.apply_policy(p.policy, by)
    }

    fn apply_policy(&mut self, policy: PolicyInput, actor: String) -> u32 {
        let version = self.policies.get(&policy.id).map(|p| p.version + 1).unwrap_or(1);
        let mut p = Policy {
            id: policy.id.clone(),
            version,
            name: policy.name,
            description: policy.description,
            effect: policy.effect,
            subjects: policy.subjects,
            resources: policy.resources,
            actions: policy.actions,
            max_duration_secs: policy.max_duration_secs,
            max_uses: policy.max_uses,
            approval: policy.approval,
            conditions: policy.conditions,
            status: Status::Active,
            updated_at_ms: now_ms(),
            updated_by: actor.clone(),
            hash: String::new(),
        };
        p.hash = hex::encode(env::sha256_array(&near_sdk::borsh::to_vec(&p).unwrap()));
        let summary = policy::describe(&p);
        self.policy_history.insert(format!("{}@{}", p.id, version), p.clone());
        self.policies.insert(p.id.clone(), p.clone());
        self.audit("policy_updated", &actor, json!({ "policy_id": p.id, "version": version, "hash": p.hash, "summary": summary }));
        version
    }

    /// Disabling is always immediate (it only removes authority). Re-enabling
    /// widens authority, so under a quorum it must go through `upsert_policy`.
    pub fn set_policy_status(&mut self, id: String, status: Status) {
        let actor = self.require_admin();
        require!(
            status != Status::Active || self.config.policy_quorum <= 1,
            "re-enabling a policy needs the admin quorum: submit it with upsert_policy"
        );
        let p = self.policies.get_mut(&id).unwrap_or_else(|| env::panic_str("policy not found"));
        p.status = status;
        self.audit("policy_status", &actor, json!({ "policy_id": id, "status": status }));
    }

    // ============================================================ requests

    fn signing_gas_required(&self) -> Gas {
        Gas::from_tgas(self.config.sign_gas_tgas + self.config.callback_gas_tgas + 30)
    }

    /// An agent asks for one capability. Policy decides immediately whether it
    /// is rejected, auto-approved (signing starts in this transaction), or
    /// waits for human approval.
    pub fn request_access(&mut self, request: RequestAccessArgs) -> u64 {
        let b = self.require_role(Role::Agent);
        let agent = self.agents.get(&b.principal).cloned().unwrap_or_else(|| env::panic_str("agent not found"));
        require!(agent.status == Status::Active, "agent is suspended");
        let now = now_ms();

        // --- anti-spam: bounded live requests and hourly rate
        let live: Vec<u64> = self.agent_live.get(&agent.id).cloned().unwrap_or_default();
        let still_live: Vec<u64> = live
            .into_iter()
            .filter(|id| {
                let r = self.requests.get(*id as u32).unwrap();
                !Self::effective_state(r, now).is_terminal()
            })
            .collect();
        require!(
            (still_live.len() as u32) < self.config.max_pending_per_agent,
            "too many live requests for this agent; release or wait for one to expire"
        );
        let (win, cnt) = self.agent_rate.get(&agent.id).cloned().unwrap_or((0, 0));
        let (win, cnt) = if now.saturating_sub(win) > 3_600_000 { (now, 0) } else { (win, cnt) };
        require!(cnt < 60, "hourly request limit reached");
        self.agent_rate.insert(agent.id.clone(), (win, cnt + 1));

        // --- input validation (fail closed on anything malformed)
        let resource = self.resources.get(&request.resource_id).cloned().unwrap_or_else(|| env::panic_str("unknown resource"));
        let action = Action::parse_canonical(&request.action).unwrap_or_else(|| env::panic_str("malformed action"));
        let ssh_key = ssh::parse_ed25519_key_any(&request.ssh_public_key).unwrap_or_else(|_| env::panic_str("ssh_public_key must be an Ed25519 key"));
        require!((60..=self.config.max_duration_secs).contains(&request.duration_secs), "duration out of range");
        let uses = request.uses.unwrap_or(1);
        require!((1..=100).contains(&uses), "uses out of range");
        if let Some(sa) = &request.source_address {
            require!(validate::is_source_address_list(sa), "malformed source_address");
        }
        require!(printable(&request.reason, 280), "reason is limited to 280 characters");
        if let Some(h) = &request.context_hash {
            require!(validate::is_hex_of_len(h, 32), "context_hash must be sha256 hex");
        }

        let id = self.requests.len() as u64;
        let mut r = AccessRequest {
            id,
            agent_id: agent.id.clone(),
            resource_id: resource.id.clone(),
            environment: resource.environment.clone(),
            action: action.canonical(),
            requested_duration_secs: request.duration_secs,
            requested_uses: uses,
            ssh_public_key: ssh::b64(&ssh_key),
            source_address: request.source_address.clone(),
            reason: request.reason.clone(),
            context_hash: request.context_hash.clone(),
            created_at_ms: now,
            approval_deadline_ms: now + self.config.approval_ttl_secs as u64 * 1000,
            policy_id: None,
            policy_version: None,
            policy_hash: None,
            checks: vec![],
            required_approvals: 0,
            eligible_approvers: vec![],
            approvals: vec![],
            state: RequestState::Rejected,
            state_reason: None,
            granted_duration_secs: 0,
            max_uses: uses,
            uses: 0,
            denied_attempts: 0,
            valid_after: 0,
            valid_before: 0,
            pending_tbs: None,
            certificate: None,
            signed_at_ms: None,
            revoked_by: None,
            events: vec![],
        };
        self.event(&mut r, "request_created", &agent.id, format!("{} on {} for {}s", action.describe(), resource.id, request.duration_secs));
        self.bump_stats(&agent.id, |s| s.requests += 1);

        // --- the host must actually expose this target, and be live
        let precheck: Option<String> = if resource.status != ResourceStatus::Active {
            Some(format!("resource {} is not active", resource.id))
        } else if !resource.services.contains(&action.target) {
            Some(format!("{} does not expose {}", resource.id, action.target))
        } else if self.environments.get(&resource.environment).and_then(|e| e.ca_public_key.as_ref()).is_none() {
            Some("environment CA key not yet available".into())
        } else {
            None
        };

        let eval = if precheck.is_none() {
            let input = policy::EvalInput {
                agent: &agent,
                resource: &resource,
                action: &action,
                duration_secs: request.duration_secs,
                uses,
                source_address: request.source_address.as_deref(),
                now_ms: now,
            };
            let ps: Vec<&Policy> = self.policies.values().collect();
            Some(policy::evaluate(&ps, &input))
        } else {
            None
        };

        let mut start_signing = false;
        match (precheck, eval) {
            (Some(reason), _) => {
                r.checks = vec![Check { name: "resource".into(), ok: false, detail: reason.clone() }];
                r.state = RequestState::Rejected;
                r.state_reason = Some(reason);
            }
            (None, Some(e)) => {
                r.checks = e.checks.clone();
                if let Some(p) = &e.policy {
                    r.policy_id = Some(p.id.clone());
                    r.policy_version = Some(p.version);
                    r.policy_hash = Some(p.hash.clone());
                    r.eligible_approvers = p.approval.approvers.clone();
                }
                match e.outcome {
                    policy::Outcome::Rejected => {
                        r.state = RequestState::Rejected;
                        r.state_reason = r.checks.iter().find(|c| !c.ok).map(|c| format!("{}: {}", c.name, c.detail));
                    }
                    policy::Outcome::AutoApproved => {
                        r.granted_duration_secs = request.duration_secs;
                        r.state = RequestState::Signing;
                        start_signing = true;
                    }
                    policy::Outcome::NeedsApproval(n) => {
                        r.required_approvals = n;
                        r.state = RequestState::PendingApproval;
                    }
                }
            }
            (None, None) => unreachable!(),
        }

        let detail = match r.state {
            RequestState::Rejected => r.state_reason.clone().unwrap_or_default(),
            RequestState::PendingApproval => format!("policy {} requires {} approval(s)", r.policy_id.clone().unwrap_or_default(), r.required_approvals),
            _ => format!("auto-approved by policy {}", r.policy_id.clone().unwrap_or_default()),
        };
        self.event(&mut r, "policy_evaluated", "policy", detail);

        if r.state == RequestState::Rejected {
            self.bump_stats(&agent.id, |s| s.rejected += 1);
            self.requests.push(r);
            return id;
        }
        let mut live = still_live;
        live.push(id);
        self.agent_live.insert(agent.id.clone(), live);
        if start_signing {
            require!(env::prepaid_gas() >= self.signing_gas_required(), "auto-approved requests start signing: attach at least 150 Tgas");
            self.bump_stats(&agent.id, |s| s.auto_approved += 1);
            self.event(&mut r, "approval_granted", "policy", "auto-approved".into());
            self.requests.push(r);
            self.begin_signing(id).detach();
        } else {
            self.requests.push(r);
        }
        id
    }

    pub fn approve(&mut self, request_id: u64, max_duration_secs: Option<u32>) {
        let approver = self.require_approver();
        let mut r = self.load(request_id);
        self.settle(&mut r);
        if r.state != RequestState::PendingApproval {
            self.save(r);
            return;
        }
        require!(
            r.eligible_approvers.is_empty() || r.eligible_approvers.contains(&approver) || approver.starts_with("owner:"),
            "you are not an eligible approver for this policy"
        );
        require!(!r.approvals.iter().any(|a| a.approver_id == approver), "already approved");
        if let Some(d) = max_duration_secs {
            require!(d >= 60 && d <= r.requested_duration_secs, "approvers can only narrow the window");
        }
        r.approvals.push(Approval { approver_id: approver.clone(), at_ms: now_ms(), max_duration_secs });
        let detail = match max_duration_secs {
            Some(d) => format!("approved, window narrowed to {}s ({}/{})", d, r.approvals.len(), r.required_approvals),
            None => format!("approved ({}/{})", r.approvals.len(), r.required_approvals),
        };
        self.event(&mut r, "approval_granted", &approver, detail);
        if (r.approvals.len() as u8) < r.required_approvals {
            self.save(r);
            return;
        }
        require!(env::prepaid_gas() >= self.signing_gas_required(), "final approval starts signing: attach at least 150 Tgas");
        r.granted_duration_secs = r
            .approvals
            .iter()
            .filter_map(|a| a.max_duration_secs)
            .fold(r.requested_duration_secs, |acc, d| acc.min(d));
        let agent_id = r.agent_id.clone();
        self.bump_stats(&agent_id, |s| s.approved += 1);
        self.save(r);
        self.begin_signing(request_id).detach();
    }

    pub fn deny(&mut self, request_id: u64, reason: String) {
        let approver = self.require_approver();
        require!(printable(&reason, 280), "reason too long");
        let mut r = self.load(request_id);
        self.settle(&mut r);
        require!(r.state == RequestState::PendingApproval, "request is not awaiting approval");
        require!(
            r.eligible_approvers.is_empty() || r.eligible_approvers.contains(&approver) || approver.starts_with("owner:"),
            "you are not an eligible approver for this policy"
        );
        r.state = RequestState::Denied;
        r.state_reason = Some(if reason.is_empty() { "denied".into() } else { reason.clone() });
        let agent_id = r.agent_id.clone();
        self.event(&mut r, "approval_denied", &approver, reason);
        self.drop_live(&agent_id, request_id);
        self.bump_stats(&agent_id, |s| s.denied += 1);
        self.save(r);
    }

    /// Kill a capability. Effective at the gate on the very next command
    /// (every execution calls `consume`), and at sshd once the gate's KRL
    /// sync picks up the revoked serial.
    pub fn revoke(&mut self, request_id: u64, reason: String) {
        let who = self.require_approver();
        require!(printable(&reason, 280), "reason too long");
        let mut r = self.load(request_id);
        self.settle(&mut r);
        require!(!r.state.is_terminal(), "nothing to revoke");
        self.revoke_inner(&mut r, &who, reason);
        self.save(r);
    }

    fn revoke_inner(&mut self, r: &mut AccessRequest, who: &str, reason: String) {
        let was_issued = matches!(r.state, RequestState::Active | RequestState::Signing);
        r.state = RequestState::Revoked;
        r.revoked_by = Some(who.to_string());
        r.state_reason = Some(if reason.is_empty() { "revoked".into() } else { reason.clone() });
        if was_issued {
            self.revocations.push(Revocation { serial: r.id, resource_id: r.resource_id.clone(), at_ms: now_ms(), valid_before: r.valid_before });
        }
        let agent_id = r.agent_id.clone();
        self.event(r, "authorization_revoked", who, reason);
        self.drop_live(&agent_id, r.id);
        self.bump_stats(&agent_id, |s| s.revoked += 1);
    }

    /// The agent releases its own capability as soon as the task is done.
    pub fn cancel_request(&mut self, request_id: u64) {
        let b = self.require_role(Role::Agent);
        let mut r = self.load(request_id);
        require!(r.agent_id == b.principal, "not your request");
        self.settle(&mut r);
        require!(!r.state.is_terminal(), "already finished");
        let was_issued = matches!(r.state, RequestState::Active | RequestState::Signing);
        r.state = RequestState::Cancelled;
        r.state_reason = Some("released by agent".into());
        if was_issued {
            self.revocations.push(Revocation { serial: r.id, resource_id: r.resource_id.clone(), at_ms: now_ms(), valid_before: r.valid_before });
        }
        let agent_id = r.agent_id.clone();
        self.event(&mut r, "authorization_released", &agent_id, "agent released the capability".into());
        self.drop_live(&agent_id, request_id);
        self.save(r);
    }

    // ============================================================ signing

    /// Build the certificate body from the approved request and ask the MPC
    /// network to sign it. Nothing here is agent-controlled except the
    /// ephemeral public key and (if policy allows) the source address.
    fn begin_signing(&mut self, id: u64) -> Promise {
        let mut r = self.load(id);
        let env_ = self.environments.get(&r.environment).cloned().unwrap();
        let resource = self.resources.get(&r.resource_id).cloned().unwrap();
        let ca: [u8; 32] = ssh::unb64(env_.ca_public_key.as_ref().unwrap()).unwrap().try_into().unwrap();
        let subject: [u8; 32] = ssh::unb64(&r.ssh_public_key).unwrap().try_into().unwrap();
        let now_s = now_ms() / 1000;
        r.valid_after = now_s.saturating_sub(self.config.skew_secs as u64);
        r.valid_before = now_s + r.granted_duration_secs as u64;
        let mut seed = env::random_seed();
        seed.extend_from_slice(&id.to_le_bytes());
        seed.extend_from_slice(b"sbc-cert-nonce");
        let spec = ssh::UserCertSpec {
            nonce: env::sha256_array(&seed),
            subject_key: subject,
            serial: id,
            key_id: format!("sbc cap={} agent={} res={}", id, r.agent_id, r.resource_id),
            principals: vec![resource.principal.clone()],
            valid_after: r.valid_after,
            valid_before: r.valid_before,
            force_command: Some(self.config.force_command.clone()),
            source_address: r.source_address.clone(),
            extensions: vec![],
            ca_key: ca,
        };
        let tbs = ssh::build_tbs(&spec).unwrap_or_else(|e| env::panic_str(&format!("cannot build certificate: {}", e)));
        let tbs_hex = hex::encode(&tbs);
        r.pending_tbs = Some(tbs_hex.clone());
        r.state = RequestState::Signing;
        self.event(&mut r, "credential_signing", "mpc", format!("requesting threshold signature ({} byte certificate body)", tbs.len()));
        self.save(r);
        let args = json!({
            "request": {
                "path": env_.path,
                "payload_v2": { "Eddsa": tbs_hex },
                "domain_id": self.config.mpc_domain_id,
            }
        });
        Promise::new(self.config.mpc_contract.parse().unwrap())
            .function_call("sign".to_string(), args.to_string().into_bytes(), NearToken::from_yoctonear(1), Gas::from_tgas(self.config.sign_gas_tgas))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(Gas::from_tgas(self.config.callback_gas_tgas))
                    .on_signed(id),
            )
    }

    /// MPC callback. Verifies the threshold signature against the
    /// environment's CA key before anything is issued (fail closed).
    #[private]
    pub fn on_signed(&mut self, request_id: u64, #[callback_result] result: Result<MpcSignatureResponse, PromiseError>) -> bool {
        let mut r = self.load(request_id);
        if r.state != RequestState::Signing {
            // revoked or cancelled while signing: discard the signature
            r.pending_tbs = None;
            self.event(&mut r, "credential_discarded", "mpc", "signature arrived after the request was closed".into());
            self.save(r);
            return false;
        }
        let ca: Option<[u8; 32]> = self
            .environments
            .get(&r.environment)
            .and_then(|e| e.ca_public_key.as_ref())
            .and_then(|k| ssh::unb64(k).ok())
            .and_then(|v| v.try_into().ok());
        let tbs = r.pending_tbs.take().and_then(|h| hex::decode(h).ok());
        let failure: Option<String> = match (&result, &ca, &tbs) {
            (Ok(MpcSignatureResponse::Ed25519 { signature }), Some(ca), Some(tbs)) if signature.len() == 64 => {
                let sig: [u8; 64] = signature.as_slice().try_into().unwrap();
                if env::ed25519_verify(&sig, tbs, ca) {
                    let blob = ssh::attach_signature(tbs, &sig);
                    r.certificate = Some(ssh::cert_line(&blob, &format!("sbc-cap-{}", r.id)));
                    r.signed_at_ms = Some(now_ms());
                    r.state = RequestState::Active;
                    None
                } else {
                    Some("threshold signature did not verify against the environment CA key".into())
                }
            }
            (Ok(_), _, _) => Some("unexpected signature scheme from MPC".into()),
            (Err(_), _, _) => Some("MPC signing failed or timed out".into()),
        };
        let ok = failure.is_none();
        match failure {
            None => {
                let d = format!("certificate serial {} valid until {}", r.id, r.valid_before);
                self.event(&mut r, "credential_issued", "mpc", d);
            }
            Some(f) => {
                r.state = RequestState::Failed;
                r.state_reason = Some(f.clone());
                let agent_id = r.agent_id.clone();
                self.drop_live(&agent_id, r.id);
                self.event(&mut r, "credential_failed", "mpc", f);
            }
        }
        self.save(r);
        ok
    }

    // ========================================================== gate path

    fn deny_result(r: &AccessRequest, code: &str, message: String) -> ConsumeResult {
        ConsumeResult {
            allowed: false,
            code: code.into(),
            message,
            uses: r.uses,
            max_uses: r.max_uses,
            valid_before: r.valid_before,
            action: r.action.clone(),
        }
    }

    /// Called by the host gate before executing anything. This is where
    /// scope, single-use, expiry and revocation become enforcement.
    pub fn consume(&mut self, request_id: u64, action: String, session: Option<String>) -> ConsumeResult {
        let gate = self.require_role(Role::Gate);
        let resource = self.resources.get(&gate.principal).cloned().unwrap_or_else(|| env::panic_str("resource not found"));
        let session = session.filter(|s| printable(s, 64)).unwrap_or_default();
        if request_id >= self.requests.len() as u64 {
            self.audit("command_denied", &resource.id, json!({ "resource_id": resource.id, "code": "unknown_capability", "request_id": request_id }));
            return ConsumeResult { allowed: false, code: "unknown_capability".into(), message: "no such capability".into(), uses: 0, max_uses: 0, valid_before: 0, action: String::new() };
        }
        let mut r = self.load(request_id);
        self.settle(&mut r);

        // Order matters for the audit trail: an attempt outside the capability
        // is recorded as a scope escalation even if the capability is also
        // spent, expired or revoked by now.
        let denial: Option<(&str, String)> = if r.resource_id != resource.id {
            Some(("wrong_resource", format!("capability is bound to {}, not {}", r.resource_id, resource.id)))
        } else if resource.status != ResourceStatus::Active {
            Some(("resource_disabled", "this resource is disabled".into()))
        } else if action != r.action {
            Some(("out_of_scope", format!("capability permits only {}", r.action)))
        } else {
            match r.state {
                RequestState::Active => {
                    if r.uses >= r.max_uses {
                        Some(("exhausted", "all permitted uses are consumed".into()))
                    } else {
                        None
                    }
                }
                RequestState::Expired => Some(("expired", "authorization expired".into())),
                RequestState::Revoked => Some(("revoked", "authorization was revoked".into())),
                RequestState::Cancelled => Some(("released", "authorization was released by the agent".into())),
                RequestState::Exhausted => Some(("exhausted", "all permitted uses are consumed".into())),
                s => Some(("not_active", format!("capability is {:?}", s))),
            }
        };

        let agent_id = r.agent_id.clone();
        if let Some((code, message)) = denial {
            r.denied_attempts += 1;
            let shown = if action.len() > 120 { format!("{}…", &action[..120]) } else { action.clone() };
            if r.denied_attempts <= 20 {
                self.event(&mut r, "command_denied", &resource.id, format!("{}: attempted {} ({}) session={}", code, shown, message, session));
            }
            self.bump_stats(&agent_id, |s| s.actions_denied += 1);
            let out = Self::deny_result(&r, code, message);
            self.save(r);
            return out;
        }

        r.uses += 1;
        let detail = format!("{} (use {}/{}) session={}", r.action, r.uses, r.max_uses, session);
        self.event(&mut r, "command_allowed", &resource.id, detail);
        self.bump_stats(&agent_id, |s| s.actions_allowed += 1);
        if r.uses >= r.max_uses {
            r.state = RequestState::Exhausted;
            self.event(&mut r, "authorization_used", "policy", "all permitted uses consumed; capability closed".into());
            self.drop_live(&agent_id, r.id);
        }
        let out = ConsumeResult {
            allowed: true,
            code: "allowed".into(),
            message: "permitted".into(),
            uses: r.uses,
            max_uses: r.max_uses,
            valid_before: r.valid_before,
            action: r.action.clone(),
        };
        self.save(r);
        out
    }

    /// The gate rejected a command locally (it never parsed into an action).
    /// Only the program, a reason code and the SHA-256 of the full command
    /// line are recorded on-chain; the redacted text goes to the private relay.
    pub fn report_denial(&mut self, request_id: Option<u64>, code: String, program: String, command_sha256: String) {
        let gate = self.require_role(Role::Gate);
        require!(code.len() <= 40 && code.bytes().all(|c| c.is_ascii_lowercase() || c == b'_'), "bad code");
        require!(printable(&program, 64), "bad program");
        require!(validate::is_hex_of_len(&command_sha256, 32), "bad hash");
        match request_id.filter(|id| *id < self.requests.len() as u64) {
            Some(id) => {
                let mut r = self.load(id);
                require!(r.resource_id == gate.principal, "capability belongs to another resource");
                r.denied_attempts += 1;
                let agent_id = r.agent_id.clone();
                if r.denied_attempts <= 20 {
                    self.event(&mut r, "command_denied", &gate.principal, format!("{}: attempted `{}` sha256={}", code, program, &command_sha256[..16]));
                }
                self.bump_stats(&agent_id, |s| s.actions_denied += 1);
                self.save(r);
            }
            None => {
                self.audit("command_denied", &gate.principal, json!({ "resource_id": gate.principal, "code": code, "program": program, "command_sha256": command_sha256 }));
            }
        }
    }

    pub fn heartbeat(&mut self, gate_version: Option<String>) {
        let gate = self.require_role(Role::Gate);
        if let Some(r) = self.resources.get_mut(&gate.principal) {
            r.last_seen_ms = Some(now_ms());
            if let Some(v) = gate_version.filter(|v| printable(v, 40)) {
                r.gate_version = Some(v);
            }
        }
    }

    // =============================================================== views

    pub fn get_overview(&self) -> Overview {
        Overview {
            config: self.config.clone(),
            environments: self.environments.values().cloned().collect(),
            audit_seq: self.audit_seq,
            audit_head: hex::encode(self.audit_head),
            request_count: self.requests.len() as u64,
            agent_count: self.agents.len(),
            resource_count: self.resources.len(),
            policy_count: self.policies.len(),
            approver_count: self.approvers.len(),
            revocation_count: self.revocations.len() as u64,
            now_ms: now_ms(),
        }
    }

    pub fn get_ca(&self, environment: String) -> Option<String> {
        self.environments.get(&environment).and_then(|e| e.ca_public_key_ssh.clone())
    }

    pub fn whoami(&self, public_key: PublicKey) -> WhoAmI {
        WhoAmI { binding: self.keys.get(&public_key).cloned(), public_key }
    }

    pub fn list_agents(&self, from_index: Option<u32>, limit: Option<u32>) -> Vec<Agent> {
        self.agents.values().skip(from_index.unwrap_or(0) as usize).take(limit.unwrap_or(MAX_LIST).min(MAX_LIST) as usize).cloned().collect()
    }

    pub fn get_agent(&self, id: String) -> Option<Agent> {
        self.agents.get(&id).cloned()
    }

    pub fn list_approvers(&self, from_index: Option<u32>, limit: Option<u32>) -> Vec<Approver> {
        self.approvers.values().skip(from_index.unwrap_or(0) as usize).take(limit.unwrap_or(MAX_LIST).min(MAX_LIST) as usize).cloned().collect()
    }

    pub fn list_resources(&self, from_index: Option<u32>, limit: Option<u32>) -> Vec<Resource> {
        self.resources.values().skip(from_index.unwrap_or(0) as usize).take(limit.unwrap_or(MAX_LIST).min(MAX_LIST) as usize).cloned().collect()
    }

    pub fn get_resource(&self, id: String) -> Option<Resource> {
        self.resources.get(&id).cloned()
    }

    pub fn list_policies(&self, from_index: Option<u32>, limit: Option<u32>) -> Vec<Policy> {
        self.policies.values().skip(from_index.unwrap_or(0) as usize).take(limit.unwrap_or(MAX_LIST).min(MAX_LIST) as usize).cloned().collect()
    }

    pub fn get_policy(&self, id: String, version: Option<u32>) -> Option<Policy> {
        match version {
            Some(v) => self.policy_history.get(&format!("{}@{}", id, v)).cloned(),
            None => self.policies.get(&id).cloned(),
        }
    }

    pub fn list_policy_proposals(&self) -> Vec<PolicyProposal> {
        self.policy_proposals.values().take(MAX_LIST as usize).cloned().collect()
    }

    pub fn describe_policy(&self, id: String) -> Option<String> {
        self.policies.get(&id).map(policy::describe)
    }

    fn view_request(&self, r: &AccessRequest, now: u64) -> AccessRequest {
        let mut v = r.clone();
        v.state = Self::effective_state(r, now);
        v
    }

    pub fn get_request(&self, id: u64) -> Option<AccessRequest> {
        self.requests.get(id as u32).map(|r| self.view_request(r, now_ms()))
    }

    /// Newest first. Filters apply to the effective (time-aware) state.
    pub fn list_requests(
        &self,
        before_id: Option<u64>,
        limit: Option<u32>,
        agent_id: Option<String>,
        resource_id: Option<String>,
        states: Option<Vec<RequestState>>,
    ) -> Vec<AccessRequest> {
        let now = now_ms();
        let len = self.requests.len() as u64;
        let start = before_id.map(|b| b.min(len)).unwrap_or(len);
        let limit = limit.unwrap_or(50).min(MAX_LIST) as usize;
        let mut out = Vec::new();
        let mut scanned = 0;
        let mut i = start;
        while i > 0 && out.len() < limit && scanned < 500 {
            i -= 1;
            scanned += 1;
            let r = self.requests.get(i as u32).unwrap();
            if agent_id.as_ref().map(|a| a != &r.agent_id).unwrap_or(false) {
                continue;
            }
            if resource_id.as_ref().map(|x| x != &r.resource_id).unwrap_or(false) {
                continue;
            }
            let v = self.view_request(r, now);
            if states.as_ref().map(|s| !s.contains(&v.state)).unwrap_or(false) {
                continue;
            }
            out.push(v);
        }
        out
    }

    /// Revoked serials still inside their validity window, for the gate's KRL sync.
    pub fn list_revocations(&self, resource_id: String, from_index: Option<u32>) -> Vec<Revocation> {
        let now_s = now_ms() / 1000;
        self.revocations
            .iter()
            .skip(from_index.unwrap_or(0) as usize)
            .filter(|r| r.resource_id == resource_id && r.valid_before > now_s)
            .take(500)
            .cloned()
            .collect()
    }

    /// Dry-run a request against current policy (policy builder "test", agent pre-flight).
    pub fn simulate(&self, agent_id: String, resource_id: String, action: String, duration_secs: u32, uses: Option<u32>, source_address: Option<String>) -> SimulateResult {
        let agent = self.agents.get(&agent_id).unwrap_or_else(|| env::panic_str("unknown agent"));
        let resource = self.resources.get(&resource_id).unwrap_or_else(|| env::panic_str("unknown resource"));
        let action = Action::parse_canonical(&action).unwrap_or_else(|| env::panic_str("malformed action"));
        if !resource.services.contains(&action.target) {
            return SimulateResult {
                outcome: "rejected".into(),
                policy_id: None,
                policy_name: None,
                required_approvals: 0,
                checks: vec![Check { name: "resource".into(), ok: false, detail: format!("{} does not expose {}", resource.id, action.target) }],
            };
        }
        let input = policy::EvalInput {
            agent,
            resource,
            action: &action,
            duration_secs,
            uses: uses.unwrap_or(1),
            source_address: source_address.as_deref(),
            now_ms: now_ms(),
        };
        let ps: Vec<&Policy> = self.policies.values().collect();
        let e = policy::evaluate(&ps, &input);
        SimulateResult {
            outcome: match e.outcome {
                policy::Outcome::AutoApproved => "auto_approved".into(),
                policy::Outcome::NeedsApproval(_) => "needs_approval".into(),
                policy::Outcome::Rejected => "rejected".into(),
            },
            required_approvals: e.policy.as_ref().map(|p| p.approval.required).unwrap_or(0),
            policy_id: e.policy.as_ref().map(|p| p.id.clone()),
            policy_name: e.policy.as_ref().map(|p| p.name.clone()),
            checks: e.checks,
        }
    }
}

#[cfg(test)]
mod tests;
