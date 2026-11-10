//! Lifecycle tests with a simulated MPC network.
//!
//! The "MPC" here is an ed25519-dalek key used *only inside tests* to produce
//! the signature the real network would return. The contract never sees it:
//! it receives a `SignatureResponse` through the callback exactly as on
//! testnet and verifies it with `env::ed25519_verify`.

use super::*;
use ed25519_dalek::{Signer, SigningKey};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{testing_env, PromiseResult};

const CONTRACT: &str = "sbc.testnet";
const OWNER: &str = "owner.testnet";
const MPC: &str = "v1.signer-prod.testnet";
const T0_MS: u64 = 1_800_000_000_000;

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn pk_of(sk: &SigningKey) -> PublicKey {
    PublicKey::from_parts(CurveType::ED25519, sk.verifying_key().to_bytes().to_vec()).unwrap()
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

struct World {
    c: SudoByContract,
    now_ms: u64,
    mpc: SigningKey,
}

impl World {
    fn ctx(&self) -> VMContextBuilder {
        let mut b = VMContextBuilder::new();
        b.current_account_id(acc(CONTRACT))
            .block_timestamp(self.now_ms * 1_000_000)
            .prepaid_gas(Gas::from_tgas(300))
            .random_seed([3u8; 32]);
        b
    }

    fn as_owner(&self) {
        let mut b = self.ctx();
        b.predecessor_account_id(acc(OWNER)).signer_account_id(acc(OWNER));
        testing_env!(b.build());
    }

    fn as_key(&self, sk: &SigningKey) {
        self.as_key_gas(sk, 300);
    }

    fn as_key_gas(&self, sk: &SigningKey, tgas: u64) {
        let mut b = self.ctx();
        b.predecessor_account_id(acc(CONTRACT))
            .signer_account_id(acc(CONTRACT))
            .signer_account_pk(pk_of(sk))
            .prepaid_gas(Gas::from_tgas(tgas));
        testing_env!(b.build());
    }

    fn callback(&self, result: PromiseResult) {
        let mut b = self.ctx();
        b.predecessor_account_id(acc(CONTRACT)).signer_account_id(acc(OWNER));
        testing_env!(
            b.build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            vec![result],
        );
    }

    fn enroll(&mut self, role: Role, principal: &str, token: &SigningKey, real: &SigningKey) {
        self.as_owner();
        self.c.create_enrollment(role, principal.into(), pk_of(token), Some(600)).detach();
        self.as_key(token);
        let r = self.c.complete_enrollment(pk_of(real), Some(EnrollMeta { gate_version: Some("0.1.0".into()), host_fingerprint: None }));
        assert!(r.ok, "{}", r.message);
    }

    /// Answer the pending MPC sign request for `id` like the network would.
    fn mpc_sign(&mut self, id: u64) -> bool {
        let tbs = hex::decode(self.c.get_request(id).unwrap().pending_tbs.unwrap()).unwrap();
        let sig = self.mpc.sign(&tbs).to_bytes();
        let body = json!({ "scheme": "Ed25519", "signature": sig.to_vec() }).to_string();
        self.callback(PromiseResult::Successful(body.into_bytes()));
        self.c.on_signed(id, Ok(serde_json::from_value(json!({ "scheme": "Ed25519", "signature": sig.to_vec() })).unwrap()))
    }

    fn advance_secs(&mut self, s: u64) {
        self.now_ms += s * 1000;
        // re-install the mocked chain so views observe the new block time
        self.as_owner();
    }
}

// keys
fn admin_dev() -> SigningKey { key(10) }
fn agent_key() -> SigningKey { key(20) }
fn gate_key() -> SigningKey { key(30) }
fn gate2_key() -> SigningKey { key(31) }
fn approver_dev() -> SigningKey { key(40) }
fn approver2_dev() -> SigningKey { key(41) }
fn agent_ssh() -> SigningKey { key(50) }

fn policy_input(id: &str, kind: &str, targets: &[&str], max: u32, uses: u32, approvals: u8) -> PolicyInput {
    PolicyInput {
        id: id.into(),
        name: format!("Policy {}", id),
        description: String::new(),
        effect: Effect::Allow,
        subjects: SubjectSelector { all_agents: false, agents: vec!["deploy-agent".into()] },
        resources: ResourceSelector { ids: vec![], environments: vec!["production".into()], tags: vec![] },
        actions: vec![ActionRule { kind: kind.into(), targets: targets.iter().map(|s| s.to_string()).collect() }],
        max_duration_secs: max,
        max_uses: uses,
        approval: ApprovalRule { required: approvals, approvers: vec![] },
        conditions: Conditions::default(),
    }
}

fn world() -> World {
    let mut w = World {
        c: {
            let mut b = VMContextBuilder::new();
            b.current_account_id(acc(CONTRACT)).predecessor_account_id(acc(CONTRACT)).block_timestamp(T0_MS * 1_000_000);
            testing_env!(b.build());
            SudoByContract::new(acc(OWNER), acc(MPC), None)
        },
        now_ms: T0_MS,
        mpc: SigningKey::from_bytes(&[99u8; 32]),
    };
    // environment + CA key from the (simulated) MPC network
    w.as_owner();
    w.c.add_environment("production".into()).detach();
    let ca_pk = PublicKey::from_parts(CurveType::ED25519, w.mpc.verifying_key().to_bytes().to_vec()).unwrap();
    let ca_str = String::from(&ca_pk);
    w.callback(PromiseResult::Successful(serde_json::to_vec(&ca_str).unwrap()));
    assert!(w.c.on_ca_key("production".into(), Ok(ca_str)));

    w.as_owner();
    w.c.create_approver("success".into(), "Success".into(), true);
    w.c.create_approver("oncall".into(), "On-call SRE".into(), false);
    w.c.create_agent("deploy-agent".into(), "Deploy Agent".into(), "platform-team".into(), "claude-opus-5-5".into());
    w.c.create_resource("prod-web-02".into(), "prod-web-02".into(), "production".into(), vec!["web".into()], vec!["checkout-api".into(), "payments-api".into(), "sshd".into()]);
    w.c.create_resource("prod-web-03".into(), "prod-web-03".into(), "production".into(), vec![], vec!["checkout-api".into()]);
    w.enroll(Role::Admin, "success", &key(1), &admin_dev());
    w.enroll(Role::Approver, "oncall", &key(2), &approver_dev());
    w.enroll(Role::Agent, "deploy-agent", &key(3), &agent_key());
    w.enroll(Role::Gate, "prod-web-02", &key(4), &gate_key());
    w.enroll(Role::Gate, "prod-web-03", &key(5), &gate2_key());
    w.as_key(&admin_dev());
    w.c.upsert_policy(policy_input("prod-remediation", "service.restart", &["checkout-api", "payments-api"], 900, 1, 1));
    w
}

fn request(w: &mut World, action: &str, secs: u32) -> u64 {
    w.as_key(&agent_key());
    w.c.request_access(RequestAccessArgs {
        resource_id: "prod-web-02".into(),
        action: action.into(),
        duration_secs: secs,
        uses: None,
        ssh_public_key: ssh::ed25519_pubkey_line(&agent_ssh().verifying_key().to_bytes(), "agent"),
        source_address: None,
        reason: "checkout-api stopped responding after deploy #1842".into(),
        context_hash: Some("ab".repeat(32)),
    })
}

fn consume(w: &mut World, gate: &SigningKey, id: u64, action: &str) -> ConsumeResult {
    w.as_key(gate);
    w.c.consume(id, action.into(), Some("sess-1".into()))
}

fn approved_active(w: &mut World, secs: u32) -> u64 {
    let id = request(w, "service.restart:checkout-api", secs);
    w.as_key(&approver_dev());
    w.c.approve(id, None);
    assert!(w.mpc_sign(id));
    id
}

#[test]
fn hero_flow_request_approve_issue_execute_deny_expire() {
    let mut w = world();
    let id = request(&mut w, "service.restart:checkout-api", 600);
    let r = w.c.get_request(id).unwrap();
    assert_eq!(r.state, RequestState::PendingApproval);
    assert_eq!(r.required_approvals, 1);
    assert!(r.checks.iter().all(|c| c.ok), "{:?}", r.checks);
    assert_eq!(r.policy_id.as_deref(), Some("prod-remediation"));

    w.as_key(&approver_dev());
    w.c.approve(id, None);
    assert_eq!(w.c.get_request(id).unwrap().state, RequestState::Signing);
    assert!(w.mpc_sign(id));

    let r = w.c.get_request(id).unwrap();
    assert_eq!(r.state, RequestState::Active);
    let (_, cert) = ssh::parse_cert_line(r.certificate.as_ref().unwrap()).unwrap();
    assert_eq!(cert.serial, serial_for(id));
    assert_ne!(cert.serial, 0, "OpenSSH KRLs cannot revoke serial 0");
    assert_eq!(cert.principals, vec!["sbc-prod-web-02".to_string()]);
    assert_eq!(cert.critical_option("force-command"), Some("/usr/local/sbin/sbc-gate"));
    assert!(cert.extensions.is_empty(), "no pty / forwarding");
    assert_eq!(cert.valid_before - cert.valid_after, 600 + 60);
    assert_eq!(cert.subject_key, agent_ssh().verifying_key().to_bytes());
    assert_eq!(cert.ca_key, w.mpc.verifying_key().to_bytes());

    // `sudo systemctl restart sshd` parses, but is out of scope
    let d = consume(&mut w, &gate_key(), id, "service.restart:sshd");
    assert!(!d.allowed);
    assert_eq!(d.code, "out_of_scope");
    // `sudo cat /etc/shadow` never parses into an action: gate reports it
    w.as_key(&gate_key());
    w.c.report_denial(Some(id), "no_adapter".into(), "cat".into(), "cd".repeat(32));

    let ok = consume(&mut w, &gate_key(), id, "service.restart:checkout-api");
    assert!(ok.allowed, "{}", ok.message);
    assert_eq!((ok.uses, ok.max_uses), (1, 1));
    // single use: the window is still open, but the capability is spent
    let again = consume(&mut w, &gate_key(), id, "service.restart:checkout-api");
    assert!(!again.allowed);
    assert_eq!(again.code, "exhausted");

    let r = w.c.get_request(id).unwrap();
    assert_eq!(r.state, RequestState::Exhausted);
    assert_eq!(r.denied_attempts, 3);
    let kinds: Vec<_> = r.events.iter().map(|e| e.kind.as_str()).collect();
    for k in ["request_created", "policy_evaluated", "approval_granted", "credential_signing", "credential_issued", "command_denied", "command_allowed", "authorization_used"] {
        assert!(kinds.contains(&k), "missing {k} in {kinds:?}");
    }
    let a = w.c.get_agent("deploy-agent".into()).unwrap();
    assert_eq!(a.stats.actions_allowed, 1);
    assert_eq!(a.stats.actions_denied, 3);
}

/// Regression from the live testnet run: after the single use was consumed,
/// `restart sshd` was labelled `exhausted`. It must be recorded as what it is.
#[test]
fn scope_escalation_is_labelled_even_after_the_capability_is_spent() {
    let mut w = world();
    let id = approved_active(&mut w, 600);
    assert!(consume(&mut w, &gate_key(), id, "service.restart:checkout-api").allowed);
    let d = consume(&mut w, &gate_key(), id, "service.restart:sshd");
    assert_eq!(d.code, "out_of_scope");
    let again = consume(&mut w, &gate_key(), id, "service.restart:checkout-api");
    assert_eq!(again.code, "exhausted");
}

#[test]
fn expiry_is_enforced_by_block_time() {
    let mut w = world();
    let mut p = policy_input("prod-remediation", "service.restart", &["checkout-api"], 900, 5, 1);
    p.max_uses = 5;
    w.as_key(&admin_dev());
    w.c.upsert_policy(p);
    w.as_key(&agent_key());
    let id = w.c.request_access(RequestAccessArgs {
        resource_id: "prod-web-02".into(),
        action: "service.restart:checkout-api".into(),
        duration_secs: 600,
        uses: Some(5),
        ssh_public_key: ssh::b64(&agent_ssh().verifying_key().to_bytes()),
        source_address: None,
        reason: "r".into(),
        context_hash: None,
    });
    w.as_key(&approver_dev());
    w.c.approve(id, None);
    assert!(w.mpc_sign(id));
    assert!(consume(&mut w, &gate_key(), id, "service.restart:checkout-api").allowed);
    w.advance_secs(601);
    assert_eq!(w.c.get_request(id).unwrap().state, RequestState::Expired);
    let d = consume(&mut w, &gate_key(), id, "service.restart:checkout-api");
    assert!(!d.allowed);
    assert_eq!(d.code, "expired");
    let r = w.c.get_request(id).unwrap();
    assert!(r.events.iter().any(|e| e.kind == "authorization_expired"));
}

#[test]
fn revocation_is_immediate_and_feeds_krl() {
    let mut w = world();
    let id = approved_active(&mut w, 600);
    w.as_key(&approver_dev());
    w.c.revoke(id, "incident resolved by human".into());
    let d = consume(&mut w, &gate_key(), id, "service.restart:checkout-api");
    assert!(!d.allowed);
    assert_eq!(d.code, "revoked");
    let rev = w.c.list_revocations("prod-web-02".into(), None);
    assert_eq!(rev.len(), 1);
    assert_eq!(rev[0].serial, serial_for(id));
    assert!(w.c.list_revocations("prod-web-03".into(), None).is_empty());
}

#[test]
fn host_escalation_is_denied() {
    let mut w = world();
    let id = approved_active(&mut w, 600);
    let d = consume(&mut w, &gate2_key(), id, "service.restart:checkout-api");
    assert!(!d.allowed);
    assert_eq!(d.code, "wrong_resource");
    // and the real host can still use it
    assert!(consume(&mut w, &gate_key(), id, "service.restart:checkout-api").allowed);
}

#[test]
fn disabled_resource_is_a_kill_switch() {
    let mut w = world();
    let id = approved_active(&mut w, 600);
    w.as_key(&admin_dev());
    w.c.set_resource_status("prod-web-02".into(), ResourceStatus::Disabled);
    let d = consume(&mut w, &gate_key(), id, "service.restart:checkout-api");
    assert_eq!(d.code, "resource_disabled");
}

#[test]
fn policy_rejections_are_explained() {
    let mut w = world();
    // too long
    let id = request(&mut w, "service.restart:checkout-api", 1800);
    let r = w.c.get_request(id).unwrap();
    assert_eq!(r.state, RequestState::Rejected);
    let dur = r.checks.iter().find(|c| c.name == "duration").unwrap();
    assert!(!dur.ok);
    assert_eq!(dur.detail, "requested 30m / allowed 15m");
    // target not granted by policy
    let id = request(&mut w, "service.restart:sshd", 600);
    let r = w.c.get_request(id).unwrap();
    assert_eq!(r.state, RequestState::Rejected);
    assert!(!r.checks.iter().find(|c| c.name == "target").unwrap().ok);
    // target not exposed by the host at all
    let id = request(&mut w, "service.restart:postgres", 600);
    let r = w.c.get_request(id).unwrap();
    assert_eq!(r.state, RequestState::Rejected);
    assert!(r.state_reason.unwrap().contains("does not expose"));
    assert_eq!(w.c.get_agent("deploy-agent".into()).unwrap().stats.rejected, 3);
}

#[test]
fn explicit_deny_wins_over_allow() {
    let mut w = world();
    w.as_key(&admin_dev());
    w.c.upsert_policy(policy_input("broad", "service.restart", &["*"], 900, 1, 0));
    let mut deny = policy_input("never-sshd", "service.restart", &["sshd"], 900, 1, 0);
    deny.effect = Effect::Deny;
    deny.subjects = SubjectSelector { all_agents: true, agents: vec![] };
    w.c.upsert_policy(deny);
    let id = request(&mut w, "service.restart:sshd", 600);
    let r = w.c.get_request(id).unwrap();
    assert_eq!(r.state, RequestState::Rejected);
    assert_eq!(r.checks[0].name, "deny");
    // the broad auto policy still governs checkout-api, and wins over the 1-approval one
    let id = request(&mut w, "service.restart:checkout-api", 600);
    let r = w.c.get_request(id).unwrap();
    assert_eq!(r.state, RequestState::Signing);
    assert_eq!(r.policy_id.as_deref(), Some("broad"));
}

#[test]
fn auto_approval_signs_in_the_request_transaction() {
    let mut w = world();
    w.as_key(&admin_dev());
    w.c.upsert_policy(policy_input("logs", "logs.read", &["checkout-api"], 900, 3, 0));
    let id = request(&mut w, "logs.read:checkout-api", 300);
    assert_eq!(w.c.get_request(id).unwrap().state, RequestState::Signing);
    assert!(w.mpc_sign(id));
    assert_eq!(w.c.get_request(id).unwrap().state, RequestState::Active);
}

#[test]
#[should_panic(expected = "attach at least 150 Tgas")]
fn signing_requires_enough_gas() {
    let mut w = world();
    let id = request(&mut w, "service.restart:checkout-api", 600);
    w.as_key_gas(&approver_dev(), 60);
    w.c.approve(id, None);
}

#[test]
fn bad_mpc_signature_fails_closed() {
    let mut w = world();
    let id = request(&mut w, "service.restart:checkout-api", 600);
    w.as_key(&approver_dev());
    w.c.approve(id, None);
    let forged = key(77).sign(b"not the certificate").to_bytes();
    w.callback(PromiseResult::Successful(vec![]));
    let ok = w.c.on_signed(id, Ok(MpcSignatureResponse::Ed25519 { signature: forged.to_vec() }));
    assert!(!ok);
    let r = w.c.get_request(id).unwrap();
    assert_eq!(r.state, RequestState::Failed);
    assert!(r.certificate.is_none());
    let d = consume(&mut w, &gate_key(), id, "service.restart:checkout-api");
    assert_eq!(d.code, "not_active");
}

#[test]
fn mpc_timeout_fails_closed() {
    let mut w = world();
    let id = request(&mut w, "service.restart:checkout-api", 600);
    w.as_key(&approver_dev());
    w.c.approve(id, None);
    w.callback(PromiseResult::Failed);
    assert!(!w.c.on_signed(id, Err(PromiseError::Failed)));
    assert_eq!(w.c.get_request(id).unwrap().state, RequestState::Failed);
}

#[test]
fn revoked_while_signing_discards_signature() {
    let mut w = world();
    let id = request(&mut w, "service.restart:checkout-api", 600);
    w.as_key(&approver_dev());
    w.c.approve(id, None);
    w.as_key(&admin_dev());
    w.c.revoke(id, "changed my mind".into());
    assert!(!w.mpc_sign(id));
    let r = w.c.get_request(id).unwrap();
    assert_eq!(r.state, RequestState::Revoked);
    assert!(r.certificate.is_none());
}

#[test]
fn approvers_can_only_narrow_and_multi_approval_counts() {
    let mut w = world();
    w.enroll(Role::Approver, "success", &key(6), &approver2_dev());
    w.as_key(&admin_dev());
    w.c.upsert_policy(policy_input("prod-remediation", "service.restart", &["checkout-api"], 900, 1, 2));
    let id = request(&mut w, "service.restart:checkout-api", 600);
    w.as_key(&approver_dev());
    w.c.approve(id, Some(300));
    assert_eq!(w.c.get_request(id).unwrap().state, RequestState::PendingApproval);
    w.as_key(&approver2_dev());
    w.c.approve(id, None);
    let r = w.c.get_request(id).unwrap();
    assert_eq!(r.state, RequestState::Signing);
    assert_eq!(r.granted_duration_secs, 300);
}

#[test]
#[should_panic(expected = "already approved")]
fn same_approver_cannot_count_twice() {
    let mut w = world();
    w.as_key(&admin_dev());
    w.c.upsert_policy(policy_input("prod-remediation", "service.restart", &["checkout-api"], 900, 1, 2));
    let id = request(&mut w, "service.restart:checkout-api", 600);
    w.as_key(&approver_dev());
    w.c.approve(id, None);
    w.c.approve(id, None);
}

#[test]
#[should_panic(expected = "approvers can only narrow the window")]
fn approvers_cannot_widen() {
    let mut w = world();
    let id = request(&mut w, "service.restart:checkout-api", 600);
    w.as_key(&approver_dev());
    w.c.approve(id, Some(900));
}

#[test]
#[should_panic(expected = "only approvers can do this")]
fn agents_cannot_approve_their_own_requests() {
    let mut w = world();
    let id = request(&mut w, "service.restart:checkout-api", 600);
    w.as_key(&agent_key());
    w.c.approve(id, None);
}

#[test]
#[should_panic(expected = "not bound to any identity")]
fn unknown_keys_are_rejected() {
    let mut w = world();
    w.as_key(&key(123));
    w.c.consume(0, "service.restart:checkout-api".into(), None);
}

#[test]
#[should_panic(expected = "role Agent, not Gate")]
fn agents_cannot_consume_for_the_gate() {
    let mut w = world();
    let id = approved_active(&mut w, 600);
    w.as_key(&agent_key());
    w.c.consume(id, "service.restart:checkout-api".into(), None);
}

#[test]
fn approval_window_expires() {
    let mut w = world();
    let id = request(&mut w, "service.restart:checkout-api", 600);
    w.advance_secs(16 * 60);
    assert_eq!(w.c.get_request(id).unwrap().state, RequestState::ApprovalExpired);
    w.as_key(&approver_dev());
    w.c.approve(id, None); // no-op: settles the state
    assert_eq!(w.c.get_request(id).unwrap().state, RequestState::ApprovalExpired);
}

#[test]
fn agent_release_revokes_serial() {
    let mut w = world();
    let id = approved_active(&mut w, 600);
    w.as_key(&agent_key());
    w.c.cancel_request(id);
    assert_eq!(w.c.get_request(id).unwrap().state, RequestState::Cancelled);
    assert_eq!(consume(&mut w, &gate_key(), id, "service.restart:checkout-api").code, "released");
    assert_eq!(w.c.list_revocations("prod-web-02".into(), None).len(), 1);
}

#[test]
#[should_panic(expected = "too many live requests")]
fn live_requests_are_bounded() {
    let mut w = world();
    for _ in 0..5 {
        request(&mut w, "service.restart:checkout-api", 600);
    }
}

#[test]
fn enrollment_tokens_expire_and_are_single_use() {
    let mut w = world();
    w.as_owner();
    w.c.create_enrollment(Role::Agent, "deploy-agent".into(), pk_of(&key(60)), Some(60)).detach();
    w.advance_secs(120);
    w.as_key(&key(60));
    let r = w.c.complete_enrollment(pk_of(&key(61)), None);
    assert!(!r.ok);
    assert!(w.c.whoami(pk_of(&key(60))).binding.is_none(), "token is unbound after use");
    assert!(w.c.whoami(pk_of(&key(61))).binding.is_none());
}

#[test]
fn audit_chain_advances_and_policy_is_versioned() {
    let mut w = world();
    let before = w.c.get_overview();
    w.as_key(&admin_dev());
    let v = w.c.upsert_policy(policy_input("prod-remediation", "service.restart", &["checkout-api"], 600, 1, 1));
    assert_eq!(v, 2);
    let after = w.c.get_overview();
    assert!(after.audit_seq > before.audit_seq);
    assert_ne!(after.audit_head, before.audit_head);
    assert_eq!(w.c.get_policy("prod-remediation".into(), Some(1)).unwrap().max_duration_secs, 900);
    assert_eq!(
        w.c.describe_policy("prod-remediation".into()).unwrap(),
        "deploy-agent may restart checkout-api once on production servers after one human approval. Access expires after 10m."
    );
}

fn with_quorum_of_two(w: &mut World) -> SigningKey {
    w.as_owner();
    w.c.create_approver("admin2".into(), "Second admin".into(), true);
    let admin2 = key(11);
    w.enroll(Role::Admin, "admin2", &key(7), &admin2);
    w.as_owner();
    w.c.set_config(None, None, None, None, None, None, Some(2));
    admin2
}

#[test]
fn policy_changes_need_the_admin_quorum() {
    let mut w = world();
    let admin2 = with_quorum_of_two(&mut w);
    // a single admin widening the policy only creates a proposal
    w.as_key(&admin_dev());
    let v = w.c.upsert_policy(policy_input("prod-remediation", "service.restart", &["checkout-api", "payments-api", "sshd"], 3600, 5, 0));
    assert_eq!(v, 0);
    let p = w.c.get_policy("prod-remediation".into(), None).unwrap();
    assert_eq!((p.version, p.max_duration_secs, p.approval.required), (1, 900, 1), "nothing changed yet");
    let props = w.c.list_policy_proposals();
    assert_eq!(props.len(), 1);
    // the second admin agrees → applied
    w.as_key(&admin2);
    let v = w.c.confirm_policy(props[0].id);
    assert_eq!(v, 2);
    let p = w.c.get_policy("prod-remediation".into(), None).unwrap();
    assert_eq!((p.max_duration_secs, p.approval.required), (3600, 0));
    assert_eq!(p.updated_by, "success+admin2");
    assert!(w.c.list_policy_proposals().is_empty());
}

#[test]
#[should_panic(expected = "you already approved this change")]
fn proposer_cannot_meet_the_quorum_alone() {
    let mut w = world();
    with_quorum_of_two(&mut w);
    w.as_key(&admin_dev());
    w.c.upsert_policy(policy_input("prod-remediation", "service.restart", &["*"], 3600, 5, 0));
    let id = w.c.list_policy_proposals()[0].id;
    w.c.confirm_policy(id);
}

#[test]
fn under_quorum_disabling_is_immediate_but_reenabling_is_not() {
    let mut w = world();
    with_quorum_of_two(&mut w);
    w.as_key(&admin_dev());
    w.c.set_policy_status("prod-remediation".into(), Status::Suspended);
    assert_eq!(w.c.get_policy("prod-remediation".into(), None).unwrap().status, Status::Suspended);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        w.c.set_policy_status("prod-remediation".into(), Status::Active);
    }));
    assert!(r.is_err());
}

#[test]
fn simulate_matches_request_evaluation() {
    let w = world();
    let s = w.c.simulate("deploy-agent".into(), "prod-web-02".into(), "service.restart:checkout-api".into(), 600, None, None);
    assert_eq!(s.outcome, "needs_approval");
    assert_eq!(s.required_approvals, 1);
    let s = w.c.simulate("deploy-agent".into(), "prod-web-02".into(), "service.restart:checkout-api".into(), 3600, None, None);
    assert_eq!(s.outcome, "rejected");
}
