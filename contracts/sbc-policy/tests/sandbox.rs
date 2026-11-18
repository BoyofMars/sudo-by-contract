//! Sandbox integration tests: the policy contract on a real NEAR runtime.
//!
//! `src/tests.rs` drives the contract through near-sdk's mocked environment
//! and hands `on_signed` a simulated MPC answer. These tests start a local
//! NEAR node instead (near-workspaces), deploy the policy contract next to
//! `contracts/mock-mpc-signer` (a TEST-ONLY stand-in for
//! `v1.signer-prod.testnet`), and drive the capability lifecycle with real
//! signed transactions:
//!
//! * every identity (admin, approver, agent, gate) is a function-call access
//!   key that the contract added to its own account through enrollment, so the
//!   NEAR protocol itself limits which methods each key can call;
//! * approving a request makes a real cross-contract call to the signer, and
//!   the certificate is issued by the real `on_signed` callback, which checks
//!   the signature with the `ed25519_verify` host function.
//!
//! ## Running
//!
//! The tests are `#[ignore]`d, so `cargo test --workspace` stays a plain unit
//! test run that needs no wasm build and works on Windows (the NEAR sandbox
//! node only runs on Linux x86_64/aarch64 and macOS arm64). CI's `sandbox` job
//! runs them on Linux:
//!
//! ```sh
//! (cd contracts/sbc-policy && cargo near build non-reproducible-wasm --no-abi)
//! (cd contracts/mock-mpc-signer && cargo near build non-reproducible-wasm --no-abi)
//! cargo test -p sbc-policy --test sandbox -- --ignored
//! ```
//!
//! The wasm files are read from `target/near/<crate>/<crate>.wasm` (under
//! `$CARGO_TARGET_DIR` when that is set); `SBC_POLICY_WASM` and
//! `MOCK_MPC_SIGNER_WASM` override the paths. near-sandbox downloads the node
//! binary on first use; `NEAR_SANDBOX_BIN_PATH` points it at an existing one.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use near_sdk::serde::de::DeserializeOwned;
use near_sdk::serde_json::{json, Value};
use near_workspaces::network::Sandbox;
use near_workspaces::result::{ExecutionFinalResult, ExecutionSuccess};
use near_workspaces::types::{AccessKeyPermission, Gas, KeyType, NearToken, PublicKey, SecretKey};
use near_workspaces::{Account, AccountId, Contract, Worker};
use sbc_core::ssh;
use sbc_policy::types::{
    AccessRequest, ActionRule, Agent, ApprovalRule, Conditions, ConsumeResult, Effect, PolicyInput, RequestState,
    ResourceSelector, Revocation, Role, SubjectSelector,
};
use sbc_policy::{serial_for, EnrollResult};
use std::path::{Path, PathBuf};
use std::time::Duration;

const ENV: &str = "production";
/// `CA_PATH_PREFIX/v<ca_version>/<environment>` in the contract.
const CA_PATH: &str = "sbc/ssh-user-ca/v1/production";
const RESOURCE: &str = "prod-web-02";
const AGENT: &str = "deploy-agent";
const APPROVER: &str = "oncall";
const RESTART: &str = "service.restart:checkout-api";
const OUT_OF_SCOPE: &str = "service.restart:sshd";
/// `approve` starts MPC signing and requires the signing gas up front.
const SIGNING_TGAS: u64 = 300;

// ------------------------------------------------------------------ wasm

fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("target"))
}

fn wasm(krate: &str, override_var: &str) -> Vec<u8> {
    let path = std::env::var_os(override_var)
        .map(PathBuf::from)
        .unwrap_or_else(|| target_dir().join("near").join(krate).join(format!("{krate}.wasm")));
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {} ({e}); build it with `cargo near build non-reproducible-wasm --no-abi` \
             (see the header of tests/sandbox.rs) or set {override_var}",
            path.display()
        )
    })
}

// ---------------------------------------------------------- transactions

async fn send(signer: &Account, receiver: &AccountId, method: &str, args: Value, tgas: u64) -> ExecutionFinalResult {
    signer
        .call(receiver, method)
        .args_json(args)
        .gas(Gas::from_tgas(tgas))
        .transact()
        .await
        .unwrap_or_else(|e| panic!("{method}: transaction refused: {e:?}"))
}

/// The transaction and every receipt it spawned (detached promises such as
/// the MPC sign call included) succeeded.
fn ok(method: &str, outcome: ExecutionFinalResult) -> ExecutionSuccess {
    let failed: Vec<String> = outcome.receipt_failures().iter().map(|o| format!("{o:?}")).collect();
    assert!(failed.is_empty(), "{method}: receipts failed: {failed:#?}");
    outcome.into_result().unwrap_or_else(|e| panic!("{method} failed: {e:?}"))
}

/// The protocol let the transaction in, and the contract panicked with `message`.
fn contract_refused(method: &str, outcome: ExecutionFinalResult, message: &str) {
    let failure = outcome.into_result().map(|_| ()).expect_err(&format!("{method} was accepted"));
    let text = format!("{failure:?}");
    assert!(text.contains(message), "{method}: expected a contract panic with {message:?}, got {text}");
}

/// The NEAR runtime rejected the transaction because of the signing key's
/// permissions (`protocol_error` is the `InvalidAccessKeyError` variant), so
/// the contract never ran.
async fn runtime_refused(signer: &Account, receiver: &AccountId, method: &str, args: Value, protocol_error: &str) {
    let outcome = signer.call(receiver, method).args_json(args).gas(Gas::from_tgas(30)).transact().await;
    let text = match outcome {
        Err(e) => format!("{e:?}"),
        Ok(r) => {
            assert!(r.is_failure(), "{method} on {receiver} was accepted: {r:?}");
            format!("{r:?}")
        }
    };
    assert!(text.contains(protocol_error), "{method} on {receiver}: expected {protocol_error}, got {text}");
}

async fn view<T: DeserializeOwned>(contract: &Contract, method: &str, args: Value) -> T {
    contract
        .view(method)
        .args_json(args)
        .await
        .unwrap_or_else(|e| panic!("view {method}: {e:?}"))
        .json()
        .unwrap_or_else(|e| panic!("view {method}: {e:?}"))
}

fn raw_ed25519(near_key: &str) -> [u8; 32] {
    let pk: PublicKey = near_key.parse().unwrap_or_else(|e| panic!("{near_key}: {e:?}"));
    pk.key_data().try_into().expect("32-byte Ed25519 key")
}

/// The agent's ephemeral SSH key; only its public half goes on-chain.
fn agent_ssh() -> SigningKey {
    SigningKey::from_bytes(&[50u8; 32])
}

// ----------------------------------------------------------------- world

struct World {
    worker: Worker<Sandbox>,
    /// The policy contract. Its own full-access (deploy) key is not an identity.
    sbc: Contract,
    /// The TEST-ONLY MPC signer mock.
    mpc: Contract,
    /// The owner account named at init (a separate account).
    owner: Account,
    // Identities: function-call keys on the contract account.
    admin: Account,
    approver: Account,
    agent: Account,
    gate: Account,
}

async fn subaccount(parent: &Account, name: &str, near: u128) -> Account {
    parent
        .create_subaccount(name)
        .initial_balance(NearToken::from_near(near))
        .keys(SecretKey::from_random(KeyType::ED25519))
        .transact()
        .await
        .unwrap_or_else(|e| panic!("create {name}: {e:?}"))
        .into_result()
        .unwrap_or_else(|e| panic!("create {name}: {e:?}"))
}

async fn deploy(account: Account, code: &[u8]) -> Contract {
    let id = account.id().clone();
    account
        .deploy(code)
        .await
        .unwrap_or_else(|e| panic!("deploy to {id}: {e:?}"))
        .into_result()
        .unwrap_or_else(|e| panic!("deploy to {id}: {e:?}"))
}

/// Owner mints a one-time enrollment token (a key that can only call
/// `complete_enrollment`); the token is spent to bind a freshly generated
/// device key, which the contract adds to its own account with the role's
/// method list. Returns that device key as a signer on the contract account.
async fn enroll(worker: &Worker<Sandbox>, sbc: &Contract, owner: &Account, role: &str, principal: &str) -> Account {
    let token = SecretKey::from_random(KeyType::ED25519);
    let args = json!({ "role": role, "principal": principal, "token_public_key": token.public_key().to_string(), "ttl_secs": 600 });
    ok("create_enrollment", send(owner, sbc.id(), "create_enrollment", args, 50).await);

    let device = SecretKey::from_random(KeyType::ED25519);
    let token = Account::from_secret_key(sbc.id().clone(), token, worker);
    let args = json!({ "new_public_key": device.public_key().to_string(), "meta": null });
    let r: EnrollResult = ok("complete_enrollment", send(&token, sbc.id(), "complete_enrollment", args, 50).await)
        .json()
        .expect("EnrollResult");
    assert!(r.ok, "{role} enrollment of {principal}: {}", r.message);
    Account::from_secret_key(sbc.id().clone(), device, worker)
}

fn remediation_policy() -> PolicyInput {
    PolicyInput {
        id: "prod-remediation".into(),
        name: "Production service remediation".into(),
        description: "One restart of a customer-facing service, after a human approves it.".into(),
        effect: Effect::Allow,
        subjects: SubjectSelector { all_agents: false, agents: vec![AGENT.into()] },
        resources: ResourceSelector { ids: vec![], environments: vec![ENV.into()], tags: vec![] },
        actions: vec![ActionRule { kind: "service.restart".into(), targets: vec!["checkout-api".into(), "payments-api".into()] }],
        max_duration_secs: 900,
        max_uses: 1,
        approval: ApprovalRule { required: 1, approvers: vec![] },
        conditions: Conditions::default(),
    }
}

/// Deploy both contracts, create the environment (its CA key comes from the
/// signer), the identities and one policy needing a single human approval.
async fn world() -> World {
    let worker = near_workspaces::sandbox().await.expect("start the NEAR sandbox");
    let root = worker.root_account().expect("sandbox root account");
    let owner = subaccount(&root, "owner", 20).await;
    let mpc = deploy(subaccount(&root, "mpc", 10).await, &wasm("mock_mpc_signer", "MOCK_MPC_SIGNER_WASM")).await;
    let sbc = deploy(subaccount(&root, "sbc", 50).await, &wasm("sbc_policy", "SBC_POLICY_WASM")).await;

    let init = json!({ "owner": owner.id().to_string(), "mpc_contract": mpc.id().to_string(), "mpc_domain_id": 1 });
    ok("new", send(sbc.as_account(), sbc.id(), "new", init, 30).await);

    // derived_public_key → on_ca_key, all inside this transaction
    let ca_ready: bool =
        ok("add_environment", send(&owner, sbc.id(), "add_environment", json!({ "name": ENV }), 100).await).json().unwrap();
    assert!(ca_ready, "on_ca_key rejected the signer's derived key");

    for (id, label, is_admin) in [("tobi", "Tobi", true), (APPROVER, "On-call SRE", false)] {
        let args = json!({ "id": id, "label": label, "is_admin": is_admin });
        ok("create_approver", send(&owner, sbc.id(), "create_approver", args, 30).await);
    }
    let args = json!({ "id": AGENT, "label": "Deploy Agent", "owner": "platform-team", "runtime": "sandbox test" });
    ok("create_agent", send(&owner, sbc.id(), "create_agent", args, 30).await);
    let args = json!({
        "id": RESOURCE, "label": RESOURCE, "environment": ENV, "tags": ["web"],
        "services": ["checkout-api", "payments-api", "sshd"],
    });
    ok("create_resource", send(&owner, sbc.id(), "create_resource", args, 30).await);

    let admin = enroll(&worker, &sbc, &owner, "Admin", "tobi").await;
    let approver = enroll(&worker, &sbc, &owner, "Approver", APPROVER).await;
    let agent = enroll(&worker, &sbc, &owner, "Agent", AGENT).await;
    let gate = enroll(&worker, &sbc, &owner, "Gate", RESOURCE).await;

    let version: u32 =
        ok("upsert_policy", send(&admin, sbc.id(), "upsert_policy", json!({ "policy": remediation_policy() }), 50).await)
            .json()
            .unwrap();
    assert_eq!(version, 1);

    World { worker, sbc, mpc, owner, admin, approver, agent, gate }
}

impl World {
    async fn request(&self, action: &str, duration_secs: u32) -> u64 {
        let args = json!({ "request": {
            "resource_id": RESOURCE,
            "action": action,
            "duration_secs": duration_secs,
            "uses": null,
            "ssh_public_key": ssh::ed25519_pubkey_line(&agent_ssh().verifying_key().to_bytes(), "agent"),
            "source_address": null,
            "reason": "checkout-api stopped responding after deploy #1842",
            "context_hash": "ab".repeat(32),
        }});
        ok("request_access", send(&self.agent, self.sbc.id(), "request_access", args, 100).await).json().unwrap()
    }

    async fn get(&self, id: u64) -> AccessRequest {
        view::<Option<AccessRequest>>(&self.sbc, "get_request", json!({ "id": id })).await.expect("request exists")
    }

    /// The sign → on_signed receipts belong to the approving transaction, so
    /// they have normally finished when it returns; poll briefly regardless.
    async fn wait_for(&self, id: u64, want: RequestState) -> AccessRequest {
        for _ in 0..40 {
            let r = self.get(id).await;
            if r.state == want {
                return r;
            }
            assert!(
                matches!(r.state, RequestState::PendingApproval | RequestState::Signing),
                "request {id} reached {:?} ({:?}) instead of {want:?}",
                r.state,
                r.state_reason
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        panic!("request {id} never reached {want:?}");
    }

    async fn approve_and_issue(&self, id: u64) -> AccessRequest {
        let args = json!({ "request_id": id, "max_duration_secs": null });
        ok("approve", send(&self.approver, self.sbc.id(), "approve", args, SIGNING_TGAS).await);
        self.wait_for(id, RequestState::Active).await
    }

    /// What the host gate does before running a command. Returns the verdict
    /// and the transaction's logs (NEP-297 audit events).
    async fn consume(&self, id: u64, action: &str) -> (ConsumeResult, Vec<String>) {
        let args = json!({ "request_id": id, "action": action, "session": "sandbox-1" });
        let s = ok("consume", send(&self.gate, self.sbc.id(), "consume", args, 50).await);
        let logs = s.logs().into_iter().map(String::from).collect();
        (s.json().expect("ConsumeResult"), logs)
    }
}

// ----------------------------------------------------------------- tests

#[tokio::test]
#[ignore = "needs the NEAR sandbox and cargo-near wasm builds; see the header of this file"]
async fn approved_capability_is_signed_by_mpc_and_enforced_at_the_gate() {
    let w = world().await;

    // The environment CA is the key the signer derives for (contract account, CA path).
    let ca_line: String = view::<Option<String>>(&w.sbc, "get_ca", json!({ "environment": ENV })).await.expect("CA key");
    let ca = ssh::parse_ed25519_pubkey_line(&ca_line).expect("ssh-ed25519 CA line");
    let derived: String =
        view(&w.mpc, "derived_public_key", json!({ "path": CA_PATH, "predecessor": w.sbc.id().to_string(), "domain_id": 1 }))
            .await;
    assert_eq!(ca, raw_ed25519(&derived), "the CA is the key derived for the contract account");
    let elsewhere: String =
        view(&w.mpc, "derived_public_key", json!({ "path": CA_PATH, "predecessor": w.owner.id().to_string(), "domain_id": 1 }))
            .await;
    assert_ne!(raw_ed25519(&elsewhere), ca, "another account asking for the same path gets another key");

    // Request: policy evaluation says one human approval.
    let id = w.request(RESTART, 600).await;
    let r = w.get(id).await;
    assert_eq!(r.state, RequestState::PendingApproval);
    assert_eq!(r.required_approvals, 1);
    assert_eq!(r.policy_id.as_deref(), Some("prod-remediation"));
    assert!(r.checks.iter().all(|c| c.ok), "{:?}", r.checks);
    assert!(r.certificate.is_none());

    // Approve: cross-contract sign → callback verifies → certificate.
    let r = w.approve_and_issue(id).await;
    assert_eq!(r.approvals.len(), 1);
    assert_eq!(r.approvals[0].approver_id, APPROVER);
    let kinds: Vec<&str> = r.events.iter().map(|e| e.kind.as_str()).collect();
    for k in ["request_created", "policy_evaluated", "approval_granted", "credential_signing", "credential_issued"] {
        assert!(kinds.contains(&k), "missing {k} in {kinds:?}");
    }
    let (blob, cert) = ssh::parse_cert_line(r.certificate.as_deref().expect("certificate issued")).expect("OpenSSH certificate");
    assert_eq!(cert.ca_key, ca, "certificate names the environment CA");
    VerifyingKey::from_bytes(&ca)
        .unwrap()
        .verify_strict(&blob[..cert.signed_len], &Signature::from_bytes(&cert.signature))
        .expect("certificate signature verifies against the MPC-derived CA key");
    assert_eq!(cert.serial, serial_for(id));
    assert_eq!(cert.principals, vec![format!("sbc-{RESOURCE}")]);
    assert_eq!(cert.critical_option("force-command"), Some("/usr/local/sbin/sbc-gate"));
    assert!(cert.extensions.is_empty(), "no pty / forwarding");
    assert_eq!(cert.subject_key, agent_ssh().verifying_key().to_bytes());
    assert_eq!((cert.valid_after, cert.valid_before), (r.valid_after, r.valid_before));
    assert_eq!(cert.valid_before - cert.valid_after, 600 + 60);

    // Gate: exactly one use.
    let (first, _) = w.consume(id, RESTART).await;
    assert!(first.allowed, "{}", first.message);
    assert_eq!((first.code.as_str(), first.uses, first.max_uses), ("allowed", 1, 1));
    let (second, _) = w.consume(id, RESTART).await;
    assert!(!second.allowed);
    assert_eq!(second.code, "exhausted");

    // Out of scope: denied, labelled as escalation, recorded on-chain.
    let (escalation, logs) = w.consume(id, OUT_OF_SCOPE).await;
    assert!(!escalation.allowed);
    assert_eq!(escalation.code, "out_of_scope");
    assert!(
        logs.iter().any(|l| l.starts_with("EVENT_JSON:") && l.contains("\"command_denied\"") && l.contains("out_of_scope")),
        "no command_denied audit event in {logs:?}"
    );
    let r = w.get(id).await;
    assert_eq!(r.state, RequestState::Exhausted);
    assert_eq!((r.uses, r.denied_attempts), (1, 2));
    assert!(
        r.events.iter().any(|e| e.kind == "command_denied" && e.detail.starts_with(&format!("out_of_scope: attempted {OUT_OF_SCOPE}"))),
        "{:?}",
        r.events
    );
    let agent: Agent = view::<Option<Agent>>(&w.sbc, "get_agent", json!({ "id": AGENT })).await.expect("agent");
    assert_eq!((agent.stats.actions_allowed, agent.stats.actions_denied), (1, 2));
}

#[tokio::test]
#[ignore = "needs the NEAR sandbox and cargo-near wasm builds; see the header of this file"]
async fn revoked_and_released_capabilities_land_on_the_revocation_list() {
    let w = world().await;

    // An approver revokes a live capability.
    let revoked = w.request(RESTART, 600).await;
    let issued = w.approve_and_issue(revoked).await;
    let args = json!({ "request_id": revoked, "reason": "incident resolved by a human" });
    ok("revoke", send(&w.approver, w.sbc.id(), "revoke", args, 50).await);
    let r = w.get(revoked).await;
    assert_eq!(r.state, RequestState::Revoked);
    assert_eq!(r.revoked_by.as_deref(), Some(APPROVER));
    assert_eq!(w.consume(revoked, RESTART).await.0.code, "revoked");

    // The agent releases one as soon as its task is done.
    let released = w.request(RESTART, 600).await;
    w.approve_and_issue(released).await;
    ok("cancel_request", send(&w.agent, w.sbc.id(), "cancel_request", json!({ "request_id": released }), 50).await);
    assert_eq!(w.get(released).await.state, RequestState::Cancelled);
    assert_eq!(w.consume(released, RESTART).await.0.code, "released");

    // Both serials are on the list the gate syncs into sshd's KRL, and they
    // are the serials of the certificates that were actually issued.
    let krl: Vec<Revocation> = view(&w.sbc, "list_revocations", json!({ "resource_id": RESOURCE, "from_index": null })).await;
    let serials: Vec<u64> = krl.iter().map(|r| r.serial).collect();
    assert_eq!(serials, vec![serial_for(revoked), serial_for(released)]);
    let (_, cert) = ssh::parse_cert_line(issued.certificate.as_deref().unwrap()).unwrap();
    assert_eq!(cert.serial, krl[0].serial);
    assert!(krl.iter().all(|r| r.resource_id == RESOURCE && r.valid_before > r.at_ms / 1000));
}

#[tokio::test]
#[ignore = "needs the NEAR sandbox and cargo-near wasm builds; see the header of this file"]
async fn role_keys_cannot_call_methods_outside_their_list() {
    let w = world().await;

    // Enrollment gave each identity a function-call key on the contract
    // account carrying exactly its role's methods and a spending allowance.
    for (who, role) in [(&w.admin, Role::Admin), (&w.approver, Role::Approver), (&w.agent, Role::Agent), (&w.gate, Role::Gate)] {
        let key = w
            .sbc
            .view_access_key(&who.secret_key().public_key())
            .await
            .unwrap_or_else(|e| panic!("{role:?} key is not on the contract account: {e:?}"));
        let AccessKeyPermission::FunctionCall(p) = key.permission else {
            panic!("{role:?} key has full access");
        };
        assert_eq!(p.receiver_id, w.sbc.id().to_string(), "{role:?}");
        assert_eq!(p.method_names, role.method_names().split(',').map(String::from).collect::<Vec<_>>(), "{role:?}");
        assert!(p.allowance.is_some(), "{role:?} key has an unlimited allowance");
    }

    let id = w.request(RESTART, 600).await;
    let approve = json!({ "request_id": id, "max_duration_secs": null });
    let request = json!({ "request": {
        "resource_id": RESOURCE, "action": RESTART, "duration_secs": 600, "uses": null,
        "ssh_public_key": ssh::b64(&agent_ssh().verifying_key().to_bytes()),
        "source_address": null, "reason": "r", "context_hash": null,
    }});
    let consume = json!({ "request_id": id, "action": RESTART, "session": null });
    let mint = json!({ "role": "Agent", "principal": AGENT, "token_public_key": SecretKey::from_random(KeyType::ED25519).public_key().to_string(), "ttl_secs": 600 });

    // The runtime refuses these before any contract code runs.
    runtime_refused(&w.agent, w.sbc.id(), "approve", approve.clone(), "MethodNameMismatch").await; // self-approval
    runtime_refused(&w.agent, w.sbc.id(), "consume", consume.clone(), "MethodNameMismatch").await;
    runtime_refused(&w.agent, w.sbc.id(), "create_enrollment", mint, "MethodNameMismatch").await;
    runtime_refused(&w.gate, w.sbc.id(), "request_access", request.clone(), "MethodNameMismatch").await;
    runtime_refused(&w.gate, w.sbc.id(), "approve", approve.clone(), "MethodNameMismatch").await;
    runtime_refused(&w.approver, w.sbc.id(), "consume", consume, "MethodNameMismatch").await;
    runtime_refused(&w.admin, w.sbc.id(), "request_access", request, "MethodNameMismatch").await;
    // ...and no role key reaches any other contract, e.g. to ask the signer
    // for signatures under the contract's CA key directly.
    let sign = json!({ "request": { "path": CA_PATH, "payload_v2": { "Eddsa": "00".repeat(32) }, "domain_id": 1 } });
    runtime_refused(&w.agent, w.mpc.id(), "sign", sign, "ReceiverMismatch").await;

    let r = w.get(id).await;
    assert_eq!(r.state, RequestState::PendingApproval, "nothing above reached the contract");
    assert!(r.approvals.is_empty());

    // Keys the protocol lets through must still be bound identities: neither
    // the contract account's own full-access key nor another account's key is.
    let out = send(w.sbc.as_account(), w.sbc.id(), "approve", approve.clone(), SIGNING_TGAS).await;
    contract_refused("approve with the contract's deploy key", out, "not bound to any identity");
    let mallory = subaccount(&w.worker.root_account().unwrap(), "mallory", 5).await;
    let out = send(&mallory, w.sbc.id(), "approve", approve, SIGNING_TGAS).await;
    contract_refused("approve from another account", out, "call with a Sudo by Contract access key");

    // Control: the approver's key does what the others could not.
    assert_eq!(w.approve_and_issue(id).await.approvals[0].approver_id, APPROVER);
}
