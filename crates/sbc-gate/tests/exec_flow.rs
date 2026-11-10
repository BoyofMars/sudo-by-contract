//! End-to-end test of the forced-command path against a mock NEAR RPC.
//!
//! The mock decodes every transaction the gate sends, verifies its Ed25519
//! signature against the enrolled gate key, and answers `consume` the way
//! the contract would for a capability granting `service.restart:checkout-api`.

use base64::Engine;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier, VerifyingKey};
use sbc_core::ssh;
use sbc_gate::config::{Backend, GateConfig};
use sbc_gate::exec::{Gate, Invocation, EXIT_DENIED, EXIT_NOT_AUTHORISABLE, EXIT_UNAVAILABLE};
use sbc_gate::near::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const CONTRACT: &str = "sbc.testnet";

#[derive(Default)]
struct Calls {
    consume: Vec<Value>,
    report_denial: Vec<Value>,
    uses: u32,
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        s
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take(4).try_into().unwrap())
    }
    fn bytes(&mut self) -> &'a [u8] {
        let n = self.u32() as usize;
        self.take(n)
    }
}

/// Decode a signed FunctionCall transaction and verify its signature.
fn decode_signed(signed: &[u8], expect_pk: &[u8; 32]) -> (String, Value) {
    let mut r = Reader { b: signed, p: 0 };
    let signer = String::from_utf8(r.bytes().to_vec()).unwrap();
    assert_eq!(signer, CONTRACT, "role keys sign as the contract account");
    assert_eq!(r.take(1), &[0]);
    let pk: [u8; 32] = r.take(32).try_into().unwrap();
    assert_eq!(&pk, expect_pk, "signed by the enrolled gate key");
    r.take(8); // nonce
    let receiver = String::from_utf8(r.bytes().to_vec()).unwrap();
    assert_eq!(receiver, CONTRACT);
    r.take(32); // block hash
    assert_eq!(r.u32(), 1);
    assert_eq!(r.take(1), &[2], "FunctionCall");
    let method = String::from_utf8(r.bytes().to_vec()).unwrap();
    let args: Value = serde_json::from_slice(r.bytes()).unwrap();
    r.take(8 + 16); // gas, deposit
    let tx_len = r.p;
    assert_eq!(r.take(1), &[0]);
    let sig = Signature::from_bytes(r.take(64).try_into().unwrap());
    let hash = Sha256::digest(&signed[..tx_len]);
    VerifyingKey::from_bytes(&pk).unwrap().verify(&hash, &sig).expect("valid tx signature");
    (method, args)
}

fn mock_rpc(gate_pk: [u8; 32], calls: Arc<Mutex<Calls>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body).unwrap();
            let req: Value = serde_json::from_slice(&body).unwrap();
            let result = match req["method"].as_str().unwrap() {
                "query" => json!({ "nonce": 7, "block_hash": bs58::encode([3u8; 32]).into_string(), "permission": "FullAccess" }),
                "send_tx" => {
                    let signed = base64::engine::general_purpose::STANDARD.decode(req["params"]["signed_tx_base64"].as_str().unwrap()).unwrap();
                    let (method, args) = decode_signed(&signed, &gate_pk);
                    let mut c = calls.lock().unwrap();
                    let ret = match method.as_str() {
                        "consume" => {
                            c.consume.push(args.clone());
                            let ok = args["action"] == "service.restart:checkout-api" && args["request_id"] == 12 && c.uses < 1;
                            if ok {
                                c.uses += 1;
                                json!({ "allowed": true, "code": "allowed", "message": "permitted", "uses": 1, "max_uses": 1, "valid_before": 0, "action": "service.restart:checkout-api" })
                            } else if args["action"] != "service.restart:checkout-api" {
                                json!({ "allowed": false, "code": "out_of_scope", "message": "capability permits only service.restart:checkout-api", "uses": c.uses, "max_uses": 1, "valid_before": 0, "action": "service.restart:checkout-api" })
                            } else {
                                json!({ "allowed": false, "code": "exhausted", "message": "all permitted uses are consumed", "uses": 1, "max_uses": 1, "valid_before": 0, "action": "service.restart:checkout-api" })
                            }
                        }
                        "report_denial" => {
                            c.report_denial.push(args.clone());
                            Value::Null
                        }
                        m => panic!("unexpected method {m}"),
                    };
                    let sv = if ret.is_null() { String::new() } else { base64::engine::general_purpose::STANDARD.encode(ret.to_string()) };
                    json!({ "status": { "SuccessValue": sv }, "transaction": { "hash": "x" } })
                }
                m => panic!("unexpected rpc {m}"),
            };
            let resp = json!({ "jsonrpc": "2.0", "id": req["id"], "result": result }).to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", resp.len(), resp).unwrap();
        }
    });
    format!("http://127.0.0.1:{}", addr.port())
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// serial is the certificate serial; the capability id is serial - 1.
fn cert_auth_info(ca: &SigningKey, principal: &str, serial: u64, after: u64, before: u64) -> String {
    let spec = ssh::UserCertSpec {
        nonce: [4; 32],
        subject_key: SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        serial,
        key_id: format!("sbc cap={} agent=deploy-agent res=prod-web-02", serial),
        principals: vec![principal.into()],
        valid_after: after,
        valid_before: before,
        force_command: Some("/usr/local/sbin/sbc-gate".into()),
        source_address: None,
        extensions: vec![],
        ca_key: ca.verifying_key().to_bytes(),
    };
    let tbs = ssh::build_tbs(&spec).unwrap();
    let blob = ssh::attach_signature(&tbs, &ca.sign(&tbs).to_bytes());
    format!("publickey {}\n", ssh::cert_line(&blob, ""))
}

fn setup(rpc: Option<String>) -> (Gate, SigningKey, Arc<Mutex<Calls>>) {
    let dir = std::env::temp_dir().join(format!("sbc-gate-test-{}-{}", std::process::id(), rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = SigningKey::from_bytes(&[42; 32]);
    let gate_signer = Signer::generate(CONTRACT);
    let calls = Arc::new(Mutex::new(Calls::default()));
    let rpc = rpc.unwrap_or_else(|| mock_rpc(gate_signer.key.verifying_key().to_bytes(), calls.clone()));
    let key_file = dir.join("gate.key");
    std::fs::write(&key_file, serde_json::to_string(&gate_signer.key_file()).unwrap()).unwrap();
    let ca_file = dir.join("ca.pub");
    std::fs::write(&ca_file, ssh::ed25519_pubkey_line(&ca.verifying_key().to_bytes(), "ca")).unwrap();
    let cfg = GateConfig {
        contract: CONTRACT.into(),
        rpc,
        relay: None,
        resource: "prod-web-02".into(),
        principal: "sbc-prod-web-02".into(),
        environment: "production".into(),
        key_file: key_file.display().to_string(),
        ca_file: ca_file.display().to_string(),
        krl_file: dir.join("krl").display().to_string(),
        backend: Backend::DryRun,
        services: vec!["checkout-api".into(), "sshd".into()],
        exec_timeout_secs: 5,
        rpc_timeout_secs: 3,
    };
    cfg.validate().unwrap();
    (Gate::load(cfg).unwrap(), ca, calls)
}

fn rand_suffix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as u64
}

fn inv(cmd: &str, info: &str) -> Invocation {
    Invocation { original_command: cmd.into(), auth_info: Some(info.into()) }
}

#[test]
fn hero_sequence_at_the_gate() {
    let (gate, ca, calls) = setup(None);
    let info = cert_auth_info(&ca, "sbc-prod-web-02", 13, now() - 60, now() + 600);

    // âœ“ the approved action runs (dry-run backend prints the fixed argv)
    assert_eq!(gate.run(&inv("sudo systemctl restart checkout-api", &info)), 0);
    // âœ• never parses into an action: reported on-chain with only program + hash
    assert_eq!(gate.run(&inv("sudo cat /etc/shadow", &info)), EXIT_NOT_AUTHORISABLE);
    // âœ• parses, but the contract says out of scope
    assert_eq!(gate.run(&inv("sudo systemctl restart sshd", &info)), EXIT_DENIED);
    // âœ• single use already consumed
    assert_eq!(gate.run(&inv("sudo systemctl restart checkout-api", &info)), EXIT_DENIED);
    // âœ• injection attempt never reaches the chain or a shell
    assert_eq!(gate.run(&inv("sudo systemctl restart checkout-api; id", &info)), EXIT_NOT_AUTHORISABLE);

    let c = calls.lock().unwrap();
    assert_eq!(c.consume.len(), 3, "only parsed, locally-exposed actions reach consume()");
    assert_eq!(c.report_denial.len(), 2);
    assert_eq!(c.report_denial[0]["program"], "cat");
    assert_eq!(c.report_denial[0]["code"], "no_adapter");
    assert_eq!(c.report_denial[0]["request_id"], 12);
    assert_eq!(
        c.report_denial[0]["command_sha256"],
        hex::encode(Sha256::digest(b"sudo cat /etc/shadow")),
        "the full command is only committed as a hash"
    );
    assert_eq!(c.report_denial[1]["code"], "shell_metacharacter");
}

#[test]
fn certificates_are_checked_independently_of_sshd() {
    let (gate, ca, calls) = setup(None);
    let expired = cert_auth_info(&ca, "sbc-prod-web-02", 13, now() - 700, now() - 100);
    assert_eq!(gate.run(&inv("sudo systemctl restart checkout-api", &expired)), EXIT_DENIED);
    let other_host = cert_auth_info(&ca, "sbc-prod-web-03", 13, now() - 60, now() + 600);
    assert_eq!(gate.run(&inv("sudo systemctl restart checkout-api", &other_host)), EXIT_DENIED);
    let rogue = cert_auth_info(&SigningKey::from_bytes(&[1; 32]), "sbc-prod-web-02", 13, now() - 60, now() + 600);
    assert_eq!(gate.run(&inv("sudo systemctl restart checkout-api", &rogue)), EXIT_DENIED);
    assert_eq!(gate.run(&Invocation { original_command: "id".into(), auth_info: None }), EXIT_DENIED);
    let c = calls.lock().unwrap();
    assert!(c.consume.is_empty(), "invalid certificates never reach consume()");
    let codes: Vec<_> = c.report_denial.iter().map(|r| r["code"].as_str().unwrap().to_string()).collect();
    assert_eq!(codes, vec!["expired", "wrong_resource", "untrusted_ca", "no_auth_info"]);
}

#[test]
fn host_local_ceiling_beats_the_contract() {
    let (gate, ca, calls) = setup(None);
    let info = cert_auth_info(&ca, "sbc-prod-web-02", 13, now() - 60, now() + 600);
    assert_eq!(gate.run(&inv("sudo systemctl restart payments-api", &info)), EXIT_DENIED);
    let c = calls.lock().unwrap();
    assert!(c.consume.is_empty());
    assert_eq!(c.report_denial[0]["code"], "not_exposed_locally");
}

#[test]
fn unreachable_chain_fails_closed() {
    // nothing listens on this port
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        format!("http://127.0.0.1:{}", p)
    };
    let (gate, ca, _calls) = setup(Some(dead));
    let info = cert_auth_info(&ca, "sbc-prod-web-02", 13, now() - 60, now() + 600);
    assert_eq!(gate.run(&inv("sudo systemctl restart checkout-api", &info)), EXIT_UNAVAILABLE);
}

#[test]
fn serial_zero_is_never_honoured() {
    let (gate, ca, calls) = setup(None);
    let info = cert_auth_info(&ca, "sbc-prod-web-02", 0, now() - 60, now() + 600);
    assert_eq!(gate.run(&inv("sudo systemctl restart checkout-api", &info)), EXIT_DENIED);
    let c = calls.lock().unwrap();
    assert!(c.consume.is_empty());
    assert_eq!(c.report_denial[0]["code"], "malformed_certificate");
}
