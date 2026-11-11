//! `sbc-gate enroll --key-file` without a token: re-provisioning a host from
//! a gate key the contract already holds. Nothing may be sent on-chain, and a
//! key the contract does not hold for the resource must be refused.

use sbc_core::ssh;
use sbc_gate::config::{Backend, GateConfig};
use sbc_gate::enroll::{enroll, EnrollOpts};
use sbc_gate::near::Signer;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const CONTRACT: &str = "sbc.testnet";

/// Answers `get_resource` / `get_ca` views; counts anything else.
fn mock_rpc(gate_key: String, ca_line: String, other: Arc<AtomicUsize>) -> String {
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
            let view = |v: Value| json!({ "result": v.to_string().into_bytes(), "logs": [], "block_height": 1, "block_hash": "x" });
            let result = match (req["method"].as_str(), req["params"]["method_name"].as_str()) {
                (Some("query"), Some("get_resource")) => view(json!({
                    "id": "prod-web-02",
                    "environment": "production",
                    "principal": "sbc-prod-web-02",
                    "services": ["checkout-api", "sshd"],
                    "gate_key": gate_key,
                    "status": "Active",
                })),
                (Some("query"), Some("get_ca")) => view(json!(ca_line)),
                _ => {
                    other.fetch_add(1, Ordering::SeqCst);
                    json!({ "error": "unexpected" })
                }
            };
            let resp = json!({ "jsonrpc": "2.0", "id": req["id"], "result": result }).to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", resp.len(), resp).unwrap();
        }
    });
    format!("http://127.0.0.1:{}", addr.port())
}

fn tmp(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("sbc-enroll-{}-{}-{}", tag, std::process::id(), nanos));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn ca_line() -> String {
    ssh::ed25519_pubkey_line(&[9u8; 32], "sbc-ca:production")
}

fn opts(rpc: String, key_file: Option<PathBuf>, dir: &Path) -> EnrollOpts {
    EnrollOpts {
        contract: CONTRACT.into(),
        resource: "prod-web-02".into(),
        token: None,
        key_file,
        rpc,
        relay: None,
        backend: Backend::Supervisor,
        config_dir: dir.join("etc-sbc"),
        ssh_dir: dir.join("ssh"),
        write_sshd: false,
        write_sudoers: false,
        // write everything except the KRL (which needs ssh-keygen)
        dry_run: false,
    }
}

fn has_ssh_keygen() -> bool {
    std::process::Command::new("ssh-keygen").arg("-?").output().is_ok()
}

#[test]
fn reprovisions_with_the_enrolled_key_without_any_transaction() {
    if !has_ssh_keygen() {
        eprintln!("skipping: ssh-keygen not on PATH");
        return;
    }
    let dir = tmp("ok");
    let gate = Signer::generate(CONTRACT);
    let key_path = dir.join("gate.key");
    std::fs::write(&key_path, serde_json::to_string(&gate.key_file()).unwrap()).unwrap();
    let other = Arc::new(AtomicUsize::new(0));
    let rpc = mock_rpc(gate.public_key_string(), ca_line(), other.clone());

    enroll(opts(rpc, Some(key_path), &dir)).expect("re-provisioning succeeds");

    assert_eq!(other.load(Ordering::SeqCst), 0, "no transaction or unexpected RPC was sent");
    let cfg = GateConfig::load(&dir.join("etc-sbc").join("gate.toml")).unwrap();
    assert_eq!(cfg.resource, "prod-web-02");
    assert_eq!(cfg.principal, "sbc-prod-web-02");
    let installed = Signer::from_key_file(&cfg.key_file).unwrap();
    assert_eq!(installed.public_key_string(), gate.public_key_string(), "the given key is the one installed");
    assert_eq!(std::fs::read_to_string(&cfg.ca_file).unwrap().trim(), ca_line());
    assert_eq!(std::fs::read_to_string(dir.join("ssh").join("sbc_principals").join("sbc-agent")).unwrap().trim(), "sbc-prod-web-02");
}

#[test]
fn refuses_a_key_the_contract_does_not_hold() {
    let dir = tmp("wrong");
    let enrolled = Signer::generate(CONTRACT);
    let impostor = Signer::generate(CONTRACT);
    let key_path = dir.join("gate.key");
    std::fs::write(&key_path, serde_json::to_string(&impostor.key_file()).unwrap()).unwrap();
    let rpc = mock_rpc(enrolled.public_key_string(), ca_line(), Arc::new(AtomicUsize::new(0)));

    let err = enroll(opts(rpc, Some(key_path), &dir)).unwrap_err();
    assert!(err.contains("not the enrolled gate key"), "{}", err);
    assert!(!dir.join("etc-sbc").join("gate.toml").exists(), "nothing written");
}

#[test]
fn refuses_a_key_for_another_contract() {
    let dir = tmp("acct");
    let other_contract = Signer::generate("someone-else.testnet");
    let key_path = dir.join("gate.key");
    std::fs::write(&key_path, serde_json::to_string(&other_contract.key_file()).unwrap()).unwrap();
    let rpc = mock_rpc(other_contract.public_key_string(), ca_line(), Arc::new(AtomicUsize::new(0)));

    let err = enroll(opts(rpc, Some(key_path), &dir)).unwrap_err();
    assert!(err.contains("not sbc.testnet"), "{}", err);
}

#[test]
fn needs_a_token_or_a_key() {
    let dir = tmp("none");
    let err = enroll(opts("http://127.0.0.1:9".into(), None, &dir)).unwrap_err();
    assert!(err.contains("missing --token"), "{}", err);
}
