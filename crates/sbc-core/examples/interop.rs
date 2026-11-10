//! OpenSSH interoperability harness (test tooling, not shipped).
//!
//! `cargo run -p sbc-core --example interop -- mint <user.pub> <out-cert.pub> <ttl-secs> [serial]`
//!     Builds a certificate with `sbc_core::ssh::build_tbs` (the exact code the
//!     policy contract runs), signs it with a throwaway CA generated for this
//!     run, and writes `<out-cert.pub>` plus `<out-cert.pub>.ca.pub`. Feed the
//!     result to `ssh-keygen -L -f` to have OpenSSH parse and verify it.
//!
//! `cargo run -p sbc-core --example interop -- inspect <cert.pub>`
//!     Parses a certificate produced by anything (e.g. `ssh-keygen -s`) with
//!     our parser and prints the fields, to cross-check the encoding.
use ed25519_dalek::{Signer, SigningKey, Verifier};
use sbc_core::ssh;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("mint") => mint(&args[2], &args[3], args[4].parse().unwrap(), args.get(5).map(|s| s.parse().unwrap()).unwrap_or(1042)),
        Some("inspect") => inspect(&args[2]),
        _ => eprintln!("usage: interop mint <user.pub> <out> <ttl> [serial] | interop inspect <cert.pub>"),
    }
}

fn mint(user_pub: &str, out: &str, ttl: u64, serial: u64) {
    let line = std::fs::read_to_string(user_pub).unwrap();
    let subject = ssh::parse_ed25519_pubkey_line(line.trim()).unwrap();
    let mut seed = [0u8; 32];
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    seed[..8].copy_from_slice(&now.to_le_bytes());
    seed[8] = 0x5b; // throwaway, per-run test CA
    let ca = SigningKey::from_bytes(&seed);
    let spec = ssh::UserCertSpec {
        nonce: [0x11; 32],
        subject_key: subject,
        serial,
        key_id: format!("sbc cap={} agent=deploy-agent res=prod-web-02", serial),
        principals: vec!["sbc-prod-web-02".into()],
        valid_after: now - 60,
        valid_before: now + ttl,
        force_command: Some("/usr/local/sbin/sbc-gate".into()),
        source_address: None,
        extensions: vec![],
        ca_key: ca.verifying_key().to_bytes(),
    };
    let tbs = ssh::build_tbs(&spec).unwrap();
    let sig = ca.sign(&tbs).to_bytes();
    let blob = ssh::attach_signature(&tbs, &sig);
    std::fs::write(out, ssh::cert_line(&blob, "sbc-interop") + "\n").unwrap();
    std::fs::write(format!("{out}.ca.pub"), ssh::ed25519_pubkey_line(&ca.verifying_key().to_bytes(), "sbc-test-ca") + "\n").unwrap();
    println!("tbs_len={} cert_len={}", tbs.len(), blob.len());
}

fn inspect(path: &str) {
    let line = std::fs::read_to_string(path).unwrap();
    let (blob, p) = ssh::parse_cert_line(line.trim()).unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&p.ca_key).unwrap();
    let ok = vk
        .verify(&blob[..p.signed_len], &ed25519_dalek::Signature::from_bytes(&p.signature))
        .is_ok();
    println!("serial={} type={} key_id={:?}", p.serial, p.cert_type, p.key_id);
    println!("principals={:?}", p.principals);
    println!("valid_after={} valid_before={}", p.valid_after, p.valid_before);
    println!("critical_options={:?}", p.critical_options);
    println!("extensions={:?}", p.extensions);
    println!("ca_key={}", ssh::ed25519_pubkey_line(&p.ca_key, ""));
    println!("signature_valid={}", ok);
    // re-encode from parsed fields and compare byte-for-byte with OpenSSH's TBS
    let spec = ssh::UserCertSpec {
        nonce: p.nonce.clone().try_into().unwrap_or([0; 32]),
        subject_key: p.subject_key,
        serial: p.serial,
        key_id: p.key_id.clone(),
        principals: p.principals.clone(),
        valid_after: p.valid_after,
        valid_before: p.valid_before,
        force_command: p.critical_option("force-command").map(String::from),
        source_address: p.critical_option("source-address").map(String::from),
        extensions: p.extensions.clone(),
        ca_key: p.ca_key,
    };
    let rebuilt = ssh::build_tbs(&spec).unwrap();
    println!("reencode_matches_openssh={}", rebuilt == blob[..p.signed_len]);
}
