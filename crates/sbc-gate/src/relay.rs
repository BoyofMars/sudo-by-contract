//! Best-effort, signed execution reports to the private relay. The on-chain
//! record (consume / report_denial) is authoritative; the relay holds the
//! redacted command text and exit codes that should not be public.
//!
//! Auth: `Authorization: SBC-Ed25519 pk=<ed25519:b58>,ts=<ms>,sig=<b64>` with
//! sig = Ed25519(utf8("sbc-relay/v1\n{METHOD}\n{PATH}\n{ts}\n{sha256hex(body)}")).

use crate::near::Signer;
use base64::Engine;
use ed25519_dalek::Signer as _;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct GateReport {
    pub resource_id: String,
    pub request_id: Option<u64>,
    pub decision: &'static str,
    pub code: String,
    pub program: String,
    pub redacted_command: String,
    pub command_sha256: String,
    pub action: Option<String>,
    pub session: String,
    pub exit_code: Option<i32>,
    pub duration_ms: Option<u64>,
    pub at_ms: u64,
}

pub fn auth_header(signer: &Signer, method: &str, path: &str, ts_ms: u64, body: &[u8]) -> String {
    let body_hash = hex::encode(Sha256::digest(body));
    let msg = format!("sbc-relay/v1\n{}\n{}\n{}\n{}", method, path, ts_ms, body_hash);
    let sig = signer.key.sign(msg.as_bytes()).to_bytes();
    format!(
        "SBC-Ed25519 pk={},ts={},sig={}",
        signer.public_key_string(),
        ts_ms,
        base64::engine::general_purpose::STANDARD.encode(sig)
    )
}

pub fn send(relay: &str, signer: &Signer, report: &GateReport) {
    let body = serde_json::to_vec(report).unwrap();
    let path = "/v1/gate-reports";
    let header = auth_header(signer, "POST", path, report.at_ms, &body);
    let url = format!("{}{}", relay.trim_end_matches('/'), path);
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(3)).build();
    if let Err(e) = agent
        .post(&url)
        .set("authorization", &header)
        .set("content-type", "application/json")
        .send_bytes(&body)
    {
        eprintln!("sbc-gate: note: relay report not delivered ({}); on-chain record is authoritative", short(&e.to_string()));
    }
}

fn short(s: &str) -> String {
    s.chars().take(120).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn header_signs_canonical_message() {
        let s = Signer::generate("sbc.testnet");
        let h = auth_header(&s, "POST", "/v1/gate-reports", 1_800_000_000_000, b"{}");
        let sig_b64 = h.split("sig=").nth(1).unwrap();
        let sig = base64::engine::general_purpose::STANDARD.decode(sig_b64).unwrap();
        let msg = format!("sbc-relay/v1\nPOST\n/v1/gate-reports\n1800000000000\n{}", hex::encode(Sha256::digest(b"{}")));
        s.key
            .verifying_key()
            .verify(msg.as_bytes(), &ed25519_dalek::Signature::from_bytes(&sig.try_into().unwrap()))
            .unwrap();
        assert!(h.starts_with("SBC-Ed25519 pk=ed25519:"));
    }
}
