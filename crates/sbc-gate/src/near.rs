//! Minimal NEAR JSON-RPC client with hand-rolled borsh transaction encoding
//! (same layout as packages/sbc-client/src/near.ts, verified there against
//! @near-js/transactions). The gate signs exactly one kind of transaction: a
//! FunctionCall on the policy contract with its Gate-role access key.

use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub const TGAS: u64 = 1_000_000_000_000;

#[derive(Debug)]
pub enum RpcError {
    Transport(String),
    Rpc(String),
    Execution(String),
    Decode(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Transport(s) => write!(f, "transport: {}", s),
            RpcError::Rpc(s) => write!(f, "rpc: {}", s),
            RpcError::Execution(s) => write!(f, "contract: {}", s),
            RpcError::Decode(s) => write!(f, "decode: {}", s),
        }
    }
}

/// NEAR CLI key file: `{"account_id", "public_key", "private_key": "ed25519:<base58 seed||pub>"}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub account_id: String,
    pub public_key: String,
    pub private_key: String,
}

pub struct Signer {
    pub account_id: String,
    pub key: SigningKey,
}

impl Signer {
    pub fn from_secret(account_id: &str, secret: &str) -> Result<Signer, String> {
        let data = secret.strip_prefix("ed25519:").ok_or("expected ed25519:<base58> secret")?;
        let raw = bs58::decode(data).into_vec().map_err(|_| "invalid base58 secret")?;
        if raw.len() != 64 && raw.len() != 32 {
            return Err("ed25519 secrets are 64 bytes".into());
        }
        let seed: [u8; 32] = raw[..32].try_into().unwrap();
        let key = SigningKey::from_bytes(&seed);
        if raw.len() == 64 && raw[32..] != key.verifying_key().to_bytes() {
            return Err("secret key does not match its public half".into());
        }
        Ok(Signer { account_id: account_id.to_string(), key })
    }

    pub fn from_key_file(path: &str) -> Result<Signer, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read key {}: {}", path, e))?;
        Self::from_key_json(&text).map_err(|e| format!("invalid key file {}: {}", path, e))
    }

    /// Parse a NEAR CLI key file. Tolerates a UTF-8 byte-order mark and
    /// surrounding whitespace, which Windows editors and pipes add.
    pub fn from_key_json(text: &str) -> Result<Signer, String> {
        let kf: KeyFile = serde_json::from_str(text.trim_start_matches('\u{feff}').trim()).map_err(|e| e.to_string())?;
        Signer::from_secret(&kf.account_id, &kf.private_key)
    }

    pub fn generate(account_id: &str) -> Signer {
        Signer { account_id: account_id.to_string(), key: SigningKey::generate(&mut rand_core::OsRng) }
    }

    pub fn public_key_string(&self) -> String {
        format!("ed25519:{}", bs58::encode(self.key.verifying_key().to_bytes()).into_string())
    }

    pub fn key_file(&self) -> KeyFile {
        let mut raw = self.key.to_bytes().to_vec();
        raw.extend_from_slice(&self.key.verifying_key().to_bytes());
        KeyFile {
            account_id: self.account_id.clone(),
            public_key: self.public_key_string(),
            private_key: format!("ed25519:{}", bs58::encode(raw).into_string()),
        }
    }
}

// ---------------------------------------------------------------- borsh

fn put_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put_string(b: &mut Vec<u8>, s: &[u8]) {
    put_u32(b, s.len() as u32);
    b.extend_from_slice(s);
}

pub fn encode_function_call_tx(
    signer_id: &str,
    public_key: &[u8; 32],
    nonce: u64,
    receiver_id: &str,
    block_hash: &[u8; 32],
    method: &str,
    args: &[u8],
    gas: u64,
    deposit: u128,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(256 + args.len());
    put_string(&mut b, signer_id.as_bytes());
    b.push(0); // KeyType::ED25519
    b.extend_from_slice(public_key);
    b.extend_from_slice(&nonce.to_le_bytes());
    put_string(&mut b, receiver_id.as_bytes());
    b.extend_from_slice(block_hash);
    put_u32(&mut b, 1); // one action
    b.push(2); // Action::FunctionCall
    put_string(&mut b, method.as_bytes());
    put_string(&mut b, args);
    b.extend_from_slice(&gas.to_le_bytes());
    b.extend_from_slice(&deposit.to_le_bytes());
    b
}

// ------------------------------------------------------------------ rpc

pub struct Rpc {
    pub url: String,
    agent: ureq::Agent,
}

impl Rpc {
    pub fn new(url: &str, timeout_secs: u64) -> Rpc {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent(concat!("sbc-gate/", env!("CARGO_PKG_VERSION")))
            .build();
        Rpc { url: url.to_string(), agent }
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = json!({ "jsonrpc": "2.0", "id": "sbc-gate", "method": method, "params": params });
        let resp = self
            .agent
            .post(&self.url)
            .send_json(body)
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        let v: Value = resp.into_json().map_err(|e| RpcError::Decode(e.to_string()))?;
        if let Some(err) = v.get("error") {
            let name = err.pointer("/cause/name").and_then(Value::as_str).unwrap_or("RPC_ERROR");
            return Err(RpcError::Rpc(format!("{}: {}", name, truncate(&err.to_string(), 300))));
        }
        v.get("result").cloned().ok_or_else(|| RpcError::Decode("missing result".into()))
    }

    pub fn view(&self, contract: &str, method: &str, args: &Value) -> Result<Value, RpcError> {
        let r = self.call(
            "query",
            json!({
                "request_type": "call_function",
                "finality": "optimistic",
                "account_id": contract,
                "method_name": method,
                "args_base64": base64::engine::general_purpose::STANDARD.encode(args.to_string()),
            }),
        )?;
        if let Some(e) = r.get("error") {
            return Err(RpcError::Execution(e.to_string()));
        }
        let bytes: Vec<u8> = r
            .get("result")
            .and_then(Value::as_array)
            .ok_or_else(|| RpcError::Decode("view result missing".into()))?
            .iter()
            .map(|x| x.as_u64().unwrap_or(0) as u8)
            .collect();
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).map_err(|e| RpcError::Decode(e.to_string()))
    }

    fn access_key(&self, account: &str, public_key: &str) -> Result<(u64, [u8; 32]), RpcError> {
        let r = self.call(
            "query",
            json!({ "request_type": "view_access_key", "finality": "optimistic", "account_id": account, "public_key": public_key }),
        )?;
        let nonce = r.get("nonce").and_then(Value::as_u64).ok_or_else(|| RpcError::Decode("nonce".into()))?;
        let bh = r.get("block_hash").and_then(Value::as_str).ok_or_else(|| RpcError::Decode("block_hash".into()))?;
        let bh: [u8; 32] = bs58::decode(bh)
            .into_vec()
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| RpcError::Decode("block_hash".into()))?;
        Ok((nonce, bh))
    }

    /// Sign and send a FunctionCall; returns the method's JSON return value.
    pub fn function_call(&self, signer: &Signer, receiver: &str, method: &str, args: &Value, gas: u64) -> Result<Value, RpcError> {
        let args_bytes = args.to_string().into_bytes();
        let pk_str = signer.public_key_string();
        let pk = signer.key.verifying_key().to_bytes();
        let mut last_err = None;
        for attempt in 0..4u64 {
            let (nonce, block_hash) = self.access_key(&signer.account_id, &pk_str)?;
            let tx = encode_function_call_tx(&signer.account_id, &pk, nonce + 1 + attempt, receiver, &block_hash, method, &args_bytes, gas, 0);
            let hash = Sha256::digest(&tx);
            let sig = signer.key.sign(&hash).to_bytes();
            let mut signed = tx;
            signed.push(0);
            signed.extend_from_slice(&sig);
            let res = self.call(
                "send_tx",
                json!({
                    "signed_tx_base64": base64::engine::general_purpose::STANDARD.encode(&signed),
                    "wait_until": "EXECUTED_OPTIMISTIC",
                }),
            );
            match res {
                Ok(out) => return interpret_outcome(&out),
                Err(RpcError::Rpc(m)) => match retryable_tx_rejection(&m) {
                    Some(wait_ms) => {
                        last_err = Some(RpcError::Rpc(m));
                        std::thread::sleep(Duration::from_millis(wait_ms * (attempt + 1)));
                        continue;
                    }
                    None => return Err(RpcError::Rpc(m)),
                },
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| RpcError::Rpc("exhausted transaction retries".into())))
    }
}

/// RPC rejections that mean the transaction was never executed, so resending a
/// freshly built one is safe; returns the back-off step in milliseconds.
/// - nonce clash: another command on this host used the key at the same moment;
/// - `InvalidTxError: Expired`: the block hash came from an RPC node ahead of the
///   one that received the transaction (load-balanced testnet RPC), which treats
///   an unknown hash as expired. Waiting lets the nodes converge.
pub fn retryable_tx_rejection(message: &str) -> Option<u64> {
    if message.to_ascii_lowercase().contains("nonce") {
        Some(150)
    } else if message.contains("InvalidTxError") && message.contains("Expired") {
        Some(500)
    } else {
        None
    }
}

fn interpret_outcome(out: &Value) -> Result<Value, RpcError> {
    let status = out.get("status").ok_or_else(|| RpcError::Decode("missing status".into()))?;
    if let Some(f) = status.get("Failure") {
        let msg = f
            .pointer("/ActionError/kind/FunctionCallError/ExecutionError")
            .and_then(Value::as_str)
            .map(|s| s.trim_start_matches("Smart contract panicked: ").to_string())
            .unwrap_or_else(|| truncate(&f.to_string(), 300));
        return Err(RpcError::Execution(msg));
    }
    match status.get("SuccessValue").and_then(Value::as_str) {
        Some("") | None => Ok(Value::Null),
        Some(b64) => {
            let bytes = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|e| RpcError::Decode(e.to_string()))?;
            serde_json::from_slice(&bytes).map_err(|e| RpcError::Decode(e.to_string()))
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_layout_is_stable() {
        // Golden vector produced by packages/sbc-client (itself verified
        // byte-for-byte against @near-js/transactions).
        let tx = encode_function_call_tx(
            "sbc.testnet",
            &[7u8; 32],
            42,
            "sbc.testnet",
            &[9u8; 32],
            "consume",
            br#"{"a":1}"#,
            30 * TGAS,
            0,
        );
        assert_eq!(hex::encode(&tx), include_str!("../testdata/tx_golden.hex").trim());
    }

    #[test]
    fn key_file_roundtrip() {
        let s = Signer::generate("sbc.testnet");
        let kf = s.key_file();
        let s2 = Signer::from_secret(&kf.account_id, &kf.private_key).unwrap();
        assert_eq!(s.public_key_string(), s2.public_key_string());
        assert!(Signer::from_secret("x", "ed25519:3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").is_err());
    }

    #[test]
    fn key_file_tolerates_bom_and_crlf() {
        let s = Signer::generate("sbc.testnet");
        let json = serde_json::to_string_pretty(&s.key_file()).unwrap();
        let windows = format!("\u{feff}{}\r\n", json.replace('\n', "\r\n"));
        assert_eq!(Signer::from_key_json(&windows).unwrap().public_key_string(), s.public_key_string());
        assert!(Signer::from_key_json("\u{feff}").is_err());
    }

    #[test]
    fn only_never_executed_rejections_are_retried() {
        // the rejection that failed the 2026-11-12 scheduled run
        let expired = r#"INVALID_TRANSACTION: {"cause":{"info":{},"name":"INVALID_TRANSACTION"},"code":-32000,"data":{"TxExecutionError":{"InvalidTxError":"Expired"}},"message":"Server error","name":"HANDLER_ERROR"}"#;
        assert_eq!(retryable_tx_rejection(expired), Some(500));
        assert_eq!(retryable_tx_rejection(r#"INVALID_TRANSACTION: {"InvalidTxError":{"InvalidNonce":{"tx_nonce":8,"ak_nonce":8}}}"#), Some(150));
        // anything else is final: a bad signature, a missing key, a timeout
        assert_eq!(retryable_tx_rejection(r#"INVALID_TRANSACTION: {"InvalidTxError":"InvalidSignature"}"#), None);
        assert_eq!(retryable_tx_rejection("UNKNOWN_ACCESS_KEY: access key does not exist"), None);
        assert_eq!(retryable_tx_rejection("TIMEOUT_ERROR: transaction not included"), None);
    }

    #[test]
    fn outcome_failure_is_surfaced() {
        let v = json!({ "status": { "Failure": { "ActionError": { "kind": { "FunctionCallError": { "ExecutionError": "Smart contract panicked: this access key is not bound to any identity" } } } } } });
        match interpret_outcome(&v) {
            Err(RpcError::Execution(m)) => assert_eq!(m, "this access key is not bound to any identity"),
            other => panic!("{:?}", other.map(|_| ())),
        }
        let ok = json!({ "status": { "SuccessValue": base64::engine::general_purpose::STANDARD.encode(r#"{"allowed":true}"#) } });
        assert_eq!(interpret_outcome(&ok).unwrap()["allowed"], json!(true));
    }
}
