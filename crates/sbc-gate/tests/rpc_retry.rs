//! Transaction resends against a mock NEAR RPC that rejects the first send.
//!
//! On 2026-11-12 a scheduled live run failed because a load-balanced testnet RPC
//! answered a heartbeat with `InvalidTxError: Expired` (the block hash came from
//! a node ahead of the one that received the transaction). Such a transaction is
//! never executed, so the gate rebuilds it with a fresh block hash and resends.
//! Rejections that are not known to be safe are never resent.

use sbc_gate::near::{Rpc, Signer, TGAS};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const CONTRACT: &str = "sbc.testnet";

/// Serves view_access_key and send_tx; the first send_tx gets `first_error`.
fn mock_rpc(first_error: Value, queries: Arc<AtomicUsize>, sends: Arc<AtomicUsize>) -> String {
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
            let resp = match req["method"].as_str().unwrap() {
                "query" => {
                    let n = queries.fetch_add(1, Ordering::SeqCst) as u8;
                    // a different block hash each time: the resend must not reuse the rejected one
                    json!({ "jsonrpc": "2.0", "id": req["id"], "result": { "nonce": 7, "block_hash": bs58::encode([n + 1; 32]).into_string(), "permission": "FullAccess" } })
                }
                "send_tx" => {
                    if sends.fetch_add(1, Ordering::SeqCst) == 0 {
                        json!({ "jsonrpc": "2.0", "id": req["id"], "error": first_error.clone() })
                    } else {
                        json!({ "jsonrpc": "2.0", "id": req["id"], "result": { "status": { "SuccessValue": "" }, "transaction": { "hash": "x" } } })
                    }
                }
                m => panic!("unexpected rpc {m}"),
            }
            .to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", resp.len(), resp).unwrap();
        }
    });
    format!("http://127.0.0.1:{}", addr.port())
}

fn rejection(tx_error: Value) -> Value {
    json!({ "name": "HANDLER_ERROR", "code": -32000, "message": "Server error", "cause": { "name": "INVALID_TRANSACTION", "info": {} }, "data": { "TxExecutionError": { "InvalidTxError": tx_error } } })
}

#[test]
fn expired_transaction_is_rebuilt_and_resent() {
    let (queries, sends) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let rpc = Rpc::new(&mock_rpc(rejection(json!("Expired")), queries.clone(), sends.clone()), 10);
    let signer = Signer::generate(CONTRACT);
    let out = rpc.function_call(&signer, CONTRACT, "heartbeat", &json!({ "gate_version": "test" }), 30 * TGAS);
    assert!(out.is_ok(), "{:?}", out.err());
    assert_eq!(sends.load(Ordering::SeqCst), 2, "one rejected send, one resend");
    assert_eq!(queries.load(Ordering::SeqCst), 2, "a fresh block hash for the resend");
}

#[test]
fn other_rejections_are_not_resent() {
    let (queries, sends) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let rpc = Rpc::new(&mock_rpc(rejection(json!("InvalidSignature")), queries, sends.clone()), 10);
    let signer = Signer::generate(CONTRACT);
    let out = rpc.function_call(&signer, CONTRACT, "consume", &json!({ "request_id": 1 }), 30 * TGAS);
    assert!(out.is_err());
    assert_eq!(sends.load(Ordering::SeqCst), 1, "never resent");
}
