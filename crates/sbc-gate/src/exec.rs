//! `sbc-gate` as sshd's forced command.
//!
//! ```text
//! certificate (SSH_USER_AUTH) ──verify──▶ capability serial
//! SSH_ORIGINAL_COMMAND ──parse──▶ typed action ──host ceiling──▶ consume() on NEAR
//!                                                     │ allowed
//!                                                     ▼
//!                                  execve(fixed argv)  ──▶ exit code back to agent
//! ```
//!
//! Fail closed at every step: no config, no certificate, unparseable command,
//! unreachable chain, or a `consume` that is anything but `allowed` → deny.

use crate::adapters;
use crate::auth;
use crate::config::{Backend, GateConfig};
use crate::near::{Rpc, Signer, TGAS};
use crate::relay::{self, GateReport};
use sbc_core::action::parse_command;
use sbc_core::redact::{program_of, redact_command};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const EXIT_NOT_AUTHORISABLE: i32 = 126;
pub const EXIT_DENIED: i32 = 77; // EX_NOPERM
pub const EXIT_UNAVAILABLE: i32 = 69; // EX_UNAVAILABLE
pub const EXIT_CONFIG: i32 = 78; // EX_CONFIG

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn session_id() -> String {
    let mut b = [0u8; 6];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    hex::encode(b)
}

/// Everything the forced command needs from its environment.
pub struct Invocation {
    pub original_command: String,
    pub auth_info: Option<String>,
}

impl Invocation {
    pub fn from_env() -> Invocation {
        let original_command = std::env::var("SSH_ORIGINAL_COMMAND").unwrap_or_default();
        let auth_info = std::env::var("SSH_USER_AUTH").ok().and_then(|p| std::fs::read_to_string(p).ok());
        Invocation { original_command, auth_info }
    }
}

pub struct Gate {
    pub cfg: GateConfig,
    pub ca_key: [u8; 32],
    pub signer: Signer,
    pub rpc: Rpc,
}

impl Gate {
    pub fn load(cfg: GateConfig) -> Result<Gate, String> {
        let ca_line = std::fs::read_to_string(&cfg.ca_file).map_err(|e| format!("cannot read CA {}: {}", cfg.ca_file, e))?;
        let ca_key = sbc_core::ssh::parse_ed25519_pubkey_line(ca_line.trim()).map_err(|e| format!("bad CA file: {}", e))?;
        let signer = Signer::from_key_file(&cfg.key_file)?;
        if signer.account_id != cfg.contract {
            return Err("gate key must be an access key on the contract account".into());
        }
        let rpc = Rpc::new(&cfg.rpc, cfg.rpc_timeout_secs);
        Ok(Gate { cfg, ca_key, signer, rpc })
    }

    fn report(&self, r: GateReport) {
        if let Some(relay) = &self.cfg.relay {
            relay::send(relay, &self.signer, &r);
        }
    }

    fn base_report(&self, inv: &Invocation, serial: Option<u64>, session: &str) -> GateReport {
        GateReport {
            resource_id: self.cfg.resource.clone(),
            request_id: serial,
            decision: "denied",
            code: String::new(),
            program: program_of(&inv.original_command),
            redacted_command: redact_command(&inv.original_command),
            command_sha256: hex::encode(Sha256::digest(inv.original_command.as_bytes())),
            action: None,
            session: session.to_string(),
            exit_code: None,
            duration_ms: None,
            at_ms: now_ms(),
        }
    }

    /// Record a locally-decided denial on-chain (best effort) and at the relay.
    fn deny_local(&self, inv: &Invocation, serial: Option<u64>, session: &str, code: &str, message: &str) -> i32 {
        eprintln!("sbc-gate: DENIED ({}) {}", code, message);
        let mut rep = self.base_report(inv, serial, session);
        rep.code = code.to_string();
        let args = json!({
            "request_id": serial,
            "code": code,
            "program": rep.program,
            "command_sha256": rep.command_sha256,
        });
        if let Err(e) = self.rpc.function_call(&self.signer, &self.cfg.contract, "report_denial", &args, 20 * TGAS) {
            eprintln!("sbc-gate: note: denial not yet recorded on-chain ({})", e);
        }
        self.report(rep);
        if code == "interactive_session" || code.starts_with("shell") || code == "no_adapter" {
            EXIT_NOT_AUTHORISABLE
        } else {
            EXIT_DENIED
        }
    }

    pub fn run(&self, inv: &Invocation) -> i32 {
        let session = session_id();
        let now_s = now_ms() / 1000;

        // 1. which capability is this?
        let presented = match inv.auth_info.as_deref() {
            None => return self.deny_local(inv, None, &session, "no_auth_info", "sshd did not expose authentication info (ExposeAuthInfo yes is required)"),
            Some(info) => match auth::verify_presented(info, &self.ca_key, &self.cfg.principal, now_s) {
                Ok(p) => p,
                Err(e) => return self.deny_local(inv, None, &session, e.code(), "presented certificate is not valid for this host"),
            },
        };
        let serial = presented.serial;

        // 2. what is being asked, as a typed action?
        let parsed = match parse_command(&inv.original_command) {
            Ok(p) => p,
            Err(rej) => return self.deny_local(inv, Some(serial), &session, rej.code(), &rej.message()),
        };
        let canonical = parsed.action.canonical();

        // 3. host-local ceiling
        if !self.cfg.services.contains(&parsed.action.target) {
            return self.deny_local(
                inv,
                Some(serial),
                &session,
                "not_exposed_locally",
                &format!("this host does not expose {} (host-local allowlist)", parsed.action.target),
            );
        }

        // 4. the contract decides, and records the use, before anything runs
        let args = json!({ "request_id": serial, "action": canonical, "session": session });
        let decision: Value = match self.rpc.function_call(&self.signer, &self.cfg.contract, "consume", &args, 30 * TGAS) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("sbc-gate: DENIED (policy_unreachable) could not confirm authorization with the policy contract — failing closed ({})", e);
                let mut rep = self.base_report(inv, Some(serial), &session);
                rep.code = "policy_unreachable".into();
                rep.action = Some(canonical);
                self.report(rep);
                return EXIT_UNAVAILABLE;
            }
        };
        let allowed = decision.get("allowed").and_then(Value::as_bool) == Some(true);
        let code = decision.get("code").and_then(Value::as_str).unwrap_or("malformed").to_string();
        let message = decision.get("message").and_then(Value::as_str).unwrap_or("").to_string();
        if !allowed {
            eprintln!("sbc-gate: DENIED ({}) capability #{}: {}", code, serial, message);
            let mut rep = self.base_report(inv, Some(serial), &session);
            rep.code = code;
            rep.action = Some(canonical);
            self.report(rep);
            return EXIT_DENIED;
        }
        let uses = decision.get("uses").and_then(Value::as_u64).unwrap_or(0);
        let max_uses = decision.get("max_uses").and_then(Value::as_u64).unwrap_or(0);
        eprintln!("sbc-gate: ✓ authorized {} — capability #{}, use {}/{}, session {}", canonical, serial, uses, max_uses, session);

        // 5. execute the fixed argv; never a shell
        let argv = adapters::argv(self.cfg.backend, &parsed);
        let started = Instant::now();
        let code = execute(self.cfg.backend, &argv, Duration::from_secs(self.cfg.exec_timeout_secs));
        let mut rep = self.base_report(inv, Some(serial), &session);
        rep.decision = "allowed";
        rep.code = "allowed".into();
        rep.action = Some(canonical);
        rep.exit_code = Some(code);
        rep.duration_ms = Some(started.elapsed().as_millis() as u64);
        self.report(rep);
        code
    }
}

/// Spawn without a shell, with a scrubbed environment and a hard timeout.
pub fn execute(backend: Backend, argv: &[String], timeout: Duration) -> i32 {
    if backend == Backend::DryRun {
        println!("{}", serde_json::to_string(argv).unwrap());
        return 0;
    }
    let mut child = match Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sbc-gate: could not start {}: {}", argv[0], e);
            return EXIT_UNAVAILABLE;
        }
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code().unwrap_or(1),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!("sbc-gate: action exceeded {}s and was terminated", timeout.as_secs());
                return 124;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => {
                eprintln!("sbc-gate: wait failed: {}", e);
                return 1;
            }
        }
    }
}
