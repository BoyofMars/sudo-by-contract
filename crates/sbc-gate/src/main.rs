//! sbc-gate â€” the Sudo by Contract enforcement point on an enrolled host.
//!
//! Invoked with no arguments by sshd (`ForceCommand`), it executes exactly
//! one approved typed action or refuses. Other subcommands are for operators.

use sbc_gate::config::{Backend, GateConfig, DEFAULT_CONFIG};
use sbc_gate::{adapters, enroll, exec};
use std::path::PathBuf;

const HELP: &str = "sbc-gate â€” Sudo by Contract host gate

USAGE
  sbc-gate                      Forced command for sshd (reads SSH_ORIGINAL_COMMAND, SSH_USER_AUTH)
  sbc-gate enroll --contract <id> --resource <id> --token <ed25519:...>
                  [--rpc URL] [--relay URL] [--backend systemd|supervisor]
                  [--config-dir /etc/sbc] [--ssh-dir /etc/ssh]
                  [--write-sshd] [--write-sudoers] [--dry-run]
  sbc-gate sync                 Heartbeat, refresh the revocation list (KRL), check CA pin
  sbc-gate check <command...>   Show how a command line maps to a typed action (no execution)
  sbc-gate sudoers              Print the exact sudoers rules for this host's services
  sbc-gate sshd-config          Print the sshd drop-in for this host's configuration
  sbc-gate version

ENVIRONMENT
  SBC_GATE_CONFIG   config path (default /etc/sbc/gate.toml)

EXIT CODES
  0..   exit code of the executed action      77  denied by policy
  126   not an authorisable action             69  policy contract unreachable (fail closed)
  78    gate misconfigured (fail closed)";

fn config_path() -> PathBuf {
    std::env::var("SBC_GATE_CONFIG").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(DEFAULT_CONFIG))
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        None | Some("exec") => run_exec(),
        Some("enroll") => run_enroll(&args[1..]),
        Some("sync") => match GateConfig::load(&config_path()).and_then(|c| enroll::sync(&c)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("sbc-gate sync: {}", e);
                1
            }
        },
        Some("check") => {
            let line = args[1..].join(" ");
            match sbc_core::parse_command(&line) {
                Ok(p) => {
                    println!("action   {}", p.action.canonical());
                    println!("meaning  {}", p.action.describe());
                    for b in [Backend::Systemd, Backend::Supervisor] {
                        println!("argv     {:?} ({:?})", adapters::argv(b, &p), b);
                    }
                    0
                }
                Err(r) => {
                    println!("rejected {} â€” {}", r.code(), r.message());
                    exec::EXIT_NOT_AUTHORISABLE
                }
            }
        }
        Some("sshd-config") => match GateConfig::load(&config_path()) {
            Ok(c) => {
                print!("{}", enroll::sshd_snippet(&c));
                0
            }
            Err(e) => {
                eprintln!("{}", e);
                exec::EXIT_CONFIG
            }
        },
        Some("sudoers") => match GateConfig::load(&config_path()) {
            Ok(c) => {
                print!("{}", adapters::render_sudoers(c.backend, enroll::AGENT_USER, &c.services));
                0
            }
            Err(e) => {
                eprintln!("{}", e);
                exec::EXIT_CONFIG
            }
        },
        Some("version") | Some("--version") => {
            println!("sbc-gate {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some("help") | Some("--help") | Some("-h") => {
            println!("{}", HELP);
            0
        }
        Some(other) => {
            eprintln!("unknown command {}\n\n{}", other, HELP);
            2
        }
    };
    std::process::exit(code);
}

fn run_exec() -> i32 {
    let cfg = match GateConfig::load(&config_path()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sbc-gate: DENIED (gate_misconfigured) {} â€” failing closed", e);
            return exec::EXIT_CONFIG;
        }
    };
    let gate = match exec::Gate::load(cfg) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("sbc-gate: DENIED (gate_misconfigured) {} â€” failing closed", e);
            return exec::EXIT_CONFIG;
        }
    };
    gate.run(&exec::Invocation::from_env())
}

fn run_enroll(args: &[String]) -> i32 {
    let req = |n: &str| flag(args, n).ok_or_else(|| format!("missing {}", n));
    let opts = (|| -> Result<enroll::EnrollOpts, String> {
        Ok(enroll::EnrollOpts {
            contract: req("--contract")?,
            resource: req("--resource")?,
            token: req("--token")?,
            rpc: flag(args, "--rpc").unwrap_or_else(|| "https://rpc.testnet.fastnear.com".into()),
            relay: flag(args, "--relay"),
            backend: match flag(args, "--backend").as_deref() {
                None | Some("systemd") => Backend::Systemd,
                Some("supervisor") => Backend::Supervisor,
                Some(b) => return Err(format!("unknown backend {}", b)),
            },
            config_dir: PathBuf::from(flag(args, "--config-dir").unwrap_or_else(|| "/etc/sbc".into())),
            ssh_dir: PathBuf::from(flag(args, "--ssh-dir").unwrap_or_else(|| "/etc/ssh".into())),
            write_sshd: has(args, "--write-sshd"),
            write_sudoers: has(args, "--write-sudoers"),
            dry_run: has(args, "--dry-run"),
        })
    })();
    match opts.and_then(enroll::enroll) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("sbc-gate enroll: {}", e);
            1
        }
    }
}
