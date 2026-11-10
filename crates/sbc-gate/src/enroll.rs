//! `sbc-gate enroll` and `sbc-gate sync`.
//!
//! Enrollment is deliberately explicit about what it changes. By default it
//! writes only Sudo by Contract's own files and *prints* the sshd and sudoers
//! changes for the operator to review; `--write-sshd` / `--write-sudoers`
//! apply them (sudoers is validated with `visudo -c` first).

use crate::adapters;
use crate::config::{Backend, GateConfig};
use crate::near::{Rpc, Signer, TGAS};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const AGENT_USER: &str = "sbc-agent";

pub struct EnrollOpts {
    pub contract: String,
    pub resource: String,
    pub token: String,
    pub rpc: String,
    pub relay: Option<String>,
    pub backend: Backend,
    pub config_dir: PathBuf,
    pub ssh_dir: PathBuf,
    pub write_sshd: bool,
    pub write_sudoers: bool,
    pub dry_run: bool,
}

pub fn sshd_snippet(cfg: &GateConfig) -> String {
    format!(
        "# /etc/ssh/sshd_config.d/50-sbc.conf — Sudo by Contract (sbc-gate enroll)\n\
         # Trust certificates from this environment's NEAR-MPC-derived CA. No CA private key exists.\n\
         TrustedUserCAKeys {ca}\n\
         # Revoked capability serials, synced from the contract by `sbc-gate sync`.\n\
         RevokedKeys {krl}\n\
         \n\
         Match User {user}\n\
         \x20   # only certificates, only for this host's principal ({principal})\n\
         \x20   AuthorizedKeysFile none\n\
         \x20   AuthorizedPrincipalsFile {ssh}/sbc_principals/%u\n\
         \x20   AuthenticationMethods publickey\n\
         \x20   PasswordAuthentication no\n\
         \x20   KbdInteractiveAuthentication no\n\
         \x20   # every session is a single typed action through the gate\n\
         \x20   ExposeAuthInfo yes\n\
         \x20   ForceCommand /usr/local/sbin/sbc-gate\n\
         \x20   PermitTTY no\n\
         \x20   PermitUserRC no\n\
         \x20   AllowTcpForwarding no\n\
         \x20   AllowStreamLocalForwarding no\n\
         \x20   AllowAgentForwarding no\n\
         \x20   X11Forwarding no\n\
         \x20   PermitTunnel no\n\
         \x20   MaxSessions 1\n",
        ca = cfg.ca_file,
        krl = cfg.krl_file,
        user = AGENT_USER,
        principal = cfg.principal,
        ssh = Path::new(&cfg.ca_file).parent().map(|p| p.display().to_string()).unwrap_or_else(|| "/etc/ssh".into()),
    )
}

fn host_fingerprint(ssh_dir: &Path) -> Option<String> {
    let line = std::fs::read_to_string(ssh_dir.join("ssh_host_ed25519_key.pub")).ok()?;
    let b64 = line.split_whitespace().nth(1)?;
    let blob = sbc_core::ssh::unb64(b64).ok()?;
    let digest = Sha256::digest(&blob);
    Some(format!("SHA256:{}", sbc_core::ssh::b64(&digest).trim_end_matches('=')))
}

fn write_file(path: &Path, contents: &str, mode: u32, dry_run: bool) -> Result<(), String> {
    if dry_run {
        println!("--- would write {} ({:o})", path.display(), mode);
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {}", dir.display(), e))?;
    }
    let tmp = path.with_extension("sbc-tmp");
    std::fs::write(&tmp, contents).map_err(|e| format!("write {}: {}", tmp.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
    }
    let _ = mode;
    std::fs::rename(&tmp, path).map_err(|e| format!("install {}: {}", path.display(), e))?;
    println!("    wrote {}", path.display());
    Ok(())
}

#[cfg(unix)]
fn chown_to_agent(path: &Path) {
    // The gate runs as sbc-agent (it is sshd's forced command), so it must be
    // able to read its key. Nothing else runs as that user.
    if let Ok(out) = Command::new("id").args(["-u", AGENT_USER]).output() {
        let uid: Option<u32> = String::from_utf8_lossy(&out.stdout).trim().parse().ok();
        let gid: Option<u32> = Command::new("id")
            .args(["-g", AGENT_USER])
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok());
        if let (Some(u), Some(g)) = (uid, gid) {
            let _ = std::os::unix::fs::chown(path, Some(u), Some(g));
        }
    }
}
#[cfg(not(unix))]
fn chown_to_agent(_path: &Path) {}

pub fn write_krl(krl_file: &str, ca_file: &str, serials: &[u64]) -> Result<(), String> {
    let krl = Path::new(krl_file);
    let spec = krl.with_extension("spec");
    let mut s = String::from("# revoked Sudo by Contract capability serials\n");
    for n in serials {
        s.push_str(&format!("serial: {}\n", n));
    }
    std::fs::write(&spec, s).map_err(|e| format!("write {}: {}", spec.display(), e))?;
    let tmp = krl.with_extension("krl-tmp");
    let _ = std::fs::remove_file(&tmp);
    let out = Command::new("ssh-keygen")
        .arg("-k")
        .arg("-f")
        .arg(&tmp)
        .arg("-s")
        .arg(ca_file)
        .arg(&spec)
        .output()
        .map_err(|e| format!("ssh-keygen: {}", e))?;
    if !out.status.success() {
        return Err(format!("ssh-keygen -k failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    std::fs::rename(&tmp, krl).map_err(|e| format!("install KRL: {}", e))?;
    Ok(())
}

pub fn enroll(o: EnrollOpts) -> Result<(), String> {
    println!("Enrolling resource {} with policy contract {}", o.resource, o.contract);
    let rpc = Rpc::new(&o.rpc, 30);
    let token = Signer::from_secret(&o.contract, &o.token)?;

    println!("  • Looking up resource and environment CA …");
    let res = rpc
        .view(&o.contract, "get_resource", &json!({ "id": o.resource }))
        .map_err(|e| e.to_string())?;
    if res.is_null() {
        return Err(format!("resource {} does not exist on {}", o.resource, o.contract));
    }
    let environment = res["environment"].as_str().unwrap_or_default().to_string();
    let principal = res["principal"].as_str().unwrap_or_default().to_string();
    let services: Vec<String> = res["services"]
        .as_array()
        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let ca_line = rpc
        .view(&o.contract, "get_ca", &json!({ "environment": environment }))
        .map_err(|e| e.to_string())?;
    let ca_line = ca_line.as_str().ok_or("environment CA key is not ready yet (MPC derivation pending)")?.to_string();
    sbc_core::ssh::parse_ed25519_pubkey_line(&ca_line).map_err(|e| format!("bad CA line from contract: {}", e))?;
    println!("    environment {}  CA {}", environment, ca_line.split_whitespace().take(2).collect::<Vec<_>>().join(" ").chars().take(60).collect::<String>() + "…");

    println!("  • Generating this host's gate key (never leaves the host) …");
    let gate = Signer::generate(&o.contract);
    let fingerprint = host_fingerprint(&o.ssh_dir);
    let meta = json!({ "gate_version": env!("CARGO_PKG_VERSION"), "host_fingerprint": fingerprint });

    println!("  • Exchanging the one-time enrollment token for the gate key …");
    let r: Value = rpc
        .function_call(&token, &o.contract, "complete_enrollment", &json!({ "new_public_key": gate.public_key_string(), "meta": meta }), 50 * TGAS)
        .map_err(|e| format!("enrollment rejected: {}", e))?;
    if r.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("enrollment rejected: {}", r.get("message").and_then(Value::as_str).unwrap_or("unknown")));
    }
    println!("    bound {} as Gate for {}", gate.public_key_string(), o.resource);

    let ca_file = o.ssh_dir.join("sbc_user_ca.pub");
    let krl_file = o.ssh_dir.join("sbc_revoked.krl");
    let key_file = o.config_dir.join("gate.key");
    let cfg = GateConfig {
        contract: o.contract.clone(),
        rpc: o.rpc.clone(),
        relay: o.relay.clone(),
        resource: o.resource.clone(),
        principal: principal.clone(),
        environment,
        key_file: key_file.display().to_string(),
        ca_file: ca_file.display().to_string(),
        krl_file: krl_file.display().to_string(),
        backend: o.backend,
        services: services.clone(),
        exec_timeout_secs: 120,
        rpc_timeout_secs: 15,
    };
    cfg.validate()?;

    println!("  • Writing Sudo by Contract files …");
    write_file(&key_file, &serde_json::to_string_pretty(&gate.key_file()).unwrap(), 0o600, o.dry_run)?;
    if !o.dry_run {
        chown_to_agent(&key_file);
    }
    write_file(&o.config_dir.join("gate.toml"), &cfg.to_toml(), 0o644, o.dry_run)?;
    write_file(&ca_file, &format!("{}\n", ca_line), 0o644, o.dry_run)?;
    write_file(&o.ssh_dir.join("sbc_principals").join(AGENT_USER), &format!("{}\n", principal), 0o644, o.dry_run)?;
    if !o.dry_run {
        write_krl(&cfg.krl_file, &cfg.ca_file, &[])?;
        println!("    wrote {} (empty)", cfg.krl_file);
    }

    let snippet = sshd_snippet(&cfg);
    let sudoers = adapters::render_sudoers(o.backend, AGENT_USER, &services);
    if o.write_sshd && !o.dry_run {
        write_file(&o.ssh_dir.join("sshd_config.d").join("50-sbc.conf"), &snippet, 0o644, false)?;
        println!("    validate with `sshd -t`, then reload sshd");
    } else {
        println!("\n  sshd configuration (review, then install as /etc/ssh/sshd_config.d/50-sbc.conf):\n");
        println!("{}", snippet);
    }
    if o.write_sudoers && !o.dry_run {
        let path = Path::new("/etc/sudoers.d/sbc-gate");
        let tmp = Path::new("/etc/sudoers.d/.sbc-gate.check");
        std::fs::write(tmp, &sudoers).map_err(|e| e.to_string())?;
        let ok = Command::new("visudo").args(["-cf"]).arg(tmp).status().map(|s| s.success()).unwrap_or(false);
        let _ = std::fs::remove_file(tmp);
        if !ok {
            return Err("generated sudoers failed `visudo -c`; not installed".into());
        }
        write_file(path, &sudoers, 0o440, false)?;
    } else {
        println!("  sudoers rules (review, then install as /etc/sudoers.d/sbc-gate, mode 0440):\n");
        println!("{}", sudoers);
    }
    println!("\n✓ {} enrolled. Install `sbc-gate sync` on a 1-minute timer for heartbeats and revocation lists.", o.resource);
    Ok(())
}

/// Heartbeat + revocation list + CA pin check. Run every minute.
pub fn sync(cfg: &GateConfig) -> Result<i32, String> {
    let rpc = Rpc::new(&cfg.rpc, cfg.rpc_timeout_secs);
    let signer = Signer::from_key_file(&cfg.key_file)?;
    let mut warnings = 0;

    let revs = rpc
        .view(&cfg.contract, "list_revocations", &json!({ "resource_id": cfg.resource }))
        .map_err(|e| e.to_string())?;
    let serials: Vec<u64> = revs
        .as_array()
        .map(|a| a.iter().filter_map(|r| r["serial"].as_u64()).collect())
        .unwrap_or_default();
    write_krl(&cfg.krl_file, &cfg.ca_file, &serials)?;
    println!("krl: {} revoked serial(s) in {}", serials.len(), cfg.krl_file);

    let ca = rpc
        .view(&cfg.contract, "get_ca", &json!({ "environment": cfg.environment }))
        .map_err(|e| e.to_string())?;
    let pinned = std::fs::read_to_string(&cfg.ca_file).unwrap_or_default();
    let same = ca
        .as_str()
        .map(|l| l.split_whitespace().take(2).eq(pinned.split_whitespace().take(2)))
        .unwrap_or(false);
    if !same {
        eprintln!("WARNING: the contract's CA for {} differs from the pinned {}. Not changing it automatically; re-enroll to rotate.", cfg.environment, cfg.ca_file);
        warnings += 1;
    }

    let res = rpc.view(&cfg.contract, "get_resource", &json!({ "id": cfg.resource })).map_err(|e| e.to_string())?;
    let chain_services: Vec<String> = res["services"]
        .as_array()
        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let extra: Vec<&String> = chain_services.iter().filter(|s| !cfg.services.contains(s)).collect();
    if !extra.is_empty() {
        eprintln!("WARNING: contract lists services this host does not expose locally: {:?} (they will be denied here)", extra);
        warnings += 1;
    }

    rpc.function_call(&signer, &cfg.contract, "heartbeat", &json!({ "gate_version": env!("CARGO_PKG_VERSION") }), 10 * TGAS)
        .map_err(|e| format!("heartbeat failed: {}", e))?;
    println!("heartbeat: ok");
    Ok(if warnings > 0 { 2 } else { 0 })
}
