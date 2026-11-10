//! `/etc/sbc/gate.toml`. Every field that affects authorisation is required:
//! a missing or malformed config makes the gate deny everything.

use serde::{Deserialize, Serialize};
use std::path::Path;

pub const DEFAULT_CONFIG: &str = "/etc/sbc/gate.toml";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// systemd hosts: systemctl / journalctl through exact sudoers rules.
    Systemd,
    /// Containers and hosts without systemd: supervisord / supervisorctl.
    Supervisor,
    /// Never executes anything; prints the argv it would run. Tests only.
    DryRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateConfig {
    pub contract: String,
    pub rpc: String,
    #[serde(default)]
    pub relay: Option<String>,
    pub resource: String,
    pub principal: String,
    pub environment: String,
    /// NEAR CLI JSON key file of this host's gate key (role Gate).
    pub key_file: String,
    /// Pinned CA public key line (`ssh-ed25519 AAAA...`) for this environment.
    pub ca_file: String,
    pub krl_file: String,
    pub backend: Backend,
    /// Host-local ceiling: the gate refuses any target not listed here, no
    /// matter what the contract says. A compromised policy admin cannot make
    /// a host expose more than its operator allowed at enrollment.
    pub services: Vec<String>,
    #[serde(default = "default_exec_timeout")]
    pub exec_timeout_secs: u64,
    #[serde(default = "default_rpc_timeout")]
    pub rpc_timeout_secs: u64,
}

fn default_exec_timeout() -> u64 {
    120
}
fn default_rpc_timeout() -> u64 {
    15
}

impl GateConfig {
    pub fn load(path: &Path) -> Result<GateConfig, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
        let cfg: GateConfig = toml::from_str(&text).map_err(|e| format!("invalid {}: {}", path.display(), e))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !sbc_core::validate::is_slug(&self.resource) {
            return Err("resource must be a slug".into());
        }
        if self.principal != format!("sbc-{}", self.resource) {
            return Err("principal must be sbc-<resource>".into());
        }
        if !self.rpc.starts_with("https://") && !self.rpc.starts_with("http://127.0.0.1") && !self.rpc.starts_with("http://localhost") {
            return Err("rpc must be https (or loopback for tests)".into());
        }
        if self.services.iter().any(|s| !sbc_core::validate::is_unit_name(s)) {
            return Err("services contains an invalid unit name".into());
        }
        Ok(())
    }

    pub fn to_toml(&self) -> String {
        format!(
            "# Sudo by Contract gate configuration. Written by `sbc-gate enroll`.\n\
             # Authorisation-relevant: keep root-owned, 0644. The key file must be 0600.\n{}",
            toml::to_string_pretty(self).expect("serializable")
        )
    }
}
