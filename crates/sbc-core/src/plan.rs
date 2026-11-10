//! Typed action → the exact argv a host executes.
//!
//! Lives in `sbc-core` (not the gate) so the very same function runs in
//! `sbc-gate` on enrolled hosts and, compiled to WebAssembly, in the browser
//! playground. The agent's text never reaches a shell or an argv: only the
//! validated target string does, as one argv element.

use crate::action::{ActionKind, ParsedCommand};

pub const SUDO: &str = "/usr/bin/sudo";
pub const SYSTEMCTL: &str = "/usr/bin/systemctl";
pub const JOURNALCTL: &str = "/usr/bin/journalctl";
pub const SUPERVISORCTL: &str = "/usr/bin/supervisorctl";

/// Log sizes are bucketed so sudoers can list them exactly.
pub const LOG_BUCKETS: &[u32] = &[50, 100, 200, 500, 1000];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceManager {
    Systemd,
    Supervisor,
}

pub fn log_bucket(n: u32) -> u32 {
    *LOG_BUCKETS.iter().find(|b| **b >= n).unwrap_or(&1000)
}

fn supervisor_tail_bytes(lines: u32) -> u32 {
    lines * 160
}

/// The exact argv the gate executes for a parsed command.
pub fn argv(manager: ServiceManager, cmd: &ParsedCommand) -> Vec<String> {
    let t = cmd.action.target.clone();
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let mut v = match (manager, cmd.action.kind) {
        (ServiceManager::Systemd, ActionKind::ServiceRestart) => s(&[SUDO, "-n", SYSTEMCTL, "restart"]),
        (ServiceManager::Systemd, ActionKind::ServiceStatus) => s(&[SUDO, "-n", SYSTEMCTL, "status", "--no-pager"]),
        (ServiceManager::Systemd, ActionKind::LogsRead) => s(&[SUDO, "-n", JOURNALCTL, "-u"]),
        (ServiceManager::Supervisor, ActionKind::ServiceRestart) => s(&[SUDO, "-n", SUPERVISORCTL, "restart"]),
        (ServiceManager::Supervisor, ActionKind::ServiceStatus) => s(&[SUDO, "-n", SUPERVISORCTL, "status"]),
        (ServiceManager::Supervisor, ActionKind::LogsRead) => {
            let bytes = supervisor_tail_bytes(log_bucket(cmd.params.log_lines));
            s(&[SUDO, "-n", SUPERVISORCTL, "tail", &format!("-{}", bytes)])
        }
    };
    v.push(t);
    if manager == ServiceManager::Systemd && cmd.action.kind == ActionKind::LogsRead {
        v.extend(s(&["-n", &log_bucket(cmd.params.log_lines).to_string(), "--no-pager"]));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::parse_command;

    #[test]
    fn argv_never_contains_agent_text() {
        let p = parse_command("sudo systemctl restart checkout-api").unwrap();
        assert_eq!(argv(ServiceManager::Systemd, &p), vec![SUDO, "-n", SYSTEMCTL, "restart", "checkout-api"]);
        assert_eq!(argv(ServiceManager::Supervisor, &p), vec![SUDO, "-n", SUPERVISORCTL, "restart", "checkout-api"]);
        let l = parse_command("journalctl -u checkout-api -n 70").unwrap();
        assert_eq!(argv(ServiceManager::Systemd, &l), vec![SUDO, "-n", JOURNALCTL, "-u", "checkout-api", "-n", "100", "--no-pager"]);
        assert_eq!(argv(ServiceManager::Supervisor, &l), vec![SUDO, "-n", SUPERVISORCTL, "tail", "-16000", "checkout-api"]);
        let st = parse_command("systemctl status checkout-api").unwrap();
        assert_eq!(argv(ServiceManager::Systemd, &st), vec![SUDO, "-n", SYSTEMCTL, "status", "--no-pager", "checkout-api"]);
    }
}
