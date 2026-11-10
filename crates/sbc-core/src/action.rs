//! Canonical actions.
//!
//! Sudo by Contract never authorises "a shell command". It authorises a typed
//! action (`service.restart` on `checkout-api`), and the host gate maps the
//! text an agent sends over SSH onto exactly one typed action, or rejects it.
//!
//! The parser is deliberately closed:
//!
//! * the command line may only contain `[A-Za-z0-9_.@:/=+,-]` and spaces, so
//!   there is nothing for a shell to expand, and nothing is ever handed to a
//!   shell anyway (the gate `execve`s a fixed program with fixed arguments);
//! * every accepted form is spelled out below, so `startsWith("systemctl")`
//!   style bypasses (`systemctl restart a; id`, `systemctl restart --now x`,
//!   `systemctl edit x`) cannot be expressed;
//! * targets must pass [`validate::is_unit_name`], which forbids a leading
//!   `-` (argument injection) and path separators.

use crate::validate;

pub const MAX_COMMAND_LEN: usize = 512;
pub const MAX_ARGS: usize = 16;
pub const MAX_LOG_LINES: u32 = 1000;
pub const DEFAULT_LOG_LINES: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ActionKind {
    /// Restart one service. Mutating.
    ServiceRestart,
    /// Read the status of one service. Read-only.
    ServiceStatus,
    /// Read recent journal lines of one service. Read-only.
    LogsRead,
}

impl ActionKind {
    pub const ALL: &'static [ActionKind] =
        &[ActionKind::ServiceRestart, ActionKind::ServiceStatus, ActionKind::LogsRead];

    pub fn as_str(&self) -> &'static str {
        match self {
            ActionKind::ServiceRestart => "service.restart",
            ActionKind::ServiceStatus => "service.status",
            ActionKind::LogsRead => "logs.read",
        }
    }

    pub fn parse(s: &str) -> Option<ActionKind> {
        ActionKind::ALL.iter().copied().find(|k| k.as_str() == s)
    }

    pub fn is_read_only(&self) -> bool {
        !matches!(self, ActionKind::ServiceRestart)
    }

    /// Human phrasing: "restart", "read the status of", "read logs of".
    pub fn verb(&self) -> &'static str {
        match self {
            ActionKind::ServiceRestart => "restart",
            ActionKind::ServiceStatus => "read the status of",
            ActionKind::LogsRead => "read the logs of",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Action {
    pub kind: ActionKind,
    pub target: String,
}

impl Action {
    pub fn new(kind: ActionKind, target: &str) -> Option<Action> {
        if validate::is_unit_name(target) {
            Some(Action { kind, target: target.to_string() })
        } else {
            None
        }
    }

    /// `service.restart:checkout-api` — the canonical form that is stored in
    /// the contract and compared by the gate.
    pub fn canonical(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.target)
    }

    pub fn parse_canonical(s: &str) -> Option<Action> {
        let (k, t) = s.split_once(':')?;
        Action::new(ActionKind::parse(k)?, t)
    }

    pub fn describe(&self) -> String {
        format!("{} {}", self.kind.verb(), self.target)
    }
}

/// Non-authorising parameters that shape *how* an approved action runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionParams {
    pub log_lines: u32,
}

impl Default for ActionParams {
    fn default() -> Self {
        ActionParams { log_lines: DEFAULT_LOG_LINES }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    pub action: Action,
    pub params: ActionParams,
    /// Whether the agent prefixed the command with `sudo`. Purely cosmetic:
    /// the gate decides the OS privilege, not the agent.
    pub via_sudo: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandRejection {
    /// No command at all (interactive login attempt).
    Empty,
    TooLong,
    TooManyArgs,
    /// A byte outside the allowed alphabet, e.g. `;`, `|`, `$`, a quote or a newline.
    ForbiddenCharacter(char),
    /// `sudo -u`, `sudo -s`, `sudo -i`, ...
    UnsupportedSudoFlag(String),
    /// The program is not one any adapter understands (`cat`, `su`, `bash`, `/tmp/systemctl`).
    NoAdapter { program: String },
    /// The program is known but this sub-command / argument shape is not.
    UnsupportedArguments { program: String },
    /// The target failed the unit-name grammar.
    InvalidTarget(String),
}

impl CommandRejection {
    pub fn code(&self) -> &'static str {
        match self {
            CommandRejection::Empty => "interactive_session",
            CommandRejection::TooLong => "command_too_long",
            CommandRejection::TooManyArgs => "too_many_arguments",
            CommandRejection::ForbiddenCharacter(_) => "shell_metacharacter",
            CommandRejection::UnsupportedSudoFlag(_) => "unsupported_sudo_flag",
            CommandRejection::NoAdapter { .. } => "no_adapter",
            CommandRejection::UnsupportedArguments { .. } => "unsupported_arguments",
            CommandRejection::InvalidTarget(_) => "invalid_target",
        }
    }

    pub fn message(&self) -> String {
        match self {
            CommandRejection::Empty => "interactive shells are never granted".into(),
            CommandRejection::TooLong => "command exceeds 512 bytes".into(),
            CommandRejection::TooManyArgs => "command has too many arguments".into(),
            CommandRejection::ForbiddenCharacter(c) => {
                format!("character {:?} is not allowed; commands are never passed to a shell", c)
            }
            CommandRejection::UnsupportedSudoFlag(f) => format!("sudo flag {} is not supported", f),
            CommandRejection::NoAdapter { program } => {
                format!("`{}` is not an action Sudo by Contract can authorise", program)
            }
            CommandRejection::UnsupportedArguments { program } => {
                format!("this form of `{}` is not an authorisable action", program)
            }
            CommandRejection::InvalidTarget(t) => format!("`{}` is not a valid service name", t),
        }
    }
}

fn is_allowed_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, b'_' | b'.' | b'@' | b':' | b'/' | b'=' | b'+' | b',' | b'-' | b' ' | b'\t')
}

/// Split on spaces/tabs after checking the alphabet. No quoting, no escapes,
/// no expansion: there is nothing to interpret.
pub fn tokenize(original: &str) -> Result<Vec<&str>, CommandRejection> {
    if original.len() > MAX_COMMAND_LEN {
        return Err(CommandRejection::TooLong);
    }
    for ch in original.chars() {
        if !ch.is_ascii() || !is_allowed_byte(ch as u8) {
            return Err(CommandRejection::ForbiddenCharacter(ch));
        }
    }
    let toks: Vec<&str> = original.split([' ', '\t']).filter(|t| !t.is_empty()).collect();
    if toks.is_empty() {
        return Err(CommandRejection::Empty);
    }
    if toks.len() > MAX_ARGS {
        return Err(CommandRejection::TooManyArgs);
    }
    Ok(toks)
}

fn normalize_program(p: &str) -> Option<&'static str> {
    match p {
        "systemctl" | "/usr/bin/systemctl" | "/bin/systemctl" => Some("systemctl"),
        "journalctl" | "/usr/bin/journalctl" | "/bin/journalctl" => Some("journalctl"),
        _ => None,
    }
}

fn target(t: &str) -> Result<String, CommandRejection> {
    if validate::is_unit_name(t) {
        Ok(t.to_string())
    } else {
        Err(CommandRejection::InvalidTarget(t.to_string()))
    }
}

/// Map the text of an SSH exec request onto a typed action.
pub fn parse_command(original: &str) -> Result<ParsedCommand, CommandRejection> {
    let toks = tokenize(original)?;
    let mut i = 0;
    let mut via_sudo = false;
    if toks[0] == "sudo" || toks[0] == "/usr/bin/sudo" || toks[0] == "/bin/sudo" {
        via_sudo = true;
        i = 1;
        while i < toks.len() && toks[i].starts_with('-') {
            match toks[i] {
                "-n" | "--non-interactive" => i += 1,
                "--" => {
                    i += 1;
                    break;
                }
                other => return Err(CommandRejection::UnsupportedSudoFlag(other.to_string())),
            }
        }
        if i >= toks.len() {
            return Err(CommandRejection::NoAdapter { program: "sudo".into() });
        }
    }
    let argv = &toks[i..];
    let program = match normalize_program(argv[0]) {
        Some(p) => p,
        None => return Err(CommandRejection::NoAdapter { program: argv[0].to_string() }),
    };
    let unsupported = || CommandRejection::UnsupportedArguments { program: program.to_string() };

    let (action, params) = match program {
        "systemctl" => match argv {
            [_, "restart", unit] => (
                Action { kind: ActionKind::ServiceRestart, target: target(unit)? },
                ActionParams::default(),
            ),
            [_, "status", unit] | [_, "status", "--no-pager", unit] => (
                Action { kind: ActionKind::ServiceStatus, target: target(unit)? },
                ActionParams::default(),
            ),
            _ => return Err(unsupported()),
        },
        "journalctl" => {
            // journalctl -u UNIT [-n N] | journalctl --unit=UNIT [-n N]
            let mut unit: Option<&str> = None;
            let mut lines = DEFAULT_LOG_LINES;
            let mut j = 1;
            while j < argv.len() {
                match argv[j] {
                    "-u" | "--unit" if j + 1 < argv.len() && unit.is_none() => {
                        unit = Some(argv[j + 1]);
                        j += 2;
                    }
                    s if s.starts_with("--unit=") && unit.is_none() => {
                        unit = Some(&s["--unit=".len()..]);
                        j += 1;
                    }
                    "-n" | "--lines" if j + 1 < argv.len() => {
                        lines = argv[j + 1].parse::<u32>().map_err(|_| unsupported())?;
                        if lines == 0 || lines > MAX_LOG_LINES {
                            return Err(unsupported());
                        }
                        j += 2;
                    }
                    "--no-pager" => j += 1,
                    _ => return Err(unsupported()),
                }
            }
            let unit = unit.ok_or_else(unsupported)?;
            (
                Action { kind: ActionKind::LogsRead, target: target(unit)? },
                ActionParams { log_lines: lines },
            )
        }
        _ => return Err(unsupported()),
    };
    Ok(ParsedCommand { action, params, via_sudo })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> Action {
        parse_command(s).unwrap_or_else(|e| panic!("{s}: {e:?}")).action
    }

    #[test]
    fn hero_demo_commands() {
        assert_eq!(ok("sudo systemctl restart checkout-api").canonical(), "service.restart:checkout-api");
        assert!(matches!(
            parse_command("sudo cat /etc/shadow"),
            Err(CommandRejection::NoAdapter { program }) if program == "cat"
        ));
        // parses fine, but the *capability* only covers checkout-api: that is
        // enforced by comparing canonical actions, see contract + gate.
        assert_eq!(ok("sudo systemctl restart sshd").canonical(), "service.restart:sshd");
    }

    #[test]
    fn accepted_forms() {
        assert_eq!(ok("systemctl restart checkout-api").kind, ActionKind::ServiceRestart);
        assert_eq!(ok("/usr/bin/systemctl restart checkout-api").kind, ActionKind::ServiceRestart);
        assert_eq!(ok("sudo -n systemctl status checkout-api").kind, ActionKind::ServiceStatus);
        assert_eq!(ok("systemctl status --no-pager checkout-api").kind, ActionKind::ServiceStatus);
        let p = parse_command("journalctl -u checkout-api -n 50").unwrap();
        assert_eq!(p.action.canonical(), "logs.read:checkout-api");
        assert_eq!(p.params.log_lines, 50);
        assert_eq!(ok("journalctl --unit=checkout-api --no-pager").kind, ActionKind::LogsRead);
    }

    #[test]
    fn shell_metacharacters_are_rejected() {
        for s in [
            "systemctl restart checkout-api; cat /etc/shadow",
            "systemctl restart checkout-api && id",
            "systemctl restart checkout-api | sh",
            "systemctl restart $(id)",
            "systemctl restart `id`",
            "systemctl restart 'checkout-api'",
            "systemctl restart checkout-api\nid",
            "systemctl restart checkout-api > /etc/passwd",
            "systemctl restart chéckout",
            "systemctl restart checkout-api #",
            "systemctl restart *",
        ] {
            assert!(
                matches!(parse_command(s), Err(CommandRejection::ForbiddenCharacter(_))),
                "{s:?} should be rejected"
            );
        }
    }

    #[test]
    fn escalation_shapes_are_rejected() {
        assert!(matches!(parse_command("sudo su"), Err(CommandRejection::NoAdapter { .. })));
        assert!(matches!(parse_command("sudo -s"), Err(CommandRejection::UnsupportedSudoFlag(_))));
        assert!(matches!(parse_command("sudo -i"), Err(CommandRejection::UnsupportedSudoFlag(_))));
        assert!(matches!(
            parse_command("sudo -u root systemctl restart x"),
            Err(CommandRejection::UnsupportedSudoFlag(_))
        ));
        assert!(matches!(parse_command("bash"), Err(CommandRejection::NoAdapter { .. })));
        assert!(matches!(parse_command("/tmp/systemctl restart x"), Err(CommandRejection::NoAdapter { .. })));
        assert!(matches!(parse_command(""), Err(CommandRejection::Empty)));
        assert!(matches!(parse_command("   "), Err(CommandRejection::Empty)));
    }

    #[test]
    fn argument_injection_is_rejected() {
        assert!(matches!(
            parse_command("systemctl restart --now checkout-api"),
            Err(CommandRejection::UnsupportedArguments { .. })
        ));
        assert!(matches!(
            parse_command("systemctl restart -H attacker checkout-api"),
            Err(CommandRejection::UnsupportedArguments { .. })
        ));
        assert!(matches!(
            parse_command("systemctl restart --help"),
            Err(CommandRejection::InvalidTarget(_))
        ));
        assert!(matches!(
            parse_command("systemctl restart a b"),
            Err(CommandRejection::UnsupportedArguments { .. })
        ));
        assert!(matches!(
            parse_command("systemctl edit checkout-api"),
            Err(CommandRejection::UnsupportedArguments { .. })
        ));
        assert!(matches!(
            parse_command("systemctl restart ../../sshd"),
            Err(CommandRejection::InvalidTarget(_))
        ));
        assert!(matches!(
            parse_command("journalctl -u checkout-api -n 100000"),
            Err(CommandRejection::UnsupportedArguments { .. })
        ));
        assert!(matches!(
            parse_command("journalctl -u a -u b"),
            Err(CommandRejection::UnsupportedArguments { .. })
        ));
        assert!(matches!(
            parse_command("journalctl -f -u checkout-api"),
            Err(CommandRejection::UnsupportedArguments { .. })
        ));
    }

    #[test]
    fn canonical_roundtrip() {
        let a = Action::new(ActionKind::LogsRead, "checkout-api").unwrap();
        assert_eq!(Action::parse_canonical(&a.canonical()), Some(a));
        assert_eq!(Action::parse_canonical("service.reboot:x"), None);
        assert_eq!(Action::parse_canonical("service.restart:-x"), None);
    }
}
