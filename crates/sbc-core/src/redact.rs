//! Redaction for audit records.
//!
//! Denied commands are audit-worthy ("Deploy Agent attempted `sudo cat
//! /etc/shadow`"), but command lines can carry secrets (`mysql -pHunter2`,
//! `curl -H Authorization:...`, `TOKEN=... ./deploy`). Before anything leaves
//! the host we keep the program and the shape of the command and mask anything
//! that looks like a credential. The full original is only ever represented by
//! its SHA-256, which is enough to prove "this exact command was attempted"
//! without disclosing it.

const MAX_REDACTED_LEN: usize = 160;
const SECRETISH: &[&str] = &[
    "pass", "pwd", "secret", "token", "key", "auth", "cred", "bearer", "session", "cookie", "sig",
];

fn looks_secret_kv(tok: &str) -> bool {
    if let Some((k, _)) = tok.split_once('=') {
        let k = k.trim_start_matches('-').to_ascii_lowercase();
        return SECRETISH.iter().any(|s| k.contains(s));
    }
    false
}

fn looks_high_entropy(tok: &str) -> bool {
    if tok.len() < 24 || tok.starts_with('/') {
        return false;
    }
    let classes = [
        tok.bytes().any(|c| c.is_ascii_lowercase()),
        tok.bytes().any(|c| c.is_ascii_uppercase()),
        tok.bytes().any(|c| c.is_ascii_digit()),
    ];
    classes.iter().filter(|x| **x).count() >= 2 && !tok.contains('-')
}

/// Produce a printable, bounded, credential-masked rendition of a command line.
pub fn redact_command(original: &str) -> String {
    let printable: String = original
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut out: Vec<String> = Vec::new();
    let mut prev_flag_secret = false;
    for tok in printable.split_whitespace() {
        let lower = tok.to_ascii_lowercase();
        let rendered = if prev_flag_secret {
            "‹redacted›".to_string()
        } else if looks_secret_kv(tok) {
            let (k, _) = tok.split_once('=').unwrap();
            format!("{}=‹redacted›", k)
        } else if (lower.starts_with("-p") && lower.len() > 2 && !lower.starts_with("--"))
            || looks_high_entropy(tok)
        {
            // mysql -pSECRET style, or an opaque token
            if lower.starts_with("-p") && lower.len() > 2 {
                "-p‹redacted›".to_string()
            } else {
                "‹redacted›".to_string()
            }
        } else {
            tok.to_string()
        };
        prev_flag_secret = matches!(
            lower.as_str(),
            "--password" | "--token" | "--secret" | "-h" | "--header" | "--auth" | "--api-key"
        );
        out.push(rendered);
    }
    let mut s = out.join(" ");
    if s.chars().count() > MAX_REDACTED_LEN {
        s = s.chars().take(MAX_REDACTED_LEN).collect::<String>() + "…";
    }
    s
}

/// The program an attempted command would have run (first non-sudo token).
pub fn program_of(original: &str) -> String {
    let mut it = original.split_whitespace();
    let mut first = it.next().unwrap_or("");
    if first == "sudo" || first.ends_with("/sudo") {
        first = it.find(|t| !t.starts_with('-')).unwrap_or("sudo");
    }
    first.chars().filter(|c| !c.is_control()).take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_harmless_commands() {
        assert_eq!(redact_command("sudo cat /etc/shadow"), "sudo cat /etc/shadow");
        assert_eq!(program_of("sudo cat /etc/shadow"), "cat");
        assert_eq!(program_of("sudo -n su"), "su");
    }

    #[test]
    fn masks_credentials() {
        assert_eq!(redact_command("mysql -uroot -pHunter2 prod"), "mysql -uroot -p‹redacted› prod");
        assert_eq!(redact_command("DB_PASSWORD=hunter2 ./migrate"), "DB_PASSWORD=‹redacted› ./migrate");
        assert_eq!(
            redact_command("curl -H Authorization:Bearer abc https://x"),
            "curl -H ‹redacted› abc https://x"
        );
        assert_eq!(
            redact_command("deploy --token ghp_ABCDEF1234567890abcdef123456"),
            "deploy --token ‹redacted›"
        );
        assert_eq!(redact_command("echo AKIAIOSFODNN7EXAMPLEKEY1234"), "echo ‹redacted›");
    }

    #[test]
    fn bounds_length_and_controls() {
        let long = "a ".repeat(300);
        assert!(redact_command(&long).chars().count() <= MAX_REDACTED_LEN + 1);
        assert_eq!(redact_command("id\n\x1b[31m"), "id [31m");
    }
}
