//! Identifier grammars. Everything that ends up inside a certificate, a
//! sudoers rule or an argv is validated against a closed grammar here, so the
//! contract can never be talked into signing something the gate cannot parse
//! unambiguously.

/// Slugs used for resource, agent, approver and policy ids:
/// `[a-z0-9][a-z0-9-]{1,62}`, no trailing dash, no `--`.
pub fn is_slug(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 2 || b.len() > 63 {
        return false;
    }
    if !(b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) {
        return false;
    }
    if b[b.len() - 1] == b'-' {
        return false;
    }
    let mut prev_dash = false;
    for &c in b {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-';
        if !ok {
            return false;
        }
        if c == b'-' && prev_dash {
            return false;
        }
        prev_dash = c == b'-';
    }
    true
}

/// A systemd unit / supervisor program name the gate is allowed to pass as a
/// single argv element: `[A-Za-z0-9][A-Za-z0-9_.@:-]{0,99}`.
///
/// The first character can never be `-`, so a target can never be parsed as
/// an option by the program it is handed to (argument injection).
pub fn is_unit_name(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 100 {
        return false;
    }
    if !b[0].is_ascii_alphanumeric() {
        return false;
    }
    if s.contains("..") {
        return false;
    }
    b.iter()
        .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'@' | b':' | b'-'))
}

/// OpenSSH principals: printable, no whitespace, no commas (commas separate
/// principals in `ssh-keygen -n` and in `AuthorizedPrincipalsFile` options).
pub fn is_principal(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 96
        && s
            .bytes()
            .all(|c| c.is_ascii_graphic() && c != b',' && c != b'"' && c != b'\\')
}

/// Free-text labels shown to humans (resource names, agent display names).
/// Printable ASCII + space, bounded.
pub fn is_label(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 80 && s.bytes().all(|c| (0x20..0x7f).contains(&c))
}

/// Lowercase hex of a fixed byte length.
pub fn is_hex_of_len(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// IPv4/IPv6 CIDR list as accepted by the OpenSSH `source-address` critical
/// option. We accept a conservative character set and leave semantic parsing
/// to sshd, which rejects the certificate if the list is malformed (fail closed).
pub fn is_source_address_list(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s
            .bytes()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, b'.' | b':' | b'/' | b','))
        && !s.split(',').any(|p| p.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert!(is_slug("prod-web-02"));
        assert!(is_slug("r7f3a9c21"));
        assert!(!is_slug("-prod"));
        assert!(!is_slug("prod-"));
        assert!(!is_slug("prod--web"));
        assert!(!is_slug("Prod"));
        assert!(!is_slug("a"));
        assert!(!is_slug("prod_web"));
        assert!(!is_slug("prod web"));
    }

    #[test]
    fn unit_names_block_option_injection() {
        assert!(is_unit_name("checkout-api"));
        assert!(is_unit_name("getty@tty1.service"));
        assert!(!is_unit_name("--now"));
        assert!(!is_unit_name("-checkout"));
        assert!(!is_unit_name("../../etc/passwd"));
        assert!(!is_unit_name("a/b"));
        assert!(!is_unit_name("a;b"));
        assert!(!is_unit_name("a b"));
        assert!(!is_unit_name(""));
        assert!(!is_unit_name("a$(id)"));
    }

    #[test]
    fn principals() {
        assert!(is_principal("sbc-prod-web-02"));
        assert!(!is_principal("a,b"));
        assert!(!is_principal("a b"));
        assert!(!is_principal(""));
    }

    #[test]
    fn source_addresses() {
        assert!(is_source_address_list("10.0.0.0/8,192.168.1.4/32"));
        assert!(is_source_address_list("2001:db8::/32"));
        assert!(!is_source_address_list("10.0.0.0/8,"));
        assert!(!is_source_address_list("10.0.0.0/8 "));
        assert!(!is_source_address_list("*"));
    }
}
