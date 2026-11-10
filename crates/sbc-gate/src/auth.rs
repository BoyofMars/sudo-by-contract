//! Identify the capability behind this SSH session.
//!
//! sshd has already authenticated the certificate (CA, principal, validity,
//! KRL) before running us. We re-verify independently from `SSH_USER_AUTH`
//! (written by sshd when `ExposeAuthInfo yes`) so that a misconfigured sshd
//! cannot silently widen access, and so we learn the certificate serial,
//! which *is* the capability id on-chain.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sbc_core::ssh::{self, ParsedCert};

#[derive(Debug, Clone)]
pub struct Presented {
    pub cert: ParsedCert,
    pub serial: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    NoAuthInfo,
    NoCertificate,
    MultipleCertificates,
    Malformed(String),
    UntrustedCa,
    BadSignature,
    WrongPrincipal,
    NotYetValid,
    Expired,
    NotUserCert,
    MissingForceCommand,
}

impl AuthError {
    pub fn code(&self) -> &'static str {
        match self {
            AuthError::NoAuthInfo => "no_auth_info",
            AuthError::NoCertificate => "no_certificate",
            AuthError::MultipleCertificates => "ambiguous_certificate",
            AuthError::Malformed(_) => "malformed_certificate",
            AuthError::UntrustedCa => "untrusted_ca",
            AuthError::BadSignature => "bad_signature",
            AuthError::WrongPrincipal => "wrong_resource",
            AuthError::NotYetValid => "not_yet_valid",
            AuthError::Expired => "expired",
            AuthError::NotUserCert => "not_user_certificate",
            AuthError::MissingForceCommand => "missing_force_command",
        }
    }
}

/// Parse the contents of the `SSH_USER_AUTH` file and verify the single
/// certificate in it against the pinned CA key, principal and clock.
pub fn verify_presented(auth_info: &str, ca_key: &[u8; 32], principal: &str, now_secs: u64) -> Result<Presented, AuthError> {
    let mut found: Option<(Vec<u8>, ParsedCert)> = None;
    for line in auth_info.lines() {
        let line = line.trim();
        if !line.starts_with("publickey ") {
            continue;
        }
        let rest = &line["publickey ".len()..];
        if !rest.starts_with(ssh::CERT_TYPE_ED25519) {
            // plain keys are never accepted for sbc-agent (AuthorizedKeysFile none)
            continue;
        }
        if found.is_some() {
            return Err(AuthError::MultipleCertificates);
        }
        let parsed = ssh::parse_cert_line(rest).map_err(|e| AuthError::Malformed(e.to_string()))?;
        found = Some(parsed);
    }
    let (blob, cert) = found.ok_or(AuthError::NoCertificate)?;
    if &cert.ca_key != ca_key {
        return Err(AuthError::UntrustedCa);
    }
    let vk = VerifyingKey::from_bytes(ca_key).map_err(|_| AuthError::UntrustedCa)?;
    vk.verify(&blob[..cert.signed_len], &Signature::from_bytes(&cert.signature))
        .map_err(|_| AuthError::BadSignature)?;
    if cert.cert_type != ssh::SSH_CERT_TYPE_USER {
        return Err(AuthError::NotUserCert);
    }
    if !cert.principals.iter().any(|p| p == principal) {
        return Err(AuthError::WrongPrincipal);
    }
    if now_secs < cert.valid_after {
        return Err(AuthError::NotYetValid);
    }
    if now_secs >= cert.valid_before {
        return Err(AuthError::Expired);
    }
    if cert.critical_option("force-command").is_none() {
        return Err(AuthError::MissingForceCommand);
    }
    Ok(Presented { serial: cert.serial, cert })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn mint(ca: &SigningKey, principal: &str, after: u64, before: u64, serial: u64) -> String {
        let spec = ssh::UserCertSpec {
            nonce: [1; 32],
            subject_key: SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes(),
            serial,
            key_id: format!("sbc cap={} agent=deploy-agent res=prod-web-02", serial),
            principals: vec![principal.into()],
            valid_after: after,
            valid_before: before,
            force_command: Some("/usr/local/sbin/sbc-gate".into()),
            source_address: None,
            extensions: vec![],
            ca_key: ca.verifying_key().to_bytes(),
        };
        let tbs = ssh::build_tbs(&spec).unwrap();
        let blob = ssh::attach_signature(&tbs, &ca.sign(&tbs).to_bytes());
        format!("publickey {}\n", ssh::cert_line(&blob, ""))
    }

    #[test]
    fn accepts_valid_certificate() {
        let ca = SigningKey::from_bytes(&[42; 32]);
        let info = mint(&ca, "sbc-prod-web-02", 1000, 2000, 12);
        let p = verify_presented(&info, &ca.verifying_key().to_bytes(), "sbc-prod-web-02", 1500).unwrap();
        assert_eq!(p.serial, 12);
    }

    #[test]
    fn rejects_everything_else() {
        let ca = SigningKey::from_bytes(&[42; 32]);
        let other = SigningKey::from_bytes(&[43; 32]);
        let pk = ca.verifying_key().to_bytes();
        let info = mint(&ca, "sbc-prod-web-02", 1000, 2000, 12);
        assert_eq!(verify_presented(&info, &pk, "sbc-prod-web-03", 1500).unwrap_err(), AuthError::WrongPrincipal);
        assert_eq!(verify_presented(&info, &pk, "sbc-prod-web-02", 2000).unwrap_err(), AuthError::Expired);
        assert_eq!(verify_presented(&info, &pk, "sbc-prod-web-02", 999).unwrap_err(), AuthError::NotYetValid);
        assert_eq!(
            verify_presented(&mint(&other, "sbc-prod-web-02", 1000, 2000, 12), &pk, "sbc-prod-web-02", 1500).unwrap_err(),
            AuthError::UntrustedCa
        );
        assert_eq!(verify_presented("password\n", &pk, "sbc-prod-web-02", 1500).unwrap_err(), AuthError::NoCertificate);
        let two = format!("{}{}", info, mint(&ca, "sbc-prod-web-02", 1000, 2000, 13));
        assert_eq!(verify_presented(&two, &pk, "sbc-prod-web-02", 1500).unwrap_err(), AuthError::MultipleCertificates);
        // signature tampering: flip a byte inside the signed region (the serial)
        let line = info.trim().strip_prefix("publickey ").unwrap();
        let (mut blob, _) = ssh::parse_cert_line(line).unwrap();
        blob[110] ^= 1;
        let tampered = format!("publickey {}\n", ssh::cert_line(&blob, ""));
        assert!(matches!(
            verify_presented(&tampered, &pk, "sbc-prod-web-02", 1500).unwrap_err(),
            AuthError::BadSignature | AuthError::Malformed(_) | AuthError::WrongPrincipal
        ));
    }
}
