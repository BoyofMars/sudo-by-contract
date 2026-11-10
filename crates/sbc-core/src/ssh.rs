//! OpenSSH user certificates (`ssh-ed25519-cert-v01@openssh.com`).
//!
//! Wire format (PROTOCOL.certkeys in the OpenSSH source tree):
//!
//! ```text
//! string    "ssh-ed25519-cert-v01@openssh.com"
//! string    nonce
//! string    pk                      (32-byte Ed25519 public key of the subject)
//! uint64    serial
//! uint32    type                    (1 = user)
//! string    key id
//! string    valid principals        (packed list of strings)
//! uint64    valid after             (seconds since epoch)
//! uint64    valid before
//! string    critical options        (packed name/data pairs, sorted by name)
//! string    extensions              (packed name/data pairs, sorted by name)
//! string    reserved
//! string    signature key           (CA public key blob)
//! string    signature               (signature over every preceding byte)
//! ```
//!
//! Everything before `signature` is the to-be-signed (TBS) message. The policy
//! contract builds the TBS, the NEAR MPC network signs it with an Ed25519 key
//! derived for the contract's account, and the contract appends the signature.

use base64::Engine;

use crate::validate;

pub const CERT_TYPE_ED25519: &str = "ssh-ed25519-cert-v01@openssh.com";
pub const KEY_TYPE_ED25519: &str = "ssh-ed25519";
pub const SSH_CERT_TYPE_USER: u32 = 1;

/// Critical options sshd understands for user certificates. sshd refuses a
/// certificate carrying any critical option it does not recognise, so we
/// refuse to build one.
pub const KNOWN_CRITICAL_OPTIONS: &[&str] = &["force-command", "source-address", "verify-required"];

/// Extensions we are willing to grant. By default Sudo by Contract grants
/// none: no PTY, no port/agent/X11 forwarding, no ~/.ssh/rc.
pub const KNOWN_EXTENSIONS: &[&str] = &[
    "no-touch-required",
    "permit-X11-forwarding",
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-pty",
    "permit-user-rc",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertError {
    InvalidPrincipal(String),
    NoPrincipals,
    InvalidValidity,
    InvalidKeyId,
    InvalidForceCommand,
    InvalidSourceAddress,
    UnknownExtension(String),
    Truncated,
    TrailingBytes,
    WrongType(String),
    BadLength(&'static str),
    UnsortedOptions,
    Utf8,
    Base64,
}

impl core::fmt::Display for CertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CertError {}

// ---------------------------------------------------------------- wire format

#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(512) }
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(b);
        self
    }
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
    pub fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CertError> {
        let end = self.pos.checked_add(n).ok_or(CertError::Truncated)?;
        if end > self.buf.len() {
            return Err(CertError::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    pub fn u32(&mut self) -> Result<u32, CertError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn u64(&mut self) -> Result<u64, CertError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }
    pub fn bytes(&mut self) -> Result<&'a [u8], CertError> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub fn string(&mut self) -> Result<String, CertError> {
        let b = self.bytes()?;
        core::str::from_utf8(b).map(String::from).map_err(|_| CertError::Utf8)
    }
    pub fn fixed32(&mut self, what: &'static str) -> Result<[u8; 32], CertError> {
        let b = self.bytes()?;
        if b.len() != 32 {
            return Err(CertError::BadLength(what));
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(b);
        Ok(a)
    }
}

/// `string "ssh-ed25519" || string pk` — the public key blob.
pub fn ed25519_key_blob(pk: &[u8; 32]) -> Vec<u8> {
    let mut w = Writer::new();
    w.str(KEY_TYPE_ED25519).bytes(pk);
    w.into_inner()
}

/// `ssh-ed25519 AAAA... comment` — as written to `TrustedUserCAKeys` or `id_ed25519.pub`.
pub fn ed25519_pubkey_line(pk: &[u8; 32], comment: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(ed25519_key_blob(pk));
    if comment.is_empty() {
        format!("{} {}", KEY_TYPE_ED25519, b64)
    } else {
        format!("{} {} {}", KEY_TYPE_ED25519, b64, comment)
    }
}

/// Parse `ssh-ed25519 AAAA... [comment]` into the raw 32-byte key.
pub fn parse_ed25519_pubkey_line(line: &str) -> Result<[u8; 32], CertError> {
    let mut parts = line.split_whitespace();
    let ty = parts.next().ok_or(CertError::Truncated)?;
    if ty != KEY_TYPE_ED25519 {
        return Err(CertError::WrongType(ty.into()));
    }
    let b64 = parts.next().ok_or(CertError::Truncated)?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| CertError::Base64)?;
    let mut r = Reader::new(&blob);
    let inner_ty = r.string()?;
    if inner_ty != KEY_TYPE_ED25519 {
        return Err(CertError::WrongType(inner_ty));
    }
    let pk = r.fixed32("ed25519 public key")?;
    if !r.is_empty() {
        return Err(CertError::TrailingBytes);
    }
    Ok(pk)
}

// ------------------------------------------------------------------- building

/// Everything the policy contract decides about a certificate. Nothing in
/// here is chosen by the agent except `subject_key` (its ephemeral public key)
/// and, when the policy allows it, `source_address`.
#[derive(Debug, Clone)]
pub struct UserCertSpec {
    pub nonce: [u8; 32],
    pub subject_key: [u8; 32],
    pub serial: u64,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    pub force_command: Option<String>,
    pub source_address: Option<String>,
    pub extensions: Vec<String>,
    pub ca_key: [u8; 32],
}

fn pack_options(pairs: &mut Vec<(String, Option<String>)>) -> Vec<u8> {
    // PROTOCOL.certkeys: options must be lexically ordered by name, and each
    // name may appear only once.
    pairs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    pairs.dedup_by(|a, b| a.0 == b.0);
    let mut w = Writer::new();
    for (name, value) in pairs.iter() {
        w.str(name);
        match value {
            // data is itself an SSH string wrapping the value
            Some(v) => {
                let mut inner = Writer::new();
                inner.str(v);
                w.bytes(&inner.into_inner());
            }
            None => {
                w.bytes(&[]);
            }
        }
    }
    w.into_inner()
}

/// Build the to-be-signed certificate body.
pub fn build_tbs(spec: &UserCertSpec) -> Result<Vec<u8>, CertError> {
    if spec.principals.is_empty() {
        return Err(CertError::NoPrincipals);
    }
    for p in &spec.principals {
        if !validate::is_principal(p) {
            return Err(CertError::InvalidPrincipal(p.clone()));
        }
    }
    if spec.valid_before <= spec.valid_after {
        return Err(CertError::InvalidValidity);
    }
    if spec.key_id.is_empty()
        || spec.key_id.len() > 200
        || !spec.key_id.bytes().all(|c| (0x20..0x7f).contains(&c))
    {
        return Err(CertError::InvalidKeyId);
    }

    let mut crit: Vec<(String, Option<String>)> = Vec::new();
    if let Some(fc) = &spec.force_command {
        if fc.is_empty() || fc.len() > 256 || !fc.bytes().all(|c| (0x20..0x7f).contains(&c)) {
            return Err(CertError::InvalidForceCommand);
        }
        crit.push(("force-command".into(), Some(fc.clone())));
    }
    if let Some(sa) = &spec.source_address {
        if !validate::is_source_address_list(sa) {
            return Err(CertError::InvalidSourceAddress);
        }
        crit.push(("source-address".into(), Some(sa.clone())));
    }

    let mut ext: Vec<(String, Option<String>)> = Vec::new();
    for e in &spec.extensions {
        if !KNOWN_EXTENSIONS.contains(&e.as_str()) {
            return Err(CertError::UnknownExtension(e.clone()));
        }
        ext.push((e.clone(), None));
    }

    let mut principals = Writer::new();
    for p in &spec.principals {
        principals.str(p);
    }

    let mut w = Writer::new();
    w.str(CERT_TYPE_ED25519)
        .bytes(&spec.nonce)
        .bytes(&spec.subject_key)
        .u64(spec.serial)
        .u32(SSH_CERT_TYPE_USER)
        .str(&spec.key_id)
        .bytes(&principals.into_inner())
        .u64(spec.valid_after)
        .u64(spec.valid_before)
        .bytes(&pack_options(&mut crit))
        .bytes(&pack_options(&mut ext))
        .bytes(&[]) // reserved
        .bytes(&ed25519_key_blob(&spec.ca_key));
    Ok(w.into_inner())
}

/// Append the CA signature to a TBS body, producing the full certificate blob.
pub fn attach_signature(tbs: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut sig = Writer::new();
    sig.str(KEY_TYPE_ED25519).bytes(signature);
    let mut w = Writer::new();
    w.raw(tbs).bytes(&sig.into_inner());
    w.into_inner()
}

/// `ssh-ed25519-cert-v01@openssh.com AAAA... comment` — the `id_ed25519-cert.pub` line.
pub fn cert_line(blob: &[u8], comment: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
    if comment.is_empty() {
        format!("{} {}", CERT_TYPE_ED25519, b64)
    } else {
        format!("{} {} {}", CERT_TYPE_ED25519, b64, comment)
    }
}

// -------------------------------------------------------------------- parsing

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCert {
    pub nonce: Vec<u8>,
    pub subject_key: [u8; 32],
    pub serial: u64,
    pub cert_type: u32,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    /// (name, inner value) — value already unwrapped from its SSH string.
    pub critical_options: Vec<(String, String)>,
    pub extensions: Vec<String>,
    pub ca_key: [u8; 32],
    pub signature: [u8; 64],
    /// Length of the signed prefix of the blob.
    pub signed_len: usize,
}

impl ParsedCert {
    pub fn critical_option(&self, name: &str) -> Option<&str> {
        self.critical_options
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

fn parse_options(data: &[u8], unwrap_values: bool) -> Result<Vec<(String, String)>, CertError> {
    let mut r = Reader::new(data);
    let mut out: Vec<(String, String)> = Vec::new();
    while !r.is_empty() {
        let name = r.string()?;
        let raw = r.bytes()?;
        let value = if unwrap_values && !raw.is_empty() {
            let mut inner = Reader::new(raw);
            let v = inner.string()?;
            if !inner.is_empty() {
                return Err(CertError::TrailingBytes);
            }
            v
        } else if raw.is_empty() {
            String::new()
        } else {
            core::str::from_utf8(raw).map_err(|_| CertError::Utf8)?.into()
        };
        if let Some((prev, _)) = out.last() {
            if prev.as_bytes() >= name.as_bytes() {
                return Err(CertError::UnsortedOptions);
            }
        }
        out.push((name, value));
    }
    Ok(out)
}

/// Parse a full certificate blob. Does NOT verify the signature: callers must
/// verify `signature` over `blob[..signed_len]` against a trusted `ca_key`.
pub fn parse_cert(blob: &[u8]) -> Result<ParsedCert, CertError> {
    let mut r = Reader::new(blob);
    let ty = r.string()?;
    if ty != CERT_TYPE_ED25519 {
        return Err(CertError::WrongType(ty));
    }
    let nonce = r.bytes()?.to_vec();
    let subject_key = r.fixed32("subject key")?;
    let serial = r.u64()?;
    let cert_type = r.u32()?;
    let key_id = r.string()?;
    let principals_raw = r.bytes()?;
    let mut principals = Vec::new();
    let mut pr = Reader::new(principals_raw);
    while !pr.is_empty() {
        principals.push(pr.string()?);
    }
    let valid_after = r.u64()?;
    let valid_before = r.u64()?;
    let critical_options = parse_options(r.bytes()?, true)?;
    let extensions = parse_options(r.bytes()?, false)?
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    let _reserved = r.bytes()?;
    let ca_blob = r.bytes()?;
    let mut cr = Reader::new(ca_blob);
    let ca_ty = cr.string()?;
    if ca_ty != KEY_TYPE_ED25519 {
        return Err(CertError::WrongType(ca_ty));
    }
    let ca_key = cr.fixed32("ca key")?;
    if !cr.is_empty() {
        return Err(CertError::TrailingBytes);
    }
    let signed_len = r.pos();
    let sig_blob = r.bytes()?;
    if !r.is_empty() {
        return Err(CertError::TrailingBytes);
    }
    let mut sr = Reader::new(sig_blob);
    let sig_ty = sr.string()?;
    if sig_ty != KEY_TYPE_ED25519 {
        return Err(CertError::WrongType(sig_ty));
    }
    let sig_bytes = sr.bytes()?;
    if sig_bytes.len() != 64 || !sr.is_empty() {
        return Err(CertError::BadLength("signature"));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(sig_bytes);
    Ok(ParsedCert {
        nonce,
        subject_key,
        serial,
        cert_type,
        key_id,
        principals,
        valid_after,
        valid_before,
        critical_options,
        extensions,
        ca_key,
        signature,
        signed_len,
    })
}

/// Parse a `ssh-ed25519-cert-v01@openssh.com AAAA...` line (as found in
/// `id_ed25519-cert.pub` or in sshd's `ExposeAuthInfo` file after the
/// `publickey ` prefix).
pub fn parse_cert_line(line: &str) -> Result<(Vec<u8>, ParsedCert), CertError> {
    let mut parts = line.split_whitespace();
    let mut ty = parts.next().ok_or(CertError::Truncated)?;
    if ty == "publickey" {
        ty = parts.next().ok_or(CertError::Truncated)?;
    }
    if ty != CERT_TYPE_ED25519 {
        return Err(CertError::WrongType(ty.into()));
    }
    let b64 = parts.next().ok_or(CertError::Truncated)?;
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| CertError::Base64)?;
    let parsed = parse_cert(&blob)?;
    Ok((blob, parsed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    fn spec(ca: &SigningKey, subject: &SigningKey) -> UserCertSpec {
        UserCertSpec {
            nonce: [7u8; 32],
            subject_key: subject.verifying_key().to_bytes(),
            serial: 1042,
            key_id: "sbc cap=1042 agent=deploy-agent res=prod-web-02".into(),
            principals: vec!["sbc-prod-web-02".into()],
            valid_after: 1_800_000_000,
            valid_before: 1_800_000_600,
            force_command: Some("/usr/local/sbin/sbc-gate".into()),
            source_address: None,
            extensions: vec![],
            ca_key: ca.verifying_key().to_bytes(),
        }
    }

    #[test]
    fn roundtrip_and_signature() {
        let ca = SigningKey::from_bytes(&[1u8; 32]);
        let subject = SigningKey::from_bytes(&[2u8; 32]);
        let s = spec(&ca, &subject);
        let tbs = build_tbs(&s).unwrap();
        let sig = ca.sign(&tbs).to_bytes();
        let blob = attach_signature(&tbs, &sig);
        let p = parse_cert(&blob).unwrap();
        assert_eq!(p.serial, 1042);
        assert_eq!(p.cert_type, SSH_CERT_TYPE_USER);
        assert_eq!(p.principals, vec!["sbc-prod-web-02".to_string()]);
        assert_eq!(p.valid_after, 1_800_000_000);
        assert_eq!(p.valid_before, 1_800_000_600);
        assert_eq!(p.critical_option("force-command"), Some("/usr/local/sbin/sbc-gate"));
        assert!(p.extensions.is_empty());
        assert_eq!(p.signed_len, tbs.len());
        assert_eq!(&blob[..p.signed_len], &tbs[..]);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&p.ca_key).unwrap();
        vk.verify(&blob[..p.signed_len], &ed25519_dalek::Signature::from_bytes(&p.signature))
            .unwrap();
        // fits comfortably inside the MPC EdDSA payload bound (1232 bytes)
        assert!(tbs.len() < 600, "tbs is {} bytes", tbs.len());
    }

    #[test]
    fn options_are_sorted() {
        let ca = SigningKey::from_bytes(&[1u8; 32]);
        let subject = SigningKey::from_bytes(&[2u8; 32]);
        let mut s = spec(&ca, &subject);
        s.source_address = Some("10.0.0.0/8".into());
        s.extensions = vec!["permit-pty".into(), "no-touch-required".into()];
        let tbs = build_tbs(&s).unwrap();
        let blob = attach_signature(&tbs, &[0u8; 64]);
        let p = parse_cert(&blob).unwrap();
        let names: Vec<_> = p.critical_options.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["force-command", "source-address"]);
        assert_eq!(p.extensions, vec!["no-touch-required", "permit-pty"]);
    }

    #[test]
    fn rejects_bad_specs() {
        let ca = SigningKey::from_bytes(&[1u8; 32]);
        let subject = SigningKey::from_bytes(&[2u8; 32]);
        let mut s = spec(&ca, &subject);
        s.principals = vec!["a,b".into()];
        assert!(matches!(build_tbs(&s), Err(CertError::InvalidPrincipal(_))));
        let mut s = spec(&ca, &subject);
        s.valid_before = s.valid_after;
        assert_eq!(build_tbs(&s), Err(CertError::InvalidValidity));
        let mut s = spec(&ca, &subject);
        s.extensions = vec!["permit-everything".into()];
        assert!(matches!(build_tbs(&s), Err(CertError::UnknownExtension(_))));
        let mut s = spec(&ca, &subject);
        s.principals.clear();
        assert_eq!(build_tbs(&s), Err(CertError::NoPrincipals));
    }

    #[test]
    fn rejects_trailing_and_truncated() {
        let ca = SigningKey::from_bytes(&[1u8; 32]);
        let subject = SigningKey::from_bytes(&[2u8; 32]);
        let tbs = build_tbs(&spec(&ca, &subject)).unwrap();
        let mut blob = attach_signature(&tbs, &[0u8; 64]);
        blob.push(0);
        assert_eq!(parse_cert(&blob), Err(CertError::TrailingBytes));
        blob.truncate(blob.len() - 10);
        assert_eq!(parse_cert(&blob), Err(CertError::Truncated));
    }

    #[test]
    fn pubkey_lines_roundtrip() {
        let k = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
        let line = ed25519_pubkey_line(&k, "sbc-ca");
        assert!(line.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"));
        assert_eq!(parse_ed25519_pubkey_line(&line).unwrap(), k);
    }

    #[test]
    fn cert_line_with_publickey_prefix() {
        let ca = SigningKey::from_bytes(&[1u8; 32]);
        let subject = SigningKey::from_bytes(&[2u8; 32]);
        let tbs = build_tbs(&spec(&ca, &subject)).unwrap();
        let blob = attach_signature(&tbs, &ca.sign(&tbs).to_bytes());
        let line = format!("publickey {}", cert_line(&blob, ""));
        let (b2, p) = parse_cert_line(&line).unwrap();
        assert_eq!(b2, blob);
        assert_eq!(p.serial, 1042);
    }
}
