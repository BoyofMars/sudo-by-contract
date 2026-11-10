//! The gate's decision logic in the browser.
//!
//! This is not a re-implementation: it links `sbc-core`, the same crate the
//! `sbc-gate` binary and the policy contract are built from. The landing
//! page's "Try to escape" playground loads this module and shows visitors
//! exactly what an enrolled host would do with the command they type.
//!
//! ABI (no wasm-bindgen, nothing to trust but ~50 lines):
//!   alloc(len) -> ptr            reserve `len` bytes for the input
//!   evaluate(ptr, len) -> u64    returns (out_ptr << 32) | out_len, UTF-8 JSON
//!   dealloc(ptr, len)            free either buffer

use sbc_core::action::parse_command;
use sbc_core::plan::{argv, ServiceManager};
use sbc_core::redact::{program_of, redact_command};

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn arr(v: &[String]) -> String {
    format!("[{}]", v.iter().map(|s| esc(s)).collect::<Vec<_>>().join(","))
}

/// Pure function used by the export (and by tests).
pub fn evaluate_json(command: &str) -> String {
    let redacted = esc(&redact_command(command));
    let program = esc(&program_of(command));
    match parse_command(command) {
        Ok(p) => format!(
            "{{\"ok\":true,\"action\":{},\"kind\":{},\"target\":{},\"describe\":{},\"read_only\":{},\"via_sudo\":{},\"log_lines\":{},\"argv_systemd\":{},\"argv_supervisor\":{},\"program\":{},\"redacted\":{}}}",
            esc(&p.action.canonical()),
            esc(p.action.kind.as_str()),
            esc(&p.action.target),
            esc(&p.action.describe()),
            p.action.kind.is_read_only(),
            p.via_sudo,
            p.params.log_lines,
            arr(&argv(ServiceManager::Systemd, &p)),
            arr(&argv(ServiceManager::Supervisor, &p)),
            program,
            redacted
        ),
        Err(r) => format!(
            "{{\"ok\":false,\"code\":{},\"message\":{},\"program\":{},\"redacted\":{}}}",
            esc(r.code()),
            esc(&r.message()),
            program,
            redacted
        ),
    }
}

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut buf: Vec<u8> = Vec::with_capacity(len.max(1));
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr`/`len` must come from `alloc` (or a previous `evaluate` result).
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, 0, len.max(1)));
}

/// # Safety
/// `ptr`/`len` must describe an `alloc`ed buffer holding the command bytes.
#[no_mangle]
pub unsafe extern "C" fn evaluate(ptr: *const u8, len: usize) -> u64 {
    let bytes = std::slice::from_raw_parts(ptr, len);
    let out = match std::str::from_utf8(bytes) {
        Ok(cmd) => evaluate_json(cmd),
        Err(_) => "{\"ok\":false,\"code\":\"invalid_utf8\",\"message\":\"command is not valid UTF-8\",\"program\":\"\",\"redacted\":\"\"}".to_string(),
    };
    let mut out = out.into_bytes();
    out.shrink_to_fit();
    let (p, l) = (out.as_mut_ptr(), out.len());
    std::mem::forget(out);
    ((p as u64) << 32) | (l as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_and_denied_shapes() {
        let ok = evaluate_json("sudo systemctl restart checkout-api");
        assert!(ok.starts_with("{\"ok\":true,\"action\":\"service.restart:checkout-api\""));
        assert!(ok.contains("\"argv_systemd\":[\"/usr/bin/sudo\",\"-n\",\"/usr/bin/systemctl\",\"restart\",\"checkout-api\"]"));
        let no = evaluate_json("sudo cat /etc/shadow");
        assert!(no.contains("\"code\":\"no_adapter\""));
        let inj = evaluate_json("systemctl restart a; id \"x\"");
        assert!(inj.contains("\"code\":\"shell_metacharacter\""));
        assert!(inj.contains("\\\""), "quotes in messages are escaped: {inj}");
    }
}
