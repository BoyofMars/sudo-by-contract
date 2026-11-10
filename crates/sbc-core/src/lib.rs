//! Shared primitives for Sudo by Contract.
//!
//! This crate is compiled into two very different places:
//!
//! * the NEAR policy contract (wasm32), which *builds* the exact bytes of every
//!   OpenSSH certificate it asks the NEAR MPC network to sign, and
//! * `sbc-gate`, the enforcement binary on enrolled hosts, which *parses* the
//!   presented certificate and canonicalises the command the agent sent.
//!
//! Keeping both halves in one crate means "what was approved" and "what is
//! enforced" are defined by the same code.
#![forbid(unsafe_code)]

pub mod action;
pub mod redact;
pub mod ssh;
pub mod validate;

pub use action::{parse_command, Action, ActionKind, ParsedCommand};
pub use ssh::{CertError, ParsedCert, UserCertSpec};
