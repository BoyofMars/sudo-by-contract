//! Library half of `sbc-gate` (the binary is a thin CLI over this), so the
//! enforcement path can be exercised end-to-end in integration tests.
#![forbid(unsafe_code)]

pub mod adapters;
pub mod auth;
pub mod config;
pub mod enroll;
pub mod exec;
pub mod near;
pub mod relay;
