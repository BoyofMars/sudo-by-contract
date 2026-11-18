//! Pay per session.
//!
//! A server's owner prices its capabilities; an agent pays for each one it
//! is actually issued. An agent signs with a function-call access key, and
//! NEAR does not let such a key attach a deposit, so payment is a prepaid
//! escrow kept by this contract:
//!
//! * anyone funds an agent with `fund_agent` from an ordinary account; the
//!   first funder becomes the agent's wallet, the only account that can
//!   withdraw what is left;
//! * `request_access` *holds* the resource's price from that balance (and
//!   counts it against the resource's daily quota for the agent);
//! * the MPC-signed certificate being issued *settles* the hold: the amount
//!   is transferred to the resource's payee in the same callback;
//! * a request that ends without a certificate (denied, approval expired,
//!   cancelled, revoked, signing failed) *releases* the hold.
//!
//! Storage lives under its own `$`-prefixed keys, outside the contract's
//! state struct, so adding billing needs no state migration.

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U128;
use near_sdk::{env, near};

/// One NEAR in yoctoNEAR.
pub const ONE_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
/// Smallest top-up `fund_agent` accepts (covers the purse's storage).
pub const MIN_FUNDING: u128 = ONE_NEAR / 100;

#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Pricing {
    /// yoctoNEAR per issued capability.
    pub price: u128,
    /// Who is paid when a certificate is issued: the server owner's account.
    pub payee: String,
    /// Paid capabilities one agent may hold or use per UTC day on this resource (0 = no limit).
    pub daily_quota: u32,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct HeldPayment {
    pub request_id: u64,
    pub amount: u128,
    pub payee: String,
    pub resource_id: String,
    pub day: u64,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Purse {
    pub available: u128,
    pub held: Vec<HeldPayment>,
    pub spent: u128,
    pub wallet: Option<String>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct PricingView {
    pub resource_id: String,
    pub price: U128,
    pub payee: String,
    pub daily_quota: u32,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct HoldView {
    pub request_id: u64,
    pub amount: U128,
    pub payee: String,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct PurseView {
    pub agent_id: String,
    /// Spendable now (includes holds whose requests ended without a certificate).
    pub available: U128,
    pub held: U128,
    pub spent: U128,
    pub wallet: Option<String>,
    pub holds: Vec<HoldView>,
}

fn key(tag: &str, id: &str) -> Vec<u8> {
    format!("${}:{}", tag, id).into_bytes()
}

fn read<T: BorshDeserialize>(k: &[u8]) -> Option<T> {
    env::storage_read(k).and_then(|b| T::try_from_slice(&b).ok())
}

fn write<T: BorshSerialize>(k: &[u8], v: &T) {
    env::storage_write(k, &near_sdk::borsh::to_vec(v).unwrap());
}

pub fn pricing(resource_id: &str) -> Option<Pricing> {
    read(&key("p", resource_id))
}

pub fn set_pricing(resource_id: &str, p: Option<&Pricing>) {
    match p {
        Some(p) => write(&key("p", resource_id), p),
        None => {
            env::storage_remove(&key("p", resource_id));
        }
    }
}

pub fn purse(agent_id: &str) -> Purse {
    read(&key("w", agent_id)).unwrap_or_default()
}

pub fn save_purse(agent_id: &str, p: &Purse) {
    write(&key("w", agent_id), p);
}

fn quota_key(resource_id: &str, agent_id: &str, day: u64) -> Vec<u8> {
    key("d", &format!("{}\u{0}{}\u{0}{}", resource_id, agent_id, day))
}

pub fn quota_used(resource_id: &str, agent_id: &str, day: u64) -> u32 {
    read(&quota_key(resource_id, agent_id, day)).unwrap_or(0)
}

pub fn set_quota_used(resource_id: &str, agent_id: &str, day: u64, n: u32) {
    let k = quota_key(resource_id, agent_id, day);
    if n == 0 {
        env::storage_remove(&k);
    } else {
        write(&k, &n);
    }
}

pub fn utc_day(now_ms: u64) -> u64 {
    now_ms / 86_400_000
}

/// `0.0100 NEAR`
pub fn near_str(yocto: u128) -> String {
    let tenths_of_milli = yocto / (ONE_NEAR / 10_000);
    format!("{}.{:04} NEAR", tenths_of_milli / 10_000, tenths_of_milli % 10_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_read_like_money() {
        assert_eq!(near_str(ONE_NEAR / 100), "0.0100 NEAR");
        assert_eq!(near_str(ONE_NEAR + ONE_NEAR / 2), "1.5000 NEAR");
        assert_eq!(near_str(0), "0.0000 NEAR");
    }
}
