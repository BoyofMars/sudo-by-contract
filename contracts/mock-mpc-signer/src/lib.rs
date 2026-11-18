//! # TEST-ONLY mock of NEAR's MPC signer
//!
//! A stand-in for `v1.signer-prod.testnet` that the sandbox integration tests
//! (`contracts/sbc-policy/tests/sandbox.rs`) deploy next to the policy
//! contract. It implements only the two methods the policy contract calls,
//! with the same argument and result shapes:
//!
//! * `derived_public_key({ path, predecessor, domain_id })` returns
//!   `"ed25519:<base58>"`, which the policy stores as an environment's SSH CA;
//! * `sign({ request: { path, payload_v2: { "Eddsa": "<hex>" }, domain_id } })`
//!   with 1 yoctoNEAR attached returns
//!   `{ "scheme": "Ed25519", "signature": [<64 bytes>] }`, which the policy's
//!   `on_signed` callback verifies against that CA before issuing anything.
//!
//! Like the real network, the key is derived from (calling account, path), so
//! each caller gets its own key per path and only that caller can obtain
//! signatures under it. Unlike the real network there is no threshold, no TEE
//! and no secret: every key is derived from [`TEST_ONLY_ROOT_SEED`], which is
//! public. Anyone who reads this file can sign as any derived key, so this
//! contract must never be deployed anywhere but a local sandbox.
//!
//! The real signer answers asynchronously (yield/resume). This mock returns
//! synchronously; the policy contract cannot tell the difference because it
//! only consumes the result in its callback.

use ed25519_dalek::{Signer, SigningKey};
use near_sdk::{env, near, require, AccountId, CurveType, NearToken, PublicKey};

/// TEST-ONLY root seed. It is public, so every key derived from it is public too.
pub const TEST_ONLY_ROOT_SEED: [u8; 32] = *b"sbc mock mpc: TEST ONLY, PUBLIC!";

/// The real signer's Ed25519 domain (domain 0 is secp256k1).
pub const ED25519_DOMAIN_ID: u64 = 1;

/// The real signer accepts Ed25519 payloads of 32 to 1232 bytes.
const EDDSA_PAYLOAD_BYTES: core::ops::RangeInclusive<usize> = 32..=1232;

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub enum Payload {
    Ecdsa(String),
    Eddsa(String),
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct SignRequest {
    pub path: String,
    pub payload_v2: Payload,
    pub domain_id: u64,
}

/// Same wire shape as the real `SignatureResponse` (`#[serde(tag = "scheme")]`).
#[near(serializers = [json])]
#[serde(tag = "scheme")]
#[derive(Clone, Debug)]
pub enum SignatureResponse {
    Ed25519 { signature: Vec<u8> },
}

#[near(contract_state)]
#[derive(Default)]
pub struct MockMpcSigner {}

/// The signing key for (caller, path): sha256(seed || caller || "," || path).
pub fn derive_signing_key(predecessor: &AccountId, path: &str) -> SigningKey {
    let mut m = Vec::with_capacity(TEST_ONLY_ROOT_SEED.len() + predecessor.as_str().len() + 1 + path.len());
    m.extend_from_slice(&TEST_ONLY_ROOT_SEED);
    m.extend_from_slice(predecessor.as_str().as_bytes());
    m.push(b',');
    m.extend_from_slice(path.as_bytes());
    SigningKey::from_bytes(&env::sha256_array(&m))
}

fn require_ed25519_domain(domain_id: u64) {
    require!(domain_id == ED25519_DOMAIN_ID, "the mock signer implements only the Ed25519 domain (1)");
}

#[near]
impl MockMpcSigner {
    /// `predecessor` defaults to the caller, as on the real signer.
    pub fn derived_public_key(&self, path: String, predecessor: Option<AccountId>, domain_id: Option<u64>) -> PublicKey {
        require_ed25519_domain(domain_id.unwrap_or(0));
        let predecessor = predecessor.unwrap_or_else(env::predecessor_account_id);
        let vk = derive_signing_key(&predecessor, &path).verifying_key();
        PublicKey::from_parts(CurveType::ED25519, vk.to_bytes().to_vec()).unwrap()
    }

    /// Signs `payload_v2.Eddsa` with the key derived for (caller, path).
    #[payable]
    pub fn sign(&mut self, request: SignRequest) -> SignatureResponse {
        require!(env::attached_deposit() >= NearToken::from_yoctonear(1), "attach at least 1 yoctoNEAR");
        require_ed25519_domain(request.domain_id);
        let payload = match request.payload_v2 {
            Payload::Eddsa(h) => hex::decode(h).unwrap_or_else(|_| env::panic_str("Eddsa payload must be hex")),
            Payload::Ecdsa(_) => env::panic_str("Ecdsa payloads belong to the secp256k1 domain"),
        };
        require!(EDDSA_PAYLOAD_BYTES.contains(&payload.len()), "Eddsa payload must be 32-1232 bytes");
        let signature = derive_signing_key(&env::predecessor_account_id(), &request.path).sign(&payload);
        SignatureResponse::Ed25519 { signature: signature.to_bytes().to_vec() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use near_sdk::serde_json;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    const PATH: &str = "sbc/ssh-user-ca/v1/production";

    fn as_caller(caller: &str, deposit_yocto: u128) {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(caller.parse().unwrap())
            .attached_deposit(NearToken::from_yoctonear(deposit_yocto))
            .build());
    }

    fn eddsa(msg: &[u8]) -> SignRequest {
        SignRequest { path: PATH.into(), payload_v2: Payload::Eddsa(hex::encode(msg)), domain_id: ED25519_DOMAIN_ID }
    }

    #[test]
    fn signatures_verify_against_the_derived_key_in_the_policy_wire_format() {
        as_caller("sbc.test.near", 1);
        let mut c = MockMpcSigner::default();
        let pk = c.derived_public_key(PATH.into(), None, Some(1));
        assert!(serde_json::to_string(&pk).unwrap().starts_with("\"ed25519:"));
        let msg = [7u8; 300];
        let out = serde_json::to_value(c.sign(eddsa(&msg))).unwrap();
        assert_eq!(out["scheme"], "Ed25519");
        let sig: Vec<u8> = out["signature"].as_array().unwrap().iter().map(|b| b.as_u64().unwrap() as u8).collect();
        let vk = VerifyingKey::from_bytes(pk.as_bytes()[1..].try_into().unwrap()).unwrap();
        vk.verify(&msg, &Signature::from_slice(&sig).unwrap()).unwrap();
    }

    #[test]
    fn keys_are_bound_to_the_caller_and_the_path() {
        as_caller("sbc.test.near", 1);
        let c = MockMpcSigner::default();
        let mine = c.derived_public_key(PATH.into(), None, Some(1));
        assert_eq!(mine, c.derived_public_key(PATH.into(), Some("sbc.test.near".parse().unwrap()), Some(1)));
        assert_ne!(mine, c.derived_public_key(PATH.into(), Some("mallory.test.near".parse().unwrap()), Some(1)));
        assert_ne!(mine, c.derived_public_key("sbc/ssh-user-ca/v1/staging".into(), None, Some(1)));
    }

    #[test]
    #[should_panic(expected = "attach at least 1 yoctoNEAR")]
    fn signing_needs_a_deposit() {
        as_caller("sbc.test.near", 0);
        MockMpcSigner::default().sign(eddsa(&[1u8; 64]));
    }

    #[test]
    #[should_panic(expected = "only the Ed25519 domain")]
    fn other_domains_are_refused() {
        as_caller("sbc.test.near", 1);
        MockMpcSigner::default().derived_public_key(PATH.into(), None, Some(0));
    }
}
