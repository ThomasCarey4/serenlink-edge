use alloc::vec::Vec;

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

const CONTEXT: &[u8] = b"serenlink-auth-v2";

/// The bytes a device signs to prove its identity for one session, bound to the TLS channel
/// it is on (spec 3.2), so an Auth captured on one channel is worthless on any other. Each
/// field is length-prefixed so that no two different field sets produce the same message.
pub fn auth_message(nonce: &[u8], device_id: &[u8], hostname: &str, binding: &[u8; 32]) -> Vec<u8> {
    crate::lp::signed_message(CONTEXT, &[nonce, device_id, hostname.as_bytes(), binding])
}

/// Holds a device's private key. The shell decides where the key lives.
pub trait Signer {
    fn sign(&self, message: &[u8]) -> [u8; 64];
    fn public_key(&self) -> [u8; 32];
}

/// A signer backed by key bytes in memory.
pub struct KeySigner {
    key: SigningKey,
}

impl KeySigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }
}

impl Signer for KeySigner {
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }

    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}
