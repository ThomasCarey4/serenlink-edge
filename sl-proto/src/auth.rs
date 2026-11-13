use alloc::vec::Vec;

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

const CONTEXT: &[u8] = b"serenlink-auth-v1";

/// The bytes a device signs to prove its identity for one session. Each field is
/// length-prefixed so that no two different field sets produce the same message.
pub fn auth_message(nonce: &[u8], device_id: &[u8], hostname: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONTEXT.len() + nonce.len() + device_id.len() + hostname.len() + 12);
    out.extend_from_slice(CONTEXT);
    for field in [nonce, device_id, hostname.as_bytes()] {
        out.extend_from_slice(&(field.len() as u32).to_le_bytes());
        out.extend_from_slice(field);
    }
    out
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
