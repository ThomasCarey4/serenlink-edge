//! The trust store (spec 5): which release keys certify servers, which certificates are
//! revoked, and the TLS roots the device shell hands its TLS stack.
use alloc::vec::Vec;

use ed25519_dalek::{Signer as _, SigningKey};
use prost::Message;

use crate::auth::verify;
use crate::lp::signed_message;

pub const MAX_RELEASE_KEYS: usize = 3;
pub const MAX_REVOKED: usize = 64;
pub const MAX_TLS_ROOTS: usize = 4;
pub const MAX_TLS_ROOT_BYTES: usize = 2048;
/// A whole `SignedTrustStore`, encoded.
pub const MAX_TRUST_STORE_BYTES: usize = 12 * 1024;

const CONTEXT: &[u8] = b"serenlink-trust-store-v1";

#[derive(Clone, PartialEq, prost::Message)]
pub struct ReleaseKey {
    #[prost(uint32, tag = "1")]
    pub id: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub pubkey: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct TrustStore {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(message, repeated, tag = "2")]
    pub release_keys: Vec<ReleaseKey>,
    #[prost(uint64, tag = "3")]
    pub min_serial: u64,
    #[prost(uint64, repeated, tag = "4")]
    pub revoked_serials: Vec<u64>,
    /// DER certificates, for the device shell's TLS stack.
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub tls_roots: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignedTrustStore {
    #[prost(bytes = "vec", tag = "1")]
    pub body: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub release_key_id: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub sig: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustError {
    Malformed,
    Bounds,
    UnknownReleaseKey,
    BadSignature,
    /// Its version is not above the active store's.
    NotNewer,
}

fn message(body: &[u8]) -> Vec<u8> {
    signed_message(CONTEXT, &[body])
}

impl TrustStore {
    fn check_bounds(&self) -> Result<(), TrustError> {
        let keys = &self.release_keys;
        let unique = keys
            .iter()
            .enumerate()
            .all(|(i, k)| keys[..i].iter().all(|other| other.id != k.id));
        let ok = self.version > 0
            && !keys.is_empty()
            && keys.len() <= MAX_RELEASE_KEYS
            && keys.iter().all(|k| k.pubkey.len() == 32)
            && unique
            && self.revoked_serials.len() <= MAX_REVOKED
            && self.tls_roots.len() <= MAX_TLS_ROOTS
            && self.tls_roots.iter().all(|r| r.len() <= MAX_TLS_ROOT_BYTES);
        if ok { Ok(()) } else { Err(TrustError::Bounds) }
    }

    pub fn release_key(&self, id: u32) -> Option<[u8; 32]> {
        let key = self.release_keys.iter().find(|k| k.id == id)?;
        key.pubkey.as_slice().try_into().ok()
    }

    /// Whether a certificate with this serial may still be trusted.
    pub fn serial_ok(&self, serial: u64) -> bool {
        serial >= self.min_serial && !self.revoked_serials.contains(&serial)
    }

    /// `next`, if this store's keys signed it and it is newer (spec 5.2).
    pub fn accept_successor(&self, next: &SignedTrustStore) -> Result<TrustStore, TrustError> {
        // Authenticate first: the body is not decoded until a current key has signed it.
        let key = self
            .release_key(next.release_key_id)
            .ok_or(TrustError::UnknownReleaseKey)?;
        if !verify(&key, &message(&next.body), &next.sig) {
            return Err(TrustError::BadSignature);
        }
        let store = next.open_unverified()?;
        if store.version <= self.version {
            return Err(TrustError::NotNewer);
        }
        Ok(store)
    }
}

impl SignedTrustStore {
    pub fn sign(store: &TrustStore, release_key_id: u32, release_seed: &[u8; 32]) -> Self {
        let body = store.encode_to_vec();
        let sig = SigningKey::from_bytes(release_seed)
            .sign(&message(&body))
            .to_bytes()
            .to_vec();
        Self {
            body,
            release_key_id,
            sig,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TrustError> {
        if bytes.len() > MAX_TRUST_STORE_BYTES {
            return Err(TrustError::Bounds);
        }
        Self::decode(bytes).map_err(|_| TrustError::Malformed)
    }

    /// The body, parsed and within bounds, with no signature check. For a store whose
    /// signature was checked when it was accepted (spec 5.3).
    pub fn open_unverified(&self) -> Result<TrustStore, TrustError> {
        let store = TrustStore::decode(self.body.as_slice()).map_err(|_| TrustError::Malformed)?;
        store.check_bounds()?;
        Ok(store)
    }

    /// A compiled-in baseline: it must verify under one of its own keys (plan Decision 8).
    pub fn open_baseline(&self) -> Result<TrustStore, TrustError> {
        let store = self.open_unverified()?;
        let key = store
            .release_key(self.release_key_id)
            .ok_or(TrustError::UnknownReleaseKey)?;
        if !verify(&key, &message(&self.body), &self.sig) {
            return Err(TrustError::BadSignature);
        }
        Ok(store)
    }
}
