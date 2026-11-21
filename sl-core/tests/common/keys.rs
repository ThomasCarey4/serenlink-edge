//! Test keys local to the edge tests. Not the server's test keys, on purpose: edge is public
//! and depends on nothing in server/.
#![allow(dead_code)]
use sl_proto::auth::{KeySigner, Signer as _};
use sl_proto::identity::{IdentityCert, ServerIdentity, SignedIdentityCert};
use sl_proto::trust::{ReleaseKey, SignedTrustStore, TrustStore};

pub const RELEASE: [u8; 32] = [0x11; 32];
pub const ROGUE: [u8; 32] = [0x66; 32];
pub const IDENTITY: [u8; 32] = [0x22; 32];

pub fn store(min_serial: u64, revoked: &[u64]) -> TrustStore {
    TrustStore {
        version: 1,
        release_keys: vec![ReleaseKey {
            id: 1,
            pubkey: KeySigner::from_seed(RELEASE).public_key().to_vec(),
        }],
        min_serial,
        revoked_serials: revoked.to_vec(),
        tls_roots: vec![],
    }
}

pub fn baseline() -> SignedTrustStore {
    SignedTrustStore::sign(&store(1, &[]), 1, &RELEASE)
}

pub fn identity(serial: u64, host: &str, release: &[u8; 32]) -> ServerIdentity {
    let cert = IdentityCert {
        identity_pubkey: KeySigner::from_seed(IDENTITY).public_key().to_vec(),
        serial,
        hostnames: vec![host.into()],
    };
    ServerIdentity::new(IDENTITY, SignedIdentityCert::sign(&cert, 1, release).to_bytes()).unwrap()
}
