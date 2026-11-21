//! The server's identity (spec 3, 4): a certificate from a release key, and the signature
//! that binds a session to it.
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use ed25519_dalek::{Signer as _, SigningKey};
use prost::Message;

use crate::auth::verify;
use crate::lp::signed_message;

pub const MAX_CERT_BYTES: usize = 1024;
pub const MAX_HOSTNAMES: usize = 8;
pub const MAX_HOSTNAME_LEN: usize = 253;

const SERVER_CONTEXT: &[u8] = b"serenlink-server-v1";
const CERT_CONTEXT: &[u8] = b"serenlink-identity-cert-v1";

#[derive(Clone, PartialEq, prost::Message)]
pub struct IdentityCert {
    #[prost(bytes = "vec", tag = "1")]
    pub identity_pubkey: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub serial: u64,
    #[prost(string, repeated, tag = "3")]
    pub hostnames: Vec<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignedIdentityCert {
    /// An encoded `IdentityCert`, exactly as signed.
    #[prost(bytes = "vec", tag = "1")]
    pub body: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub release_key_id: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub sig: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// Did not parse.
    Malformed,
    /// Outside the bounds of spec 4.
    Bounds,
    BadSignature,
    /// No release key in the trust store has this id.
    UnknownReleaseKey,
    /// Serial below the store's `min_serial`, or listed as revoked.
    Revoked,
    /// The device's hostname is not one the certificate names.
    WrongHost,
    /// The certificate's key is not the key given with it.
    KeyMismatch,
}

fn cert_message(body: &[u8]) -> Vec<u8> {
    signed_message(CERT_CONTEXT, &[body])
}

/// What the server signs in its Challenge (spec 3.1).
pub fn server_message(binding: &[u8; 32], nonce: &[u8; 32], device_id: &[u8], hostname: &str) -> Vec<u8> {
    signed_message(SERVER_CONTEXT, &[binding, nonce, device_id, hostname.as_bytes()])
}

impl IdentityCert {
    fn check_bounds(&self) -> Result<(), IdentityError> {
        let ok = self.identity_pubkey.len() == 32
            && self.serial > 0
            && !self.hostnames.is_empty()
            && self.hostnames.len() <= MAX_HOSTNAMES
            && self
                .hostnames
                .iter()
                .all(|h| !h.is_empty() && h.len() <= MAX_HOSTNAME_LEN);
        if ok { Ok(()) } else { Err(IdentityError::Bounds) }
    }

    pub fn pubkey(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.identity_pubkey);
        out
    }
}

impl SignedIdentityCert {
    pub fn sign(cert: &IdentityCert, release_key_id: u32, release_seed: &[u8; 32]) -> Self {
        let body = cert.encode_to_vec();
        let sig = SigningKey::from_bytes(release_seed)
            .sign(&cert_message(&body))
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

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() > MAX_CERT_BYTES {
            return Err(IdentityError::Bounds);
        }
        Self::decode(bytes).map_err(|_| IdentityError::Malformed)
    }
}

/// The certificate's body, if `release_pubkey` signed it and it is within bounds. The
/// signature is checked before the body is parsed.
pub fn verify_cert_signature(
    signed: &SignedIdentityCert,
    release_pubkey: &[u8; 32],
) -> Result<IdentityCert, IdentityError> {
    if !verify(release_pubkey, &cert_message(&signed.body), &signed.sig) {
        return Err(IdentityError::BadSignature);
    }
    let cert = IdentityCert::decode(signed.body.as_slice()).map_err(|_| IdentityError::Malformed)?;
    cert.check_bounds()?;
    Ok(cert)
}

/// The gateway's identity key and its certificate. The key never leaves this value.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerIdentity {
    seed: [u8; 32],
    cert: Vec<u8>,
    serial: u64,
    hostnames: Vec<String>,
}

impl fmt::Debug for ServerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerIdentity")
            .field("serial", &self.serial)
            .field("hostnames", &self.hostnames)
            .finish_non_exhaustive()
    }
}

impl ServerIdentity {
    /// The certificate must parse, be within bounds and name this key. Its release signature
    /// is not checked here: that needs a trust store (the gateway checks it at startup when
    /// given one).
    pub fn new(seed: [u8; 32], cert: Vec<u8>) -> Result<Self, IdentityError> {
        let signed = SignedIdentityCert::from_bytes(&cert)?;
        let body = IdentityCert::decode(signed.body.as_slice()).map_err(|_| IdentityError::Malformed)?;
        body.check_bounds()?;
        if body.pubkey() != SigningKey::from_bytes(&seed).verifying_key().to_bytes() {
            return Err(IdentityError::KeyMismatch);
        }
        Ok(Self {
            seed,
            cert,
            serial: body.serial,
            hostnames: body.hostnames,
        })
    }

    pub fn cert(&self) -> &[u8] {
        &self.cert
    }

    pub fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.seed).verifying_key().to_bytes()
    }

    pub fn serial(&self) -> u64 {
        self.serial
    }

    pub fn hostnames(&self) -> &[String] {
        &self.hostnames
    }

    pub fn sign_challenge(&self, binding: &[u8; 32], nonce: &[u8; 32], device_id: &[u8], hostname: &str) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed)
            .sign(&server_message(binding, nonce, device_id, hostname))
            .to_bytes()
    }
}
