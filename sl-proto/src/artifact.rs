//! Signed artifacts (control lane spec 1): what the server offers a device, and the check the
//! device makes of an offer before it fetches a byte.
//!
//! A manifest says what a body is (kind, version, size, sha256) and who vouches for it. The
//! signature covers all of that, so a body is trusted by its hash and nothing else, and the
//! manifest can be checked long before the body has arrived.
use alloc::vec::Vec;

use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};

use crate::auth::verify;
use crate::identity::{ServerIdentity, verify_cert};
use crate::lp::signed_message;
use crate::trust::{MAX_TRUST_STORE_BYTES, TrustStore};

/// The most bytes one `Chunk` carries.
pub const MAX_CHUNK: usize = 16 * 1024;

const CONTEXT: &[u8] = b"serenlink-artifact-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u32)]
pub enum ArtifactKind {
    Configuration = 1,
    Tables = 2,
    Firmware = 3,
    Trust = 4,
}

impl ArtifactKind {
    /// By value.
    pub const ALL: [ArtifactKind; 4] = [Self::Configuration, Self::Tables, Self::Firmware, Self::Trust];
    /// The order a device fetches in: a new trust store can carry the key that signs the rest.
    pub const FETCH_ORDER: [ArtifactKind; 4] = [Self::Trust, Self::Configuration, Self::Tables, Self::Firmware];

    pub fn from_u32(v: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|k| *k as u32 == v)
    }

    /// Position in `ALL`, for arrays keyed by kind.
    pub fn index(self) -> usize {
        self as usize - 1
    }

    /// The largest body of this kind a device accepts.
    pub fn max_size(self) -> u64 {
        match self {
            Self::Configuration => 64 * 1024,
            Self::Tables => 1024 * 1024,
            Self::Firmware => 16 * 1024 * 1024,
            Self::Trust => MAX_TRUST_STORE_BYTES as u64,
        }
    }

    /// Signed by an offline release key. Configuration is the one kind that is not.
    pub fn is_release(self) -> bool {
        self != Self::Configuration
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Signer {
    Release = 1,
    Identity = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Outcome {
    Applied = 1,
    Refused = 2,
    Failed = 3,
}

impl Outcome {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Applied),
            2 => Some(Self::Refused),
            3 => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Reason {
    None = 0,
    Signature = 1,
    NotNewer = 2,
    TooBig = 3,
    WrongDevice = 4,
    Hash = 5,
    Apply = 6,
    Storage = 7,
}

impl Reason {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Signature),
            2 => Some(Self::NotNewer),
            3 => Some(Self::TooBig),
            4 => Some(Self::WrongDevice),
            5 => Some(Self::Hash),
            6 => Some(Self::Apply),
            7 => Some(Self::Storage),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Manifest {
    #[prost(uint32, tag = "1")]
    pub kind: u32,
    #[prost(uint32, tag = "2")]
    pub version: u32,
    #[prost(uint64, tag = "3")]
    pub size: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub sha256: Vec<u8>,
    /// Empty for a release kind; the one device a configuration is for.
    #[prost(bytes = "vec", tag = "5")]
    pub device_id: Vec<u8>,
    #[prost(uint32, tag = "6")]
    pub signer: u32,
    /// The release key that signed, when `signer` is release. Unused otherwise.
    #[prost(uint32, tag = "7")]
    pub key_id: u32,
    /// A `SignedIdentityCert`, when `signer` is identity. Empty otherwise.
    #[prost(bytes = "vec", tag = "8")]
    pub cert: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub sig: Vec<u8>,
}

/// What a signature covers. `signer`, `key_id` and `cert` are not in it: they only select the
/// key, and a wrong one fails the check.
fn message(kind: u32, version: u32, size: u64, sha256: &[u8], device_id: &[u8]) -> Vec<u8> {
    signed_message(
        CONTEXT,
        &[
            &kind.to_le_bytes(),
            &version.to_le_bytes(),
            &size.to_le_bytes(),
            sha256,
            device_id,
        ],
    )
}

fn sha256_of(body: &[u8]) -> Vec<u8> {
    Sha256::digest(body).to_vec()
}

impl Manifest {
    /// A manifest for `body`, signed by the offline release key `key_id`.
    pub fn sign_release(kind: ArtifactKind, version: u32, body: &[u8], key_id: u32, release_seed: &[u8; 32]) -> Self {
        let sha256 = sha256_of(body);
        let size = body.len() as u64;
        let sig = SigningKey::from_bytes(release_seed)
            .sign(&message(kind as u32, version, size, &sha256, &[]))
            .to_bytes()
            .to_vec();
        Self {
            kind: kind as u32,
            version,
            size,
            sha256,
            device_id: Vec::new(),
            signer: Signer::Release as u32,
            key_id,
            cert: Vec::new(),
            sig,
        }
    }

    /// A configuration for one device, signed by the server's identity key and carrying the
    /// certificate that vouches for that key.
    pub fn sign_config(device_id: &[u8; 16], version: u32, body: &[u8], identity: &ServerIdentity) -> Self {
        let sha256 = sha256_of(body);
        let size = body.len() as u64;
        let sig = identity
            .sign_raw(&message(
                ArtifactKind::Configuration as u32,
                version,
                size,
                &sha256,
                device_id,
            ))
            .to_vec();
        Self {
            kind: ArtifactKind::Configuration as u32,
            version,
            size,
            sha256,
            device_id: device_id.to_vec(),
            signer: Signer::Identity as u32,
            key_id: 0,
            cert: identity.cert().to_vec(),
            sig,
        }
    }

    pub fn kind(&self) -> Option<ArtifactKind> {
        ArtifactKind::from_u32(self.kind)
    }

    /// The hash, if it is 32 bytes.
    pub fn sha(&self) -> Option<[u8; 32]> {
        self.sha256.as_slice().try_into().ok()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestError {
    /// An unknown kind, a hash that is not 32 bytes, a zero size, or a device id on a release kind.
    Malformed,
    /// Not signed by a key this device trusts for this kind.
    Signature,
    TooBig,
    /// A configuration for another device.
    WrongDevice,
}

impl ManifestError {
    /// The code a device reports it under.
    pub fn reason(self) -> Reason {
        match self {
            Self::Malformed | Self::Signature => Reason::Signature,
            Self::TooBig => Reason::TooBig,
            Self::WrongDevice => Reason::WrongDevice,
        }
    }
}

/// The signature first, so nothing else about an unauthenticated manifest is believed: the
/// signer must be the one the kind allows, a release key of `store`, or an identity
/// certificate a release key of `store` signed and whose serial `store.serial_ok`. Then the
/// size (0 < size <= the kind's limit), then, for configuration, that it is for this device.
pub fn verify_manifest(m: &Manifest, store: &TrustStore, device_id: &[u8; 16]) -> Result<ArtifactKind, ManifestError> {
    let kind = m.kind().ok_or(ManifestError::Malformed)?;
    if m.sha256.len() != 32 {
        return Err(ManifestError::Malformed);
    }
    let signed = message(m.kind, m.version, m.size, &m.sha256, &m.device_id);
    let key = match (m.signer, kind.is_release()) {
        (s, true) if s == Signer::Release as u32 => store.release_key(m.key_id),
        (s, false) if s == Signer::Identity as u32 => verify_cert(store, &m.cert).ok().map(|c| c.public_key()),
        _ => None,
    };
    let key = key.ok_or(ManifestError::Signature)?;
    if !verify(&key, &signed, &m.sig) {
        return Err(ManifestError::Signature);
    }
    if m.size == 0 {
        return Err(ManifestError::Malformed);
    }
    if m.size > kind.max_size() {
        return Err(ManifestError::TooBig);
    }
    if kind.is_release() {
        if !m.device_id.is_empty() {
            return Err(ManifestError::Malformed);
        }
    } else if m.device_id != device_id {
        return Err(ManifestError::WrongDevice);
    }
    Ok(kind)
}

/// Whether `body` is what `m` describes: its length and its sha256.
pub fn body_matches(m: &Manifest, body: &[u8]) -> bool {
    m.size == body.len() as u64 && m.sha().is_some_and(|sha| Sha256::digest(body)[..] == sha[..])
}
