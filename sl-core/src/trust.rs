//! The device's trust store (spec 5.2, 5.3): a compiled-in baseline, and whatever newer store
//! was accepted since, in two meta slots written alternately.
use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use sl_proto::trust::{SignedTrustStore, TrustError, TrustStore};

use crate::storage::{Storage, StorageError};

/// The meta slots the trust store lives in.
pub const TRUST_SLOTS: [usize; 2] = [2, 3];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The compiled-in baseline does not verify: a firmware build error.
    Baseline(TrustError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferError {
    /// The store was refused; nothing changed.
    Refused(TrustError),
    /// Writing it failed; the active store is unchanged, and so is the slot holding it.
    Storage(StorageError),
}

pub struct TrustAnchor {
    active: TrustStore,
    /// The slot holding the active store; `None` while the baseline is active.
    slot: Option<usize>,
}

fn encode_slot(signed: &SignedTrustStore) -> Vec<u8> {
    let mut out = signed.to_bytes();
    let digest = Sha256::digest(&out);
    out.extend_from_slice(&digest);
    out
}

fn decode_slot(bytes: &[u8]) -> Option<TrustStore> {
    let split = bytes.len().checked_sub(32)?;
    let (body, digest) = bytes.split_at(split);
    if Sha256::digest(body).as_slice() != digest {
        return None;
    }
    SignedTrustStore::from_bytes(body).ok()?.open_unverified().ok()
}

impl TrustAnchor {
    /// The newest of the baseline and every slot that holds an intact store. A slot's
    /// signature was checked when it was accepted and is not checked again: the key that
    /// signed it may have come from a store since overwritten (spec 5.3).
    pub fn open<S: Storage>(storage: &S, baseline: &SignedTrustStore) -> Result<Self, OpenError> {
        let mut active = baseline.open_baseline().map_err(OpenError::Baseline)?;
        let mut slot = None;
        for i in TRUST_SLOTS {
            // An unreadable slot is an empty one: the baseline still stands behind it.
            let Some(store) = storage.read_meta(i).ok().flatten().and_then(|b| decode_slot(&b)) else {
                continue;
            };
            if store.version > active.version {
                active = store;
                slot = Some(i);
            }
        }
        Ok(Self { active, slot })
    }

    pub fn active(&self) -> &TrustStore {
        &self.active
    }

    /// Accept `next` if the active store's keys signed it and it is newer, writing it to the
    /// slot that does not hold the active store.
    pub fn offer<S: Storage>(&mut self, storage: &mut S, next: &SignedTrustStore) -> Result<(), OfferError> {
        let store = self.active.accept_successor(next).map_err(OfferError::Refused)?;
        let target = if self.slot == Some(TRUST_SLOTS[0]) {
            TRUST_SLOTS[1]
        } else {
            TRUST_SLOTS[0]
        };
        storage
            .write_meta(target, &encode_slot(next))
            .map_err(OfferError::Storage)?;
        self.active = store;
        self.slot = Some(target);
        Ok(())
    }
}
