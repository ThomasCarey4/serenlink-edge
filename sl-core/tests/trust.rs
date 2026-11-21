use sha2::{Digest, Sha256};
use sl_core::mem_storage::MemStorage;
use sl_core::storage::{META_SLOTS, Storage, StorageError};
use sl_core::trust::{OfferError, OpenError, TRUST_SLOTS, TrustAnchor};
use sl_proto::trust::{ReleaseKey, SignedTrustStore, TrustError, TrustStore};

const K1: [u8; 32] = [0x11; 32];
const K2: [u8; 32] = [0x12; 32];

fn public(seed: &[u8; 32]) -> Vec<u8> {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
        .to_vec()
}

fn store(version: u32, keys: &[(u32, [u8; 32])]) -> TrustStore {
    TrustStore {
        version,
        release_keys: keys
            .iter()
            .map(|(id, s)| ReleaseKey {
                id: *id,
                pubkey: public(s),
            })
            .collect(),
        min_serial: 1,
        revoked_serials: vec![],
        tls_roots: vec![],
    }
}

fn baseline() -> SignedTrustStore {
    SignedTrustStore::sign(&store(1, &[(1, K1)]), 1, &K1)
}

#[test]
fn a_fresh_device_trusts_its_baseline() {
    let s = MemStorage::new(1 << 16);
    let a = TrustAnchor::open(&s, &baseline()).unwrap();
    assert_eq!(a.active().version, 1);
}

#[test]
fn a_broken_baseline_will_not_open() {
    let s = MemStorage::new(1 << 16);
    let bad = SignedTrustStore::sign(&store(1, &[(1, K1)]), 1, &K2);
    assert!(matches!(TrustAnchor::open(&s, &bad), Err(OpenError::Baseline(_))));
}

#[test]
fn an_accepted_store_survives_a_reopen_and_chains() {
    let mut s = MemStorage::new(1 << 16);
    let mut a = TrustAnchor::open(&s, &baseline()).unwrap();
    a.offer(&mut s, &SignedTrustStore::sign(&store(2, &[(1, K1), (2, K2)]), 1, &K1))
        .unwrap();
    a.offer(&mut s, &SignedTrustStore::sign(&store(3, &[(2, K2)]), 2, &K2))
        .unwrap();
    // v4 overwrites v2's slot; v3, signed by a key only v2 introduced, still opens.
    a.offer(&mut s, &SignedTrustStore::sign(&store(4, &[(2, K2)]), 2, &K2))
        .unwrap();
    let a = TrustAnchor::open(&s, &baseline()).unwrap();
    assert_eq!(a.active().version, 4);
}

#[test]
fn refused_offers_change_nothing() {
    let mut s = MemStorage::new(1 << 16);
    let mut a = TrustAnchor::open(&s, &baseline()).unwrap();
    let old = SignedTrustStore::sign(&store(1, &[(1, K1)]), 1, &K1);
    assert_eq!(a.offer(&mut s, &old), Err(OfferError::Refused(TrustError::NotNewer)));
    let foreign = SignedTrustStore::sign(&store(2, &[(2, K2)]), 2, &K2);
    assert_eq!(
        a.offer(&mut s, &foreign),
        Err(OfferError::Refused(TrustError::UnknownReleaseKey))
    );
    for slot in TRUST_SLOTS {
        assert_eq!(s.read_meta(slot).unwrap(), None);
    }
    assert_eq!(a.active().version, 1);
}

#[test]
fn a_torn_write_leaves_the_previous_store() {
    let mut s = MemStorage::new(1 << 16);
    let mut a = TrustAnchor::open(&s, &baseline()).unwrap();
    a.offer(&mut s, &SignedTrustStore::sign(&store(2, &[(1, K1)]), 1, &K1))
        .unwrap();
    s.cut_power_after(10);
    assert!(matches!(
        a.offer(&mut s, &SignedTrustStore::sign(&store(3, &[(1, K1)]), 1, &K1)),
        Err(OfferError::Storage(_))
    ));
    assert_eq!(a.active().version, 2);
    s.power_on();
    assert_eq!(TrustAnchor::open(&s, &baseline()).unwrap().active().version, 2);
}

#[test]
fn rotted_slots_fall_back_to_the_baseline() {
    let mut s = MemStorage::new(1 << 16);
    let mut a = TrustAnchor::open(&s, &baseline()).unwrap();
    a.offer(&mut s, &SignedTrustStore::sign(&store(2, &[(1, K1)]), 1, &K1))
        .unwrap();
    a.offer(&mut s, &SignedTrustStore::sign(&store(3, &[(1, K1)]), 1, &K1))
        .unwrap();
    for slot in TRUST_SLOTS {
        let mut bytes = s.read_meta(slot).unwrap().unwrap();
        bytes[3] ^= 0x40;
        s.write_meta(slot, &bytes).unwrap();
    }
    assert_eq!(TrustAnchor::open(&s, &baseline()).unwrap().active().version, 1);
}

#[test]
fn a_newer_baseline_wins_over_older_slots() {
    let mut s = MemStorage::new(1 << 16);
    let mut a = TrustAnchor::open(&s, &baseline()).unwrap();
    a.offer(&mut s, &SignedTrustStore::sign(&store(2, &[(1, K1)]), 1, &K1))
        .unwrap();
    let firmware = SignedTrustStore::sign(&store(5, &[(1, K1)]), 1, &K1);
    assert_eq!(TrustAnchor::open(&s, &firmware).unwrap().active().version, 5);
}

#[test]
fn the_log_metadata_slots_are_untouched() {
    let mut s = MemStorage::new(1 << 16);
    let mut a = TrustAnchor::open(&s, &baseline()).unwrap();
    a.offer(&mut s, &SignedTrustStore::sign(&store(2, &[(1, K1)]), 1, &K1))
        .unwrap();
    assert_eq!(s.read_meta(0).unwrap(), None);
    assert_eq!(s.read_meta(1).unwrap(), None);
}

/// Wraps `MemStorage`; reads of the trust slots fail.
struct Unreadable(MemStorage);

impl Storage for Unreadable {
    fn capacity(&self) -> u64 {
        self.0.capacity()
    }
    fn start(&self, class: sl_proto::ids::Class) -> u64 {
        self.0.start(class)
    }
    fn end(&self, class: sl_proto::ids::Class) -> u64 {
        self.0.end(class)
    }
    fn append(&mut self, class: sl_proto::ids::Class, data: &[u8]) -> Result<(), StorageError> {
        self.0.append(class, data)
    }
    fn read(&self, class: sl_proto::ids::Class, offset: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        self.0.read(class, offset, buf)
    }
    fn trim_front(&mut self, class: sl_proto::ids::Class, new_start: u64) -> Result<(), StorageError> {
        self.0.trim_front(class, new_start)
    }
    fn truncate(&mut self, class: sl_proto::ids::Class, new_end: u64) -> Result<(), StorageError> {
        self.0.truncate(class, new_end)
    }
    fn read_meta(&self, slot: usize) -> Result<Option<Vec<u8>>, StorageError> {
        if TRUST_SLOTS.contains(&slot) {
            return Err(StorageError::Io);
        }
        self.0.read_meta(slot)
    }
    fn write_meta(&mut self, slot: usize, data: &[u8]) -> Result<(), StorageError> {
        self.0.write_meta(slot, data)
    }
}

#[test]
fn an_unreadable_slot_is_an_empty_one() {
    let mut s = MemStorage::new(1 << 16);
    let mut a = TrustAnchor::open(&s, &baseline()).unwrap();
    a.offer(&mut s, &SignedTrustStore::sign(&store(2, &[(1, K1)]), 1, &K1))
        .unwrap();
    let s = Unreadable(s);
    assert_eq!(TrustAnchor::open(&s, &baseline()).unwrap().active().version, 1);
}

#[test]
fn malformed_slots_fall_back_to_the_baseline() {
    let junk = b"not a signed trust store".to_vec();
    let mut sealed = junk.clone();
    sealed.extend_from_slice(&Sha256::digest(&junk));
    let cases: [(&str, Vec<u8>); 3] = [
        ("valid digest over non-store bytes", sealed),
        ("shorter than a digest", vec![7; 31]),
        ("empty", vec![]),
    ];
    for (name, bytes) in cases {
        for slot in TRUST_SLOTS {
            let mut s = MemStorage::new(1 << 16);
            s.write_meta(slot, &bytes).unwrap();
            let a = TrustAnchor::open(&s, &baseline()).unwrap();
            assert_eq!(a.active().version, 1, "{name}, slot {slot}");
        }
    }
}

#[test]
fn mem_storage_rejects_meta_slots_out_of_range() {
    let mut s = MemStorage::new(1 << 16);
    assert_eq!(s.read_meta(META_SLOTS), Err(StorageError::Io));
    assert_eq!(s.write_meta(META_SLOTS, b"x"), Err(StorageError::Io));
}
