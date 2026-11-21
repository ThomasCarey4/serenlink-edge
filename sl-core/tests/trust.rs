use sl_core::mem_storage::MemStorage;
use sl_core::storage::Storage;
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
