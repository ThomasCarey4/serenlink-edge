//! The recorder's declared-loss summary: two copies in metadata slots 4 and 5.

use sl_core::mem_storage::MemStorage;
use sl_core::storage::Storage;
use sl_core::summary::Summary;
use sl_proto::record::{Gap, GapReason};

fn gap(first: u64) -> Gap {
    Gap {
        reason: GapReason::BufferEvicted,
        lost_class: 2,
        from_boot: 1,
        from_mono_ms: 5,
        to_mono_ms: 6,
        lost_first_seq: first,
        lost_records: 3,
    }
}

#[test]
fn a_summary_round_trips() {
    let summary = Summary {
        generation: 7,
        carrier_end: 42,
        gaps: vec![gap(0), gap(10)],
    };
    assert_eq!(Summary::decode(&summary.encode()), Some(summary));
}

#[test]
fn an_empty_store_has_an_empty_summary() {
    assert_eq!(Summary::load(&MemStorage::new(1_000)), Summary::default());
}

#[test]
fn the_newest_copy_wins_and_a_torn_one_falls_back_to_the_other() {
    let mut storage = MemStorage::new(1_000);
    let mut summary = Summary {
        carrier_end: 1,
        gaps: vec![gap(0)],
        ..Summary::default()
    };
    summary.store(&mut storage).unwrap();
    let older = summary.clone();
    summary.carrier_end = 2;
    summary.gaps.push(gap(10));
    summary.store(&mut storage).unwrap();
    assert_eq!(Summary::load(&storage), summary);

    // The newer copy is torn by a power cut part way through its next rewrite.
    let slot = 4 + (summary.generation % 2) as usize;
    let bytes = storage.read_meta(slot).unwrap().unwrap();
    storage.write_meta(slot, &bytes[..bytes.len() / 2]).unwrap();
    assert_eq!(Summary::load(&storage), older);

    // The next store goes to the slot the older copy does not hold.
    let mut next = Summary::load(&storage);
    next.carrier_end = 3;
    next.store(&mut storage).unwrap();
    assert_eq!(Summary::load(&storage), next);
    assert_eq!(storage.read_meta(slot).unwrap().unwrap(), next.encode());
}

#[test]
fn a_rotted_copy_is_not_read() {
    let summary = Summary {
        generation: 1,
        carrier_end: 4,
        gaps: vec![gap(0)],
    };
    let mut bytes = summary.encode();
    bytes[10] ^= 1;
    assert_eq!(Summary::decode(&bytes), None);
}
