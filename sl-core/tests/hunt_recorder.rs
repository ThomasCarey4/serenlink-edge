//! Tests written to kill cargo-mutants survivors in `recorder.rs`: the block size estimate
//! that triggers an early seal, and how consecutive evictions are merged into one gap.

use sl_core::log::{DECLARATION_RESERVE, DurableLog};
use sl_core::mem_storage::MemStorage;
use sl_core::recorder::{Recorder, RecorderConfig};
use sl_proto::block::Block;
use sl_proto::ids::Class;
use sl_proto::record::{AnchorSource, Define, Gap, GapReason, Kind, TimeAnchor};
use sl_proto::value::{Value, ValueType};

fn def(local_id: u32, path: &str, unit: &str, value_type: ValueType) -> Define {
    Define {
        local_id,
        stable_key: 0,
        path: path.into(),
        source: 0,
        value_type,
        unit: unit.into(),
        kind: Kind::Linear,
    }
}

fn log(capacity: u64) -> DurableLog<MemStorage> {
    DurableLog::open(MemStorage::new(capacity)).unwrap().0
}

/// A recorder that seals only on size.
fn by_size(max_block_bytes: usize) -> Recorder {
    Recorder::new(
        RecorderConfig {
            seal_ms: [u64::MAX; 3],
            max_block_bytes,
            ..RecorderConfig::default()
        },
        1,
    )
}

/// Whether one tick seals what `fill` recorded, with the size limit at `limit`.
fn seals_at(limit: usize, fill: impl Fn(&mut Recorder)) -> bool {
    let mut log = log(1 << 20);
    let mut rec = by_size(limit);
    fill(&mut rec);
    let mut sealed = Vec::new();
    rec.tick(1, &mut log, &mut sealed).unwrap();
    !sealed.is_empty()
}

/// Seals at exactly `estimate` bytes and not one byte later.
fn assert_estimate(estimate: usize, fill: impl Fn(&mut Recorder)) {
    assert!(seals_at(estimate, &fill), "should seal at {estimate}");
    assert!(!seals_at(estimate + 1, &fill), "should not seal at {}", estimate + 1);
}

#[test]
fn a_definition_and_a_sample_are_estimated_from_the_path_and_unit() {
    // 32 per definition plus its path and unit, 12 per scalar sample.
    let d = def(1, "a.path.of.17bytes", "kn", ValueType::F64);
    assert_estimate(32 + 17 + 2 + 12, |rec| {
        rec.sample(Class::P1, &d, 0, Value::F64(1.0));
    });
    // A second sample of a defined signal adds only the sample.
    assert_estimate(32 + 17 + 2 + 12 + 12, |rec| {
        rec.sample(Class::P1, &d, 0, Value::F64(1.0));
        rec.sample(Class::P1, &d, 0, Value::F64(2.0));
    });
}

#[test]
fn a_blob_sample_is_estimated_with_its_length() {
    let d = def(1, "p", "", ValueType::Blob);
    assert_estimate(32 + 1 + 12 + 300, |rec| {
        rec.sample(Class::P2, &d, 0, Value::Blob(vec![0; 300]));
    });
}

#[test]
fn an_anchor_is_estimated_at_twenty_bytes() {
    let anchor = TimeAnchor {
        mono_ms: 0,
        utc_ms: 1,
        source: AnchorSource::Gnss,
        quality: 1,
    };
    assert_estimate(20, |rec| rec.anchor(anchor));
    assert_estimate(40, |rec| {
        rec.anchor(anchor);
        rec.anchor(anchor);
    });
}

#[test]
fn a_gap_is_estimated_at_twenty_four_bytes() {
    let gap = Gap {
        reason: GapReason::PowerOff,
        lost_class: 0,
        from_boot: 0,
        from_mono_ms: 0,
        to_mono_ms: 0,
        lost_first_seq: 0,
        lost_records: 0,
    };
    assert_estimate(24, |rec| rec.gap(Class::P1, gap));
    assert_estimate(48, |rec| {
        rec.gap(Class::P1, gap);
        rec.gap(Class::P1, gap);
    });
}

/// Record one blob sample into `class` and tick, which seals it (P1 and P2 seal on every tick).
fn put(rec: &mut Recorder, log: &mut DurableLog<MemStorage>, class: Class, d: &Define, t: u64, len: usize) {
    rec.sample(class, d, t, Value::Blob(vec![0; len]));
    rec.tick(t, log, &mut Vec::new()).unwrap();
}

/// P0 stays open, so the only P0 frames are declarations; P1 and P2 seal on every tick.
fn gap_collector() -> Recorder {
    Recorder::new(
        RecorderConfig {
            seal_ms: [u64::MAX, 0, 0],
            ..RecorderConfig::default()
        },
        1,
    )
}

/// Room for `bytes` of ordinary frames, above the declaration reserve.
fn log_with_room(bytes: u64) -> DurableLog<MemStorage> {
    log(bytes + DECLARATION_RESERVE)
}

/// Every declaration in P0, oldest first, as `(lost_class, first, count)` per gap.
fn declarations(log: &DurableLog<MemStorage>) -> Vec<Vec<(u8, u64, u64)>> {
    log.read_all(Class::P0)
        .unwrap()
        .iter()
        .map(|frame| {
            Block::decode(&frame.payload)
                .unwrap()
                .gaps
                .iter()
                .map(|g| {
                    assert_eq!(g.reason, GapReason::BufferEvicted);
                    (g.lost_class, g.lost_first_seq, g.lost_records)
                })
                .collect()
        })
        .collect()
}

#[test]
fn consecutive_evictions_from_one_class_are_reported_as_one_gap() {
    let mut log = log_with_room(1_000);
    let mut rec = gap_collector();
    let raw = def(9, "raw", "", ValueType::Blob);
    // Three P2 frames: sequences 0..2 (definition and sample), 2 and 3.
    for t in 0..3 {
        put(&mut rec, &mut log, Class::P2, &raw, t, 150);
    }
    assert_eq!(log.read_all(Class::P2).unwrap().len(), 3);
    // A P1 block that needs the room of at least two of them.
    put(
        &mut rec,
        &mut log,
        Class::P1,
        &def(1, "big", "", ValueType::Blob),
        3,
        500,
    );
    let evicted = log.first_retained_seq(Class::P2).unwrap();
    assert!(
        evicted >= 3,
        "the test must evict at least two frames, evicted to {evicted}"
    );

    assert_eq!(declarations(&log), [vec![(2, 0, evicted)]]);
}

#[test]
fn evictions_from_different_classes_are_not_merged_even_when_their_ranges_touch() {
    // Frames: A 182 bytes, B 172, C 673, D 92, E 123; a declaration of one gap about 83.
    let mut log = log_with_room(1_024);
    let mut rec = gap_collector();
    let p1 = def(1, "one", "", ValueType::Blob);
    let p2 = def(2, "two", "", ValueType::Blob);

    // P1: A = 0..2, B = 2. Then C, which evicts A while P2 is still empty.
    put(&mut rec, &mut log, Class::P1, &p1, 0, 100);
    put(&mut rec, &mut log, Class::P1, &p1, 1, 100);
    put(&mut rec, &mut log, Class::P1, &p1, 2, 600);
    assert_eq!(log.first_retained_seq(Class::P1).unwrap(), 2, "A alone is evicted");
    // P2: D = 0..2, which fits beside A's declaration.
    put(&mut rec, &mut log, Class::P2, &p2, 3, 10);
    assert_eq!(log.read_all(Class::P2).unwrap().len(), 1);
    // E needs room: D goes first (0..2 of P2), then B (2 of P1), which starts where D ended.
    put(&mut rec, &mut log, Class::P1, &p1, 4, 50);
    assert!(log.read_all(Class::P2).unwrap().is_empty());
    assert_eq!(log.first_retained_seq(Class::P1).unwrap(), 3, "B is evicted too");

    assert_eq!(declarations(&log), [vec![(1, 0, 2)], vec![(1, 2, 1), (2, 0, 2)]]);
}
