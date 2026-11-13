use sl_core::log::{DECLARATION_RESERVE, DurableLog, LostRange, Recovery};
use sl_core::mem_storage::MemStorage;
use sl_core::recorder::{Recorder, RecorderConfig, Sealed};
use sl_core::storage::{Storage, StorageError};
use sl_proto::block::{Block, block_hash};
use sl_proto::compress::{Compression, decompress};
use sl_proto::ids::Class;
use sl_proto::record::{AnchorSource, Define, Gap, GapReason, Kind, TimeAnchor};
use sl_proto::value::{Value, ValueType};

fn def(local_id: u32, value_type: ValueType) -> Define {
    Define {
        local_id,
        stable_key: u64::from(local_id),
        path: format!("test.signal.{local_id}"),
        source: 1,
        value_type,
        unit: "u".into(),
        kind: Kind::Linear,
    }
}

fn log(capacity: u64) -> DurableLog<MemStorage> {
    DurableLog::open(MemStorage::new(capacity)).unwrap().0
}

/// Room for `bytes` of ordinary frames, above the declaration reserve.
fn log_with_room(bytes: u64) -> DurableLog<MemStorage> {
    log(bytes + DECLARATION_RESERVE)
}

/// A recorder that seals every open block on each tick.
fn eager() -> Recorder {
    Recorder::new(
        RecorderConfig {
            seal_ms: [0; 3],
            ..RecorderConfig::default()
        },
        1,
    )
}

fn blocks(log: &DurableLog<MemStorage>, class: Class) -> Vec<Block> {
    log.read_all(class)
        .unwrap()
        .iter()
        .map(|f| Block::decode(&f.payload).unwrap())
        .collect()
}

#[test]
fn blocks_seal_on_their_class_interval() {
    let mut log = log(100_000);
    let mut rec = Recorder::new(RecorderConfig::default(), 3);
    let mut sealed = Vec::new();
    rec.sample(Class::P0, &def(1, ValueType::F64), 0, Value::F64(1.0));
    rec.sample(Class::P1, &def(2, ValueType::F64), 0, Value::F64(2.0));

    rec.tick(999, &mut log, &mut sealed).unwrap();
    assert!(sealed.is_empty());
    rec.tick(1_000, &mut log, &mut sealed).unwrap();
    assert_eq!(sealed.iter().map(|s| s.class).collect::<Vec<_>>(), [Class::P0]);
    rec.tick(4_999, &mut log, &mut sealed).unwrap();
    assert_eq!(sealed.len(), 1);
    rec.tick(5_000, &mut log, &mut sealed).unwrap();
    assert_eq!(
        sealed.iter().map(|s| s.class).collect::<Vec<_>>(),
        [Class::P0, Class::P1]
    );
}

#[test]
fn a_sealed_block_matches_what_the_log_holds() {
    let mut log = log(100_000);
    let mut rec = Recorder::new(
        RecorderConfig {
            table_version: 14,
            ..RecorderConfig::default()
        },
        3,
    );
    let mut sealed = Vec::new();
    rec.sample(Class::P0, &def(1, ValueType::F64), 10, Value::F64(1.0));
    rec.sample(Class::P0, &def(1, ValueType::F64), 20, Value::F64(1.5));
    rec.flush(20, &mut log, &mut sealed).unwrap();

    let frame = &log.read_all(Class::P0).unwrap()[0];
    assert_eq!(
        sealed,
        [Sealed {
            class: Class::P0,
            first_seq: 0,
            count: 3,
            hash: block_hash(&frame.payload)
        }]
    );
    assert_eq!((frame.header.count, frame.header.hash), (3, sealed[0].hash));
    let block = Block::decode(&frame.payload).unwrap();
    assert_eq!((block.boot_id, block.table_version), (3, 14));
    assert_eq!(block.columns[0].samples().len(), 2);
}

#[test]
fn a_signal_is_defined_once_in_each_class_that_uses_it() {
    let mut log = log(100_000);
    let mut rec = eager();
    let mut sealed = Vec::new();
    let d = def(1, ValueType::F64);
    for t in 0..3 {
        rec.sample(Class::P0, &d, t, Value::F64(1.0));
        rec.sample(Class::P1, &d, t, Value::F64(1.0));
        rec.tick(t, &mut log, &mut sealed).unwrap();
    }
    for class in [Class::P0, Class::P1] {
        let defines: Vec<usize> = blocks(&log, class).iter().map(|b| b.defines.len()).collect();
        assert_eq!(defines, [1, 0, 0]);
    }
}

#[test]
fn a_large_block_seals_before_its_interval() {
    let mut log = log(1_000_000);
    let mut rec = Recorder::new(
        RecorderConfig {
            max_block_bytes: 1_000,
            ..RecorderConfig::default()
        },
        1,
    );
    let mut sealed = Vec::new();
    for t in 0..200 {
        rec.sample(Class::P1, &def(1, ValueType::F64), t, Value::F64(1.0));
    }
    rec.tick(200, &mut log, &mut sealed).unwrap();
    assert_eq!(sealed.len(), 1);
}

#[test]
fn anchors_travel_in_the_first_class() {
    let mut log = log(100_000);
    let mut rec = eager();
    let mut sealed = Vec::new();
    rec.anchor(TimeAnchor {
        mono_ms: 5,
        utc_ms: 1_794_487_144_000,
        source: AnchorSource::Gnss,
        quality: 2,
    });
    rec.tick(5, &mut log, &mut sealed).unwrap();
    assert_eq!(blocks(&log, Class::P0)[0].anchors.len(), 1);
    assert!(blocks(&log, Class::P1).is_empty());
}

#[test]
fn a_full_store_evicts_the_lowest_class_and_records_the_gap() {
    let mut log = log_with_room(2_000);
    let mut rec = eager();
    let mut sealed = Vec::new();
    let raw = def(9, ValueType::Blob);
    let mut t = 0;
    while log.used() + 400 < 2_000 {
        rec.sample(Class::P2, &raw, t, Value::Blob(vec![0; 200]));
        rec.tick(t, &mut log, &mut sealed).unwrap();
        t += 1;
    }
    assert_eq!(log.first_retained_seq(Class::P2).unwrap(), 0);

    let position = def(1, ValueType::Blob);
    rec.sample(Class::P0, &position, t, Value::Blob(vec![1; 600]));
    rec.tick(t, &mut log, &mut sealed).unwrap();
    assert!(
        log.first_retained_seq(Class::P2).unwrap() > 0,
        "raw capture should have been evicted"
    );

    // The loss is declared in P0, which is evicted last, not in the class that lost data,
    // and before the block that needed the room.
    let p0 = blocks(&log, Class::P0);
    assert_eq!(p0.len(), 2);
    assert!(!p0[0].gaps.is_empty());
    assert!(
        p0[0]
            .gaps
            .iter()
            .all(|g| g.reason == GapReason::BufferEvicted && g.lost_class == 2 && g.lost_records > 0)
    );
    assert_eq!(p0[1].columns.len(), 1, "then the block itself");
}

#[test]
fn a_lower_class_never_evicts_a_higher_one() {
    let mut log = log_with_room(1_000);
    let mut rec = eager();
    let mut sealed = Vec::new();
    let position = def(1, ValueType::F64);
    let mut t = 0;
    while log.used() + 300 < 1_000 {
        rec.sample(Class::P0, &position, t, Value::F64(1.0));
        rec.tick(t, &mut log, &mut sealed).unwrap();
        t += 1;
    }
    let kept = log.read_all(Class::P0).unwrap().len();
    sealed.clear();

    rec.sample(Class::P2, &def(9, ValueType::Blob), t, Value::Blob(vec![0; 600]));
    rec.tick(t, &mut log, &mut sealed).unwrap();

    // Only the declaration of the dropped block was sealed, from the reserve; nothing in
    // P0 was evicted for it.
    assert_eq!(sealed.iter().map(|s| s.class).collect::<Vec<_>>(), [Class::P0]);
    assert_eq!(log.first_retained_seq(Class::P0).unwrap(), 0);
    assert_eq!(log.read_all(Class::P0).unwrap().len(), kept + 1);
    assert!(log.read_all(Class::P2).unwrap().is_empty());
    // The dropped block's two sequence numbers (definition and sample) are used up, and
    // the loss is declared against exactly that range.
    assert_eq!(log.next_seq(Class::P2), 2);
    let gap = blocks(&log, Class::P0).pop().unwrap().gaps[0];
    assert_eq!((gap.lost_class, gap.lost_first_seq, gap.lost_records), (2, 0, 2));
}

#[test]
fn a_definition_lost_to_eviction_is_written_again() {
    let mut log = log_with_room(2_000);
    // P0 stays open, so its only frames are declarations.
    let cfg = RecorderConfig {
        seal_ms: [u64::MAX, 0, 0],
        ..RecorderConfig::default()
    };
    let mut rec = Recorder::new(cfg, 1);
    let mut sealed = Vec::new();
    let depth = def(2, ValueType::F64);
    let mut owed = false;
    for t in 0..200 {
        rec.sample(Class::P1, &depth, t, Value::F64(4.2));
        rec.tick(t, &mut log, &mut sealed).unwrap();
        let held = blocks(&log, Class::P1);
        if owed {
            assert_eq!(
                held.last().unwrap().defines.len(),
                1,
                "not defined again after eviction, t={t}"
            );
        }
        owed = held.iter().all(|b| b.defines.is_empty());
    }
    assert!(log.first_retained_seq(Class::P1).unwrap() > 0, "the test must evict");
}

#[test]
fn a_block_too_big_for_the_store_is_dropped_without_emptying_it() {
    let mut log = log_with_room(1_000);
    let mut rec = eager();
    let mut sealed = Vec::new();
    let position = def(1, ValueType::F64);
    for t in 0..4 {
        rec.sample(Class::P0, &position, t, Value::F64(1.0));
        rec.tick(t, &mut log, &mut sealed).unwrap();
    }
    let kept = log.read_all(Class::P0).unwrap().len();
    let next = log.next_seq(Class::P0);
    sealed.clear();

    rec.sample(Class::P0, &def(8, ValueType::Blob), 4, Value::Blob(vec![0; 5_000]));
    rec.tick(4, &mut log, &mut sealed).unwrap();

    assert_eq!(sealed.len(), 1, "only the declaration of the loss");
    assert_eq!(log.first_retained_seq(Class::P0).unwrap(), 0);
    assert_eq!(
        log.read_all(Class::P0).unwrap().len(),
        kept + 1,
        "nothing may be evicted for a block that cannot fit"
    );
    // Two numbers for the dropped block, one for the gap that declares it.
    assert_eq!(log.next_seq(Class::P0), next + 3);
}

#[test]
fn a_block_too_large_for_the_format_is_dropped_and_reported() {
    // One megabyte is the most a frame may carry. Appending more would write a frame that
    // every reader takes for corruption: durable according to the recorder, and gone.
    let mut log = log(16 << 20);
    let mut rec = eager();
    let mut sealed = Vec::new();
    rec.sample(
        Class::P2,
        &def(9, ValueType::Blob),
        1,
        Value::Blob(vec![0x5a; 1_200_000]),
    );
    rec.tick(1, &mut log, &mut sealed).unwrap();

    assert_eq!(sealed.iter().map(|s| s.class).collect::<Vec<_>>(), [Class::P0]);
    assert!(log.read_all(Class::P2).unwrap().is_empty());
    assert_eq!(log.next_seq(Class::P2), 2);
    assert_eq!(
        log.used(),
        log.storage().end(Class::P0),
        "only the declaration is stored"
    );
    let gap = blocks(&log, Class::P0).pop().unwrap().gaps[0];
    assert_eq!((gap.lost_class, gap.lost_first_seq, gap.lost_records), (2, 0, 2));
}

#[test]
fn a_failed_write_loses_the_block_but_not_the_record_of_it() {
    let mut log = log(100_000);
    let mut rec = eager();
    let mut sealed = Vec::new();
    let depth = def(5, ValueType::F64);
    rec.sample(Class::P1, &depth, 1, Value::F64(4.2));
    log.storage_mut().cut_power_after(10);
    assert_eq!(rec.tick(1, &mut log, &mut sealed), Err(StorageError::Io));
    assert!(sealed.is_empty());

    // The storage works again, as after a failed flash write. The block is gone; its two
    // sequence numbers are not reused, the definition goes out again, and the declaration
    // that could not be written then is written now, first.
    log.storage_mut().power_on();
    rec.sample(Class::P1, &depth, 2, Value::F64(4.3));
    rec.tick(2, &mut log, &mut sealed).unwrap();

    let frames = log.read_all(Class::P1).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].header.first_seq, 2);
    assert_eq!(blocks(&log, Class::P1)[0].defines.len(), 1);
    let gap = blocks(&log, Class::P0)[0].gaps[0];
    assert_eq!(
        (gap.reason, gap.lost_class, gap.lost_first_seq, gap.lost_records),
        (GapReason::BufferEvicted, 1, 0, 2)
    );
}

#[test]
fn a_missing_compressor_does_not_cost_the_block() {
    let mut log = log(100_000);
    let cfg = RecorderConfig {
        seal_ms: [0; 3],
        compression: Compression::Zstd,
        ..RecorderConfig::default()
    };
    let mut rec = Recorder::new(cfg, 1);
    let mut sealed = Vec::new();
    rec.sample(Class::P0, &def(1, ValueType::F64), 1, Value::F64(1.0));
    rec.tick(1, &mut log, &mut sealed).unwrap();
    assert_eq!(sealed.len(), 1);

    // Built without zstd, the block is stored as it is, and the frame says so.
    let frame = log.read_all(Class::P0).unwrap().remove(0);
    let stored_as = if cfg!(feature = "zstd") {
        Compression::Zstd
    } else {
        Compression::None
    };
    assert_eq!(frame.header.compression, stored_as as u8);
    let raw = decompress(stored_as, &frame.payload, 1 << 20).unwrap();
    assert_eq!(block_hash(&raw), sealed[0].hash);
}

#[test]
fn corruption_found_at_open_is_reported_to_the_server() {
    let mut log = log(100_000);
    let mut rec = eager();
    let mut sealed = Vec::new();
    let recovery = Recovery {
        corrupt: vec![LostRange {
            class: Class::P1,
            first_seq: 4,
            count: 2,
        }],
        ..Recovery::default()
    };
    rec.report_recovery(&recovery, 50, &mut log, &mut sealed).unwrap();
    assert_eq!(
        blocks(&log, Class::P0)[0].gaps,
        [Gap {
            reason: GapReason::Corrupt,
            lost_class: 1,
            from_boot: 1,
            from_mono_ms: 50,
            to_mono_ms: 50,
            lost_first_seq: 4,
            lost_records: 2,
        }]
    );
}
