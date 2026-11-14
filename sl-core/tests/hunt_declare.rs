//! Round 2 tests written to kill cargo-mutants survivors in the declare-before-destroy code of
//! `log.rs` and `recorder.rs`. Each states a property that no other test pinned down.

use sl_core::frame::HEADER_LEN;
use sl_core::log::{DurableLog, LostRange, Recovery};
use sl_core::mem_storage::MemStorage;
use sl_core::recorder::{Recorder, RecorderConfig, Sealed};
use sl_core::storage::{Storage, StorageError};
use sl_proto::block::Block;
use sl_proto::ids::Class;
use sl_proto::record::{Define, Gap, GapReason, Kind};
use sl_proto::value::{Value, ValueType};

fn def(local_id: u32) -> Define {
    Define {
        local_id,
        stable_key: 0,
        path: format!("p{local_id}"),
        source: 0,
        value_type: ValueType::Blob,
        unit: String::new(),
        kind: Kind::Linear,
    }
}

fn eager_with(boot: u32) -> Recorder {
    Recorder::new(
        RecorderConfig {
            seal_ms: [0; 3],
            ..RecorderConfig::default()
        },
        boot,
    )
}

fn eager() -> Recorder {
    eager_with(1)
}

fn open(capacity: u64) -> DurableLog<MemStorage> {
    DurableLog::open(MemStorage::new(capacity)).unwrap().0
}

fn reopen(log: DurableLog<MemStorage>) -> (DurableLog<MemStorage>, Recovery) {
    DurableLog::open(log.into_storage()).unwrap()
}

fn put(rec: &mut Recorder, log: &mut DurableLog<MemStorage>, class: Class, t: u64, len: usize) -> Vec<Sealed> {
    rec.sample(class, &def(class as u32 + 1), t, Value::Blob(vec![t as u8; len]));
    let mut sealed = Vec::new();
    rec.tick(t, log, &mut sealed).unwrap();
    sealed
}

/// Every gap held by a readable P0 block.
fn held_gaps(log: &DurableLog<MemStorage>) -> Vec<Gap> {
    let mut out = Vec::new();
    for frame in log.read_all(Class::P0).unwrap() {
        if let Ok(block) = Block::decode(&frame.payload) {
            out.extend(block.gaps);
        }
    }
    out
}

fn is_declared(log: &DurableLog<MemStorage>, class: Class, seq: u64) -> bool {
    held_gaps(log)
        .iter()
        .any(|g| g.lost_class == class as u8 && g.lost_first_seq <= seq && seq < g.lost_first_seq + g.lost_records)
}

fn recovery(corrupt: Vec<LostRange>) -> Recovery {
    Recovery {
        truncated_bytes: [0; 3],
        corrupt,
    }
}

fn range(class: Class, first_seq: u64, count: u64) -> LostRange {
    LostRange {
        class,
        first_seq,
        count,
    }
}

/// Logical offset of the frame after `n` frames of `payload` bytes each.
fn at(n: u64, payload: usize) -> u64 {
    n * (HEADER_LEN + payload) as u64
}

/// Flip two bits of a frame's header: more than the log repairs, so it no longer parses.
fn rot_header(log: &mut DurableLog<MemStorage>, class: Class, frame_offset: u64) {
    log.storage_mut().corrupt(class, frame_offset + 20);
    log.storage_mut().corrupt(class, frame_offset + 21);
}

fn raw_frame(log: &DurableLog<MemStorage>, class: Class, offset: u64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    log.storage().read(class, offset, &mut bytes).unwrap();
    bytes
}

// log.rs: LostRange::contains

#[test]
fn a_rot_met_twice_is_noted_once() {
    let mut log = open(100_000);
    for k in 0..3u8 {
        log.append(Class::P1, 0, [k; 16], 1, &[k; 100]).unwrap();
    }
    log.storage_mut()
        .corrupt(Class::P1, at(1, 100) + HEADER_LEN as u64 + 10);
    let first = log.peek_unsent(Class::P1).unwrap().unwrap();
    log.mark_sent(&first);
    // The cursor stays where it is, so the next read meets the same rotted frame again.
    assert_eq!(log.peek_unsent(Class::P1).unwrap().unwrap().header.first_seq, 2);
    assert_eq!(log.peek_unsent(Class::P1).unwrap().unwrap().header.first_seq, 2);
    assert_eq!(log.undeclared(), [range(Class::P1, 1, 1)]);
}

#[test]
fn equal_ranges_in_different_classes_are_different_losses() {
    let mut log = open(100_000);
    for class in [Class::P1, Class::P2] {
        for k in 0..3u8 {
            log.append(class, 0, [k; 16], 1, &[k; 100]).unwrap();
        }
        log.storage_mut().corrupt(class, at(1, 100) + HEADER_LEN as u64 + 10);
        while let Some(frame) = log.peek_unsent(class).unwrap() {
            log.mark_sent(&frame);
        }
    }
    let mut undeclared = log.undeclared();
    undeclared.sort_by_key(|lost| lost.class as u8);
    assert_eq!(undeclared, [range(Class::P1, 1, 1), range(Class::P2, 1, 1)]);
}

// log.rs: Scan::next_header

#[test]
fn a_stale_copy_between_contiguous_frames_loses_nothing() {
    let mut log = open(100_000);
    log.append(Class::P1, 0, [0; 16], 1, &[0; 100]).unwrap();
    let copy = raw_frame(&log, Class::P1, 0, HEADER_LEN + 100);
    log.storage_mut().append(Class::P1, &copy).unwrap();
    log.append(Class::P1, 0, [1; 16], 1, &[1; 100]).unwrap();

    let first = log.peek_unsent(Class::P1).unwrap().unwrap();
    log.mark_sent(&first);
    let second = log.peek_unsent(Class::P1).unwrap().unwrap();
    assert_eq!(second.header.first_seq, 1);
    assert!(log.undeclared().is_empty(), "no sequence number is missing");

    let (log, recovery) = reopen(log);
    assert!(recovery.corrupt.is_empty());
    assert_eq!(log.first_retained_seq(Class::P1).unwrap(), 0);
}

#[test]
fn a_hole_is_reported_with_the_size_of_the_sequences_it_hides() {
    let mut log = open(100_000);
    log.append(Class::P1, 0, [0; 16], 1, &[0; 100]).unwrap();
    log.append(Class::P1, 0, [1; 16], 3, &[1; 100]).unwrap();
    log.append(Class::P1, 0, [2; 16], 1, &[2; 100]).unwrap();
    rot_header(&mut log, Class::P1, at(1, 100));
    let (_, recovery) = reopen(log);
    assert_eq!(recovery.corrupt, [range(Class::P1, 1, 3)]);
}

// log.rs: repaired_header_at

#[test]
fn a_rotted_header_that_ends_the_log_exactly_is_still_repaired() {
    // A frame with no payload is a header and nothing else: its rot is found at the very end.
    let mut log = open(100_000);
    log.append(Class::P1, 0, [0; 16], 1, &[0; 50]).unwrap();
    log.append(Class::P1, 0, [1; 16], 1, &[]).unwrap();
    log.storage_mut().corrupt(Class::P1, at(1, 50) + 20);
    let (log, recovery) = reopen(log);
    assert_eq!(recovery.corrupt, [range(Class::P1, 1, 1)]);
    assert_eq!(recovery.truncated_bytes, [0; 3]);
    assert_eq!(log.next_seq(Class::P1), 2);
}

// log.rs: trim

#[test]
fn an_eviction_moves_the_cursor_and_its_floor_past_what_it_removes() {
    // A stale copy of the first frame lies after it. Once the first frame is gone the cursor
    // must still know that sequence 0 is behind it, or the copy reads as new data.
    let mut log = open(100_000);
    log.append(Class::P1, 0, [0; 16], 1, &[0; 100]).unwrap();
    let copy = raw_frame(&log, Class::P1, 0, HEADER_LEN + 100);
    log.storage_mut().append(Class::P1, &copy).unwrap();
    log.append(Class::P1, 0, [1; 16], 1, &[1; 100]).unwrap();

    log.evict_through(Class::P1, at(1, 100)).unwrap();
    let next = log.peek_unsent(Class::P1).unwrap().unwrap();
    assert_eq!(next.header.first_seq, 1);
}

#[test]
fn trimming_one_class_keeps_the_rot_of_another() {
    let mut log = open(100_000);
    for k in 0..3u8 {
        log.append(Class::P1, 0, [k; 16], 1, &[k; 100]).unwrap();
    }
    for k in 0..4u8 {
        log.append(Class::P2, 0, [k; 16], 1, &[k; 100]).unwrap();
    }
    log.storage_mut()
        .corrupt(Class::P1, at(1, 100) + HEADER_LEN as u64 + 10);
    while let Some(frame) = log.peek_unsent(Class::P1).unwrap() {
        log.mark_sent(&frame);
    }
    log.ack(Class::P2, 4, 4).unwrap();
    assert_eq!(log.undeclared(), [range(Class::P1, 1, 1)]);
}

#[test]
fn removing_a_rotted_frame_removes_its_loss() {
    let mut log = open(100_000);
    for k in 0..3u8 {
        log.append(Class::P1, 0, [k; 16], 1, &[k; 100]).unwrap();
    }
    log.storage_mut()
        .corrupt(Class::P1, at(1, 100) + HEADER_LEN as u64 + 10);
    while let Some(frame) = log.peek_unsent(Class::P1).unwrap() {
        log.mark_sent(&frame);
    }
    assert_eq!(log.undeclared().len(), 1);
    // The frame ends exactly where the removal does: nothing of it is left to declare.
    log.evict_through(Class::P1, at(2, 100)).unwrap();
    assert!(log.undeclared().is_empty());
}

// recorder.rs: declarations

#[test]
fn a_loss_of_no_records_declares_nothing() {
    let mut log = open(100_000);
    let mut rec = eager();
    let mut sealed = Vec::new();
    rec.report_recovery(&recovery(vec![range(Class::P1, 5, 0)]), 10, &mut log, &mut sealed)
        .unwrap();
    assert!(sealed.is_empty());
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 0);
}

#[test]
fn many_losses_collapse_to_one_gap_that_over_reports() {
    let mut log = open(100_000);
    let mut rec = eager();
    let mut sealed = Vec::new();
    // Nine ranges that touch nothing: more than a declaration holds.
    let lost: Vec<LostRange> = (0..9).map(|k| range(Class::P2, 10 + 2 * k, 1)).collect();
    rec.report_recovery(&recovery(lost), 10, &mut log, &mut sealed).unwrap();
    let gaps = held_gaps(&log);
    assert_eq!(gaps.len(), 1);
    assert_eq!(
        gaps[0].reason,
        GapReason::BufferEvicted,
        "it no longer says what was lost to what"
    );
    assert_eq!(gaps[0].lost_class, Class::P2 as u8);
    assert_eq!(gaps[0].lost_first_seq, 10);
    assert_eq!(gaps[0].lost_records, 17);
}

#[test]
fn a_declaration_the_store_refuses_for_want_of_room_is_not_an_error() {
    struct Full<S>(S);
    impl<S: Storage> Storage for Full<S> {
        fn capacity(&self) -> u64 {
            self.0.capacity()
        }
        fn start(&self, class: Class) -> u64 {
            self.0.start(class)
        }
        fn end(&self, class: Class) -> u64 {
            self.0.end(class)
        }
        fn append(&mut self, _: Class, _: &[u8]) -> Result<(), StorageError> {
            Err(StorageError::Full)
        }
        fn read(&self, class: Class, offset: u64, buf: &mut [u8]) -> Result<(), StorageError> {
            self.0.read(class, offset, buf)
        }
        fn trim_front(&mut self, class: Class, new_start: u64) -> Result<(), StorageError> {
            self.0.trim_front(class, new_start)
        }
        fn truncate(&mut self, class: Class, new_end: u64) -> Result<(), StorageError> {
            self.0.truncate(class, new_end)
        }
        fn read_meta(&self, slot: usize) -> Result<Option<Vec<u8>>, StorageError> {
            self.0.read_meta(slot)
        }
        fn write_meta(&mut self, slot: usize, data: &[u8]) -> Result<(), StorageError> {
            self.0.write_meta(slot, data)
        }
    }
    let (mut log, _) = DurableLog::open(Full(MemStorage::new(100_000))).unwrap();
    let mut rec = eager();
    let mut sealed = Vec::new();
    let result = rec.report_recovery(&recovery(vec![range(Class::P1, 0, 3)]), 10, &mut log, &mut sealed);
    assert_eq!(result, Ok(()), "the loss stays undeclared and is tried again");
    assert!(sealed.is_empty());
}

#[test]
fn a_rotted_declaration_is_declared_again_with_what_it_carried() {
    let mut log = open(100_000);
    let mut rec = eager();
    let mut sealed = Vec::new();
    rec.report_recovery(&recovery(vec![range(Class::P1, 0, 5)]), 10, &mut log, &mut sealed)
        .unwrap();
    assert!(is_declared(&log, Class::P1, 4));
    // The declaration rots in the payload. Reading it notes the loss of a P0 block.
    log.storage_mut().corrupt(Class::P0, HEADER_LEN as u64 + 3);
    assert!(log.peek_unsent(Class::P0).unwrap().is_none());
    assert_eq!(log.undeclared(), [range(Class::P0, 0, 1)]);
    rec.tick(20, &mut log, &mut sealed).unwrap();
    assert!(log.undeclared().is_empty());
    for seq in 0..5 {
        assert!(
            is_declared(&log, Class::P1, seq),
            "P1 {seq} lost with the rotted declaration"
        );
    }
}

// recorder.rs: carrying gaps through the eviction of P0 frames

#[test]
fn gaps_declared_before_a_reboot_are_carried_through_the_eviction_of_their_declaration() {
    let mut log = open(2_000 + sl_core::log::DECLARATION_RESERVE);
    let mut rec = eager_with(1);
    for t in 0..4 {
        put(&mut rec, &mut log, Class::P1, t, 150);
    }
    // P0 grows until every P1 frame is evicted: the declaration is all that names them.
    let mut t = 4;
    while !log.read_all(Class::P1).unwrap().is_empty() {
        put(&mut rec, &mut log, Class::P0, t, 150);
        t += 1;
    }
    let lost = log.next_seq(Class::P1);
    assert!(lost > 0);
    // The new boot knows nothing of what the last one declared: only the frames say.
    let (mut log, _) = reopen(log);
    let mut rec = eager_with(2);
    let first_p0 = log.first_retained_seq(Class::P0).unwrap();
    for t in 100..300 {
        put(&mut rec, &mut log, Class::P0, t, 150);
        for seq in 0..lost {
            assert!(is_declared(&log, Class::P1, seq), "P1 {seq} undeclared after block {t}");
        }
    }
    assert!(
        log.first_retained_seq(Class::P0).unwrap() > first_p0 + 5,
        "P0 evicted its own frames"
    );
}

/// A log whose P0 holds two declarations of this boot, then data: one rot in the first
/// declaration's header if `rot_first`, and in the second's if not. Returns the log and the
/// recorder.
fn two_declarations_then_data(rot_first: bool) -> (DurableLog<MemStorage>, Recorder) {
    let mut log = open(3_000 + sl_core::log::DECLARATION_RESERVE);
    let mut rec = eager();
    let mut sealed = Vec::new();
    rec.report_recovery(&recovery(vec![range(Class::P1, 0, 5)]), 10, &mut log, &mut sealed)
        .unwrap();
    let second_at = log.storage().end(Class::P0);
    rec.report_recovery(&recovery(vec![range(Class::P2, 0, 3)]), 11, &mut log, &mut sealed)
        .unwrap();
    put(&mut rec, &mut log, Class::P0, 12, 100);
    rot_header(&mut log, Class::P0, if rot_first { 0 } else { second_at });
    (log, rec)
}

fn fill_p0_until_evicted(log: &mut DurableLog<MemStorage>, rec: &mut Recorder) {
    // Checked after every block once the eviction has begun: a gap may be restored later,
    // but it must never be missing from the held declarations in between.
    for t in 13..120 {
        put(rec, log, Class::P0, t, 100);
        // Until the rotted declaration is evicted nothing has read it, so nothing is owed yet.
        if log.first_retained_seq(Class::P0).unwrap() <= 2 {
            continue;
        }
        for seq in 0..5 {
            assert!(is_declared(log, Class::P1, seq), "P1 {seq} undeclared after block {t}");
        }
        for seq in 0..3 {
            assert!(is_declared(log, Class::P2, seq), "P2 {seq} undeclared after block {t}");
        }
    }
    assert!(
        log.first_retained_seq(Class::P0).unwrap() > 4,
        "P0 evicted its early frames"
    );
}

#[test]
fn a_rotted_header_before_the_first_evicted_frame_redeclares_this_boots_gaps() {
    let (mut log, mut rec) = two_declarations_then_data(true);
    fill_p0_until_evicted(&mut log, &mut rec);
    for seq in 0..5 {
        assert!(
            is_declared(&log, Class::P1, seq),
            "P1 {seq} lost with the rotted declaration"
        );
    }
    for seq in 0..3 {
        assert!(is_declared(&log, Class::P2, seq), "P2 {seq} lost");
    }
}

#[test]
fn a_rotted_header_between_evicted_frames_redeclares_this_boots_gaps() {
    let (mut log, mut rec) = two_declarations_then_data(false);
    fill_p0_until_evicted(&mut log, &mut rec);
    for seq in 0..5 {
        assert!(is_declared(&log, Class::P1, seq), "P1 {seq} lost");
    }
    for seq in 0..3 {
        assert!(
            is_declared(&log, Class::P2, seq),
            "P2 {seq} lost with the rotted declaration"
        );
    }
}

#[test]
fn the_largest_declaration_fits_the_bound_and_the_bound_is_not_slack() {
    let gap = |k: u64| Gap {
        reason: GapReason::Corrupt,
        lost_class: 2,
        from_boot: u32::MAX,
        from_mono_ms: u64::MAX,
        to_mono_ms: u64::MAX,
        lost_first_seq: u64::MAX - 1_000 * k,
        lost_records: u64::MAX,
    };
    let mut block = Block::new(u32::MAX, u32::MAX);
    block.gaps = (0..sl_core::recorder::MAX_DECLARED_GAPS as u64).map(gap).collect();
    let mut encoded = Vec::new();
    block.encode(&mut encoded);
    let largest = (HEADER_LEN + encoded.len()) as u64;
    let bound = sl_core::recorder::DECLARATION_MAX;
    assert!(
        largest <= bound,
        "a declaration of {largest} bytes outgrows the bound of {bound}"
    );
    assert!(
        bound - largest < 47,
        "the bound is a whole gap larger than it needs to be"
    );
}

// recorder.rs: where the declaration's room is drawn

/// P2 holds a frame of 360 bytes and one of 60, then a P1 block goes in. Returns whether the
/// block was stored, the bytes the declaration took, and the bytes the block took.
fn offer_a_block_to_a_store_with_two_victims(capacity: u64) -> (bool, u64, u64) {
    let mut log = open(capacity);
    log.append(Class::P2, 0, [1; 16], 1, &[7; 300]).unwrap();
    log.append(Class::P2, 0, [2; 16], 1, &[]).unwrap();
    let mut rec = eager();
    put(&mut rec, &mut log, Class::P1, 0, 600);
    let block = log.storage().end(Class::P1) - log.storage().start(Class::P1);
    let declaration = log.storage().end(Class::P0) - log.storage().start(Class::P0);
    (
        !log.read_all(Class::P1).unwrap().is_empty() && declaration > 0,
        declaration,
        block,
    )
}

#[test]
fn a_block_is_stored_exactly_when_the_evictions_free_room_for_it_and_its_declaration() {
    // With room to spare nothing is evicted; measure what the block takes.
    let mut log = open(100_000);
    let mut rec = eager();
    put(&mut rec, &mut log, Class::P1, 0, 600);
    let block = log.storage().end(Class::P1);
    let held = 360 + 60;
    let mut smallest = None;
    for capacity in (block + sl_core::log::DECLARATION_RESERVE..held + block + sl_core::log::DECLARATION_RESERVE).rev()
    {
        let (stored, declaration, _) = offer_a_block_to_a_store_with_two_victims(capacity);
        if !stored {
            break;
        }
        smallest = Some((capacity, declaration));
    }
    let (capacity, declaration) = smallest.expect("the block is stored when a victim can make room");
    assert_eq!(
        capacity,
        block + sl_core::log::DECLARATION_RESERVE + declaration,
        "the smallest store that takes the block is the block, the reserve and one declaration"
    );
}

#[test]
fn a_declaration_may_only_use_the_reserve_down_to_the_size_of_the_largest() {
    // A declaration that frees nothing leaves `DECLARATION_MAX` of the reserve for the one
    // an eviction needs; one byte less room and it goes out with an eviction instead.
    let mut dry = open(100_000);
    let mut rec = eager();
    put(&mut rec, &mut dry, Class::P2, 0, 200);
    let used = dry.used();
    let mut sealed = Vec::new();
    rec.report_recovery(&recovery(vec![range(Class::P1, 0, 3)]), 10, &mut dry, &mut sealed)
        .unwrap();
    let declaration = dry.storage().end(Class::P0);

    let run = |capacity: u64| {
        let mut log = open(capacity);
        let mut rec = eager();
        put(&mut rec, &mut log, Class::P2, 0, 200);
        let mut sealed = Vec::new();
        rec.report_recovery(&recovery(vec![range(Class::P1, 0, 3)]), 10, &mut log, &mut sealed)
            .unwrap();
        assert_eq!(sealed.len(), 1);
        assert!(is_declared(&log, Class::P1, 2));
        log.read_all(Class::P2).unwrap().len()
    };
    let exact = used + declaration + sl_core::recorder::DECLARATION_MAX;
    assert_eq!(run(exact), 1, "the declaration fits without evicting anything");
    assert_eq!(run(exact - 1), 0, "one byte short, an eviction makes room for it");
}

#[cfg(feature = "zstd")]
#[test]
fn a_block_too_large_before_compression_is_dropped_though_it_would_fit_after() {
    // The server refuses a block over the limit however small its compressed form is, so the
    // recorder must not store one.
    let mut log = open(200_000);
    let mut rec = Recorder::new(
        RecorderConfig {
            seal_ms: [0; 3],
            compression: sl_proto::compress::Compression::Zstd,
            ..RecorderConfig::default()
        },
        1,
    );
    let mut sealed = Vec::new();
    rec.sample(
        Class::P2,
        &def(3),
        0,
        Value::Blob(vec![0; sl_proto::block::MAX_BLOCK_BYTES + 1_000]),
    );
    rec.tick(1, &mut log, &mut sealed).unwrap();
    assert!(log.read_all(Class::P2).unwrap().is_empty());
    assert!(is_declared(&log, Class::P2, 0), "the dropped block is declared");
}
