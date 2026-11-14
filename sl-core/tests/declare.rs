//! Declare before destroy: the log never removes a record that no durable gap declares.

use core::cell::{Cell, RefCell};

use sl_core::frame::{FORMAT_V1, HEADER_LEN, build_frame};
use sl_core::log::{DECLARATION_RESERVE, DurableLog, LostRange};
use sl_core::mem_storage::MemStorage;
use sl_core::recorder::{Recorder, RecorderConfig, Sealed};
use sl_core::storage::{Storage, StorageError};
use sl_proto::block::Block;
use sl_proto::ids::Class;
use sl_proto::record::{Define, GapReason, Kind};
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

/// A recorder that seals every class on every tick, without compression.
fn eager() -> Recorder {
    Recorder::new(
        RecorderConfig {
            seal_ms: [0; 3],
            ..RecorderConfig::default()
        },
        1,
    )
}

fn open(capacity: u64) -> DurableLog<MemStorage> {
    DurableLog::open(MemStorage::new(capacity)).unwrap().0
}

fn reopen<S: Storage>(log: DurableLog<S>) -> (DurableLog<S>, sl_core::log::Recovery) {
    DurableLog::open(log.into_storage()).unwrap()
}

/// Record one blob of `len` bytes into `class` and tick.
fn put<S: Storage>(rec: &mut Recorder, log: &mut DurableLog<S>, class: Class, t: u64, len: usize) -> Vec<Sealed> {
    rec.sample(class, &def(class as u32 + 1), t, Value::Blob(vec![t as u8; len]));
    let mut sealed = Vec::new();
    rec.tick(t, log, &mut sealed).unwrap();
    sealed
}

/// Every lost range declared by the P0 blocks the log holds, as `(class, first, end)`.
fn declared<S: Storage>(log: &DurableLog<S>) -> Vec<(u8, u64, u64)> {
    let mut out = Vec::new();
    for frame in log.read_all(Class::P0).unwrap() {
        let Ok(block) = Block::decode(&frame.payload) else {
            continue;
        };
        for g in block.gaps {
            out.push((g.lost_class, g.lost_first_seq, g.lost_first_seq + g.lost_records));
        }
    }
    out
}

fn is_declared<S: Storage>(log: &DurableLog<S>, class: Class, seq: u64) -> bool {
    declared(log)
        .iter()
        .any(|&(c, first, end)| c == class as u8 && first <= seq && seq < end)
}

/// `MemStorage` that writes down every append and trim, in order.
struct Recording<'a> {
    inner: MemStorage,
    ops: &'a RefCell<Vec<String>>,
}

impl Storage for Recording<'_> {
    fn capacity(&self) -> u64 {
        self.inner.capacity()
    }
    fn start(&self, class: Class) -> u64 {
        self.inner.start(class)
    }
    fn end(&self, class: Class) -> u64 {
        self.inner.end(class)
    }
    fn append(&mut self, class: Class, data: &[u8]) -> Result<(), StorageError> {
        self.ops.borrow_mut().push(format!("append {class:?}"));
        self.inner.append(class, data)
    }
    fn read(&self, class: Class, offset: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        self.inner.read(class, offset, buf)
    }
    fn trim_front(&mut self, class: Class, new_start: u64) -> Result<(), StorageError> {
        self.ops.borrow_mut().push(format!("trim {class:?}"));
        self.inner.trim_front(class, new_start)
    }
    fn truncate(&mut self, class: Class, new_end: u64) -> Result<(), StorageError> {
        self.inner.truncate(class, new_end)
    }
    fn read_meta(&self, slot: usize) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.read_meta(slot)
    }
    fn write_meta(&mut self, slot: usize, data: &[u8]) -> Result<(), StorageError> {
        self.inner.write_meta(slot, data)
    }
}

#[test]
fn an_eviction_is_declared_before_anything_is_trimmed() {
    let ops = RefCell::new(Vec::new());
    let storage = Recording {
        inner: MemStorage::new(1_000 + DECLARATION_RESERVE),
        ops: &ops,
    };
    let (mut log, _) = DurableLog::open(storage).unwrap();
    let mut rec = eager();
    for t in 0..3 {
        put(&mut rec, &mut log, Class::P2, t, 200);
    }
    ops.borrow_mut().clear();
    let sealed = put(&mut rec, &mut log, Class::P1, 3, 400);

    let ops = ops.borrow().clone();
    assert_eq!(ops, ["append P0", "trim P2", "append P1"], "declare, destroy, write");
    assert_eq!(sealed.len(), 2);
    assert_eq!(sealed[0].class, Class::P0, "the declaration is reported like any block");
    assert!(is_declared(&log, Class::P2, 0));
}

#[test]
fn the_reserve_is_only_for_declarations() {
    let mut log = open(1_000 + DECLARATION_RESERVE);
    let frame = 1_000 - HEADER_LEN;
    log.append(Class::P1, 0, [1; 16], 1, &vec![1; frame]).unwrap();
    assert_eq!(log.append(Class::P1, 0, [2; 16], 1, b"x"), Err(StorageError::Full));
    let declaration = vec![0; DECLARATION_RESERVE as usize - HEADER_LEN];
    assert_eq!(log.append_declaration(0, [3; 16], 1, &declaration).unwrap(), 0);
    assert_eq!(log.used(), 1_000 + DECLARATION_RESERVE);
}

#[test]
fn eviction_makes_progress_at_the_smallest_capacity() {
    // Room for one ordinary frame of this size beside one declaration. P0 is the hard case:
    // it evicts its own frames, earlier declarations among them, and carries their gaps.
    let mut rec = eager();
    let mut log = open(300 + 100 + DECLARATION_RESERVE);
    for t in 0..50 {
        let sealed = put(&mut rec, &mut log, Class::P0, t, 200);
        // The block itself, not only a declaration of its loss, is the newest frame.
        let newest = log.read_all(Class::P0).unwrap().pop().unwrap();
        assert!(newest.payload.len() > 200, "tick {t} dropped its block");
        assert_eq!(Some(newest.header.first_seq), sealed.last().map(|s| s.first_seq));
    }
    let first = log.first_retained_seq(Class::P0).unwrap();
    for seq in 0..first {
        assert!(is_declared(&log, Class::P0, seq), "P0 {seq} lost without a gap");
    }
}

#[test]
fn gaps_are_carried_forward_through_a_chain_of_p0_evictions() {
    let mut rec = eager();
    let mut log = open(2_000 + DECLARATION_RESERVE);
    // P2 and P1 fill up and are evicted, then P0 alone evicts its own frames, including the
    // declarations that name those losses.
    for t in 0..10 {
        put(&mut rec, &mut log, Class::P2, t, 150);
        put(&mut rec, &mut log, Class::P1, t, 150);
    }
    for t in 10..200 {
        put(&mut rec, &mut log, Class::P0, t, 120);
    }
    assert!(
        log.first_retained_seq(Class::P0).unwrap() > 20,
        "P0 evicted its own frames"
    );
    for class in Class::ALL {
        let first = log.first_retained_seq(class).unwrap();
        for seq in 0..first {
            assert!(is_declared(&log, class, seq), "{class:?} {seq} lost without a held gap");
        }
    }
}

#[test]
fn rot_found_at_run_time_blocks_the_trim_until_declared() {
    let mut log = open(100_000);
    for k in 0..3u8 {
        log.append(Class::P1, 0, [k; 16], 1, &[k; 100]).unwrap();
    }
    let second_payload = (HEADER_LEN + 100 + HEADER_LEN + 10) as u64;
    log.storage_mut().corrupt(Class::P1, second_payload);

    // Upload what reads: frames 0 and 2. The server's marks pass the rotted frame.
    while let Some(frame) = log.peek_unsent(Class::P1).unwrap() {
        log.mark_sent(&frame);
    }
    let rot = LostRange {
        class: Class::P1,
        first_seq: 1,
        count: 1,
    };
    assert_eq!(log.undeclared(), [rot]);
    log.ack(Class::P1, 3, 3).unwrap();
    assert_eq!(log.first_retained_seq(Class::P1).unwrap(), 1, "kept from the rot on");

    let mut rec = eager();
    let mut sealed = Vec::new();
    rec.tick(5, &mut log, &mut sealed).unwrap();
    assert_eq!(sealed.len(), 1, "one declaration");
    assert!(log.undeclared().is_empty());
    let block = Block::decode(&log.read_all(Class::P0).unwrap()[0].payload).unwrap();
    assert_eq!(block.gaps[0].reason, GapReason::Corrupt);
    assert_eq!((block.gaps[0].lost_first_seq, block.gaps[0].lost_records), (1, 1));

    log.ack(Class::P1, 3, 3).unwrap();
    assert_eq!(log.first_retained_seq(Class::P1).unwrap(), 3);
}

#[test]
fn open_keeps_a_rotted_tail_frame_and_moves_past_it() {
    let mut log = open(100_000);
    for k in 0..2u8 {
        log.append(Class::P2, 0, [k; 16], 2, &[k; 100]).unwrap();
    }
    let end = log.storage().end(Class::P2);
    log.storage_mut().corrupt(Class::P2, end - 1);

    let (mut log, recovery) = reopen(log);
    assert_eq!(recovery.truncated_bytes, [0; 3]);
    assert_eq!(
        recovery.corrupt,
        [LostRange {
            class: Class::P2,
            first_seq: 2,
            count: 2
        }]
    );
    assert_eq!(log.storage().end(Class::P2), end, "kept on disk");
    assert_eq!(log.append(Class::P2, 0, [9; 16], 1, b"x").unwrap(), 4);
}

#[test]
fn open_repairs_one_flipped_bit_in_a_tail_header_to_find_what_was_lost() {
    let mut log = open(100_000);
    log.append(Class::P1, 0, [1; 16], 3, &[1; 100]).unwrap();
    let newest = log.storage().end(Class::P1);
    log.append(Class::P1, 0, [2; 16], 5, &[2; 100]).unwrap();
    // The magic byte of the newest frame; the metadata was never written.
    log.storage_mut().corrupt(Class::P1, newest);

    let (mut log, recovery) = reopen(log);
    assert_eq!(recovery.truncated_bytes, [0; 3]);
    assert_eq!(
        recovery.corrupt,
        [LostRange {
            class: Class::P1,
            first_seq: 3,
            count: 5
        }]
    );
    assert_eq!(log.append(Class::P1, 0, [9; 16], 1, b"x").unwrap(), 8);
}

#[test]
fn open_still_truncates_a_torn_write() {
    let mut log = open(100_000);
    log.append(Class::P0, 0, [1; 16], 1, &[1; 100]).unwrap();
    let frame = build_frame(FORMAT_V1, 0, 1, 1, [2; 16], [0; 16], &[2; 100]);
    log.storage_mut().append(Class::P0, &frame[..HEADER_LEN + 40]).unwrap();

    let (mut log, recovery) = reopen(log);
    assert_eq!(recovery.truncated_bytes, [(HEADER_LEN + 40) as u64, 0, 0]);
    assert!(recovery.corrupt.is_empty());
    assert_eq!(
        log.append(Class::P0, 0, [3; 16], 1, b"x").unwrap(),
        1,
        "never written, so reused"
    );
}

#[test]
fn recovery_is_declared_at_boot_and_then_trimmed_normally() {
    let mut log = open(100_000);
    for k in 0..3u8 {
        log.append(Class::P1, 0, [k; 16], 1, &[k; 100]).unwrap();
    }
    log.storage_mut().corrupt(Class::P1, (HEADER_LEN + 10) as u64);
    let (mut log, recovery) = reopen(log);

    let mut rec = eager();
    let mut sealed = Vec::new();
    rec.report_recovery(&recovery, 0, &mut log, &mut sealed).unwrap();
    assert_eq!(sealed.len(), 1);
    assert!(log.undeclared().is_empty());
    assert!(is_declared(&log, Class::P1, 0));

    log.ack(Class::P1, 3, 3).unwrap();
    assert_eq!(log.first_retained_seq(Class::P1).unwrap(), 3);
}

#[test]
fn a_declaration_with_no_room_is_owed_not_an_error() {
    let mut log = open(1_000 + DECLARATION_RESERVE);
    // Ordinary frames fill their room, and declarations the whole reserve.
    log.append(Class::P0, 0, [1; 16], 1, &vec![1; 1_000 - HEADER_LEN])
        .unwrap();
    log.append_declaration(0, [2; 16], 1, &vec![2; DECLARATION_RESERVE as usize - HEADER_LEN])
        .unwrap();

    // A P2 block cannot evict P0, so it is dropped, and its loss cannot be written yet.
    let mut rec = eager();
    let sealed = put(&mut rec, &mut log, Class::P2, 1, 100);
    assert!(sealed.is_empty());
    assert_eq!(log.next_seq(Class::P2), 2, "its numbers are used up all the same");

    // Once the server backs P0 up, the owed declaration goes out first.
    log.ack(Class::P0, 2, 2).unwrap();
    let sealed = put(&mut rec, &mut log, Class::P2, 2, 10);
    assert_eq!(sealed[0].class, Class::P0);
    assert!(is_declared(&log, Class::P2, 0) && is_declared(&log, Class::P2, 1));
}

#[test]
fn a_header_that_rots_at_run_time_is_found_by_the_upload_scan() {
    let mut log = open(100_000);
    log.append(Class::P2, 0, [1; 16], 2, &[1; 100]).unwrap();
    let newest = log.storage().end(Class::P2);
    log.append(Class::P2, 0, [2; 16], 3, &[2; 100]).unwrap();
    log.storage_mut().corrupt(Class::P2, newest + 20);

    while let Some(frame) = log.peek_unsent(Class::P2).unwrap() {
        log.mark_sent(&frame);
    }
    assert_eq!(
        log.undeclared(),
        [LostRange {
            class: Class::P2,
            first_seq: 2,
            count: 3
        }]
    );
}

/// `MemStorage` whose metadata writes, or P0 appends, can be made to fail.
struct Faulty<'a> {
    inner: MemStorage,
    fail_meta: &'a Cell<bool>,
    fail_p0: &'a Cell<bool>,
}

impl Storage for Faulty<'_> {
    fn capacity(&self) -> u64 {
        self.inner.capacity()
    }
    fn start(&self, class: Class) -> u64 {
        self.inner.start(class)
    }
    fn end(&self, class: Class) -> u64 {
        self.inner.end(class)
    }
    fn append(&mut self, class: Class, data: &[u8]) -> Result<(), StorageError> {
        if class == Class::P0 && self.fail_p0.get() {
            return Err(StorageError::Io);
        }
        self.inner.append(class, data)
    }
    fn read(&self, class: Class, offset: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        self.inner.read(class, offset, buf)
    }
    fn trim_front(&mut self, class: Class, new_start: u64) -> Result<(), StorageError> {
        self.inner.trim_front(class, new_start)
    }
    fn truncate(&mut self, class: Class, new_end: u64) -> Result<(), StorageError> {
        self.inner.truncate(class, new_end)
    }
    fn read_meta(&self, slot: usize) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.read_meta(slot)
    }
    fn write_meta(&mut self, slot: usize, data: &[u8]) -> Result<(), StorageError> {
        if self.fail_meta.get() {
            return Err(StorageError::Io);
        }
        self.inner.write_meta(slot, data)
    }
}

#[test]
fn rot_that_grows_past_a_declared_range_is_declared_before_it_is_trimmed() {
    // P1 holds A(0), B(1), C(2), D(3).
    let mut log = open(100_000);
    let frame = (HEADER_LEN + 100) as u64;
    for k in 0..4u8 {
        log.append(Class::P1, 0, [k; 16], 1, &[k; 100]).unwrap();
    }
    // B's header rots. The scan steps past it to C, which waits for credit.
    log.storage_mut().corrupt(Class::P1, frame + 20);
    let a = log.peek_unsent(Class::P1).unwrap().unwrap();
    log.mark_sent(&a);
    let c = log.peek_unsent(Class::P1).unwrap().unwrap();
    assert_eq!(c.header.first_seq, 2);
    let mut rec = eager();
    let mut sealed = Vec::new();
    rec.tick(1, &mut log, &mut sealed).unwrap();
    assert!(is_declared(&log, Class::P1, 1));

    // C's header rots too. The scan now steps past B and C as one stretch, [1, 3).
    log.storage_mut().corrupt(Class::P1, 2 * frame + 20);
    let d = log.peek_unsent(Class::P1).unwrap().unwrap();
    assert_eq!(d.header.first_seq, 3);
    assert!(!log.undeclared().is_empty(), "C's loss is noted");
    log.mark_sent(&d);
    rec.tick(2, &mut log, &mut sealed).unwrap();
    log.ack(Class::P1, 4, 4).unwrap();
    assert!(is_declared(&log, Class::P1, 2), "seq 2 trimmed without a durable gap");
}

#[test]
fn declarations_that_free_nothing_leave_room_to_declare_an_eviction() {
    let mut log = open(2_000 + DECLARATION_RESERVE);
    let mut rec = eager();
    let mut t = 0;
    while log.used() + 300 < 2_000 {
        t += 1;
        put(&mut rec, &mut log, Class::P2, t, 200);
    }
    // Eight P2 blocks too large ever to fit: each is dropped, and its loss declared or owed.
    let dropped_from = log.next_seq(Class::P2);
    for _ in 0..8 {
        t += 1;
        put(&mut rec, &mut log, Class::P2, t, 3_000);
    }
    let dropped_to = log.next_seq(Class::P2);
    assert!(dropped_to > dropped_from);

    // A P0 block evicts old P2 to make room; it is not dropped.
    let p0_next = log.next_seq(Class::P0);
    t += 1;
    put(&mut rec, &mut log, Class::P0, t, 200);
    let stored = log.read_all(Class::P0).unwrap().iter().any(|frame| {
        frame.header.first_seq >= p0_next && Block::decode(&frame.payload).is_ok_and(|block| !block.columns.is_empty())
    });
    assert!(stored, "P0 data dropped while old P2 data stayed");
    // What was owed went out with the eviction's declaration, not a later one.
    for seq in dropped_from..dropped_to {
        assert!(is_declared(&log, Class::P2, seq), "dropped P2 {seq} not declared");
    }
}

#[test]
fn evicting_a_rotted_p0_declaration_declares_this_boots_losses_again() {
    let mut log = open(3_000 + DECLARATION_RESERVE);
    let mut rec = eager();
    // A P2 block too large ever to fit: dropped, and declared in P0 frame 0.
    put(&mut rec, &mut log, Class::P2, 1, 4_000);
    assert!(is_declared(&log, Class::P2, 0));
    // That declaration's payload rots, and P0 fills up offline until it is evicted.
    log.storage_mut().corrupt(Class::P0, HEADER_LEN as u64 + 5);
    for t in 2..42 {
        put(&mut rec, &mut log, Class::P0, t, 200);
    }
    assert!(log.first_retained_seq(Class::P0).unwrap() > 0, "frame 0 was evicted");
    assert!(is_declared(&log, Class::P2, 0), "its only declaration was evicted");
}

#[test]
fn a_dropped_block_is_reported_declared_even_when_its_skip_fails() {
    let fail_meta = Cell::new(false);
    let fail_p0 = Cell::new(false);
    let storage = Faulty {
        inner: MemStorage::new(3_000 + DECLARATION_RESERVE),
        fail_meta: &fail_meta,
        fail_p0: &fail_p0,
    };
    let (mut log, _) = DurableLog::open(storage).unwrap();
    let mut rec = eager();
    rec.sample(Class::P2, &def(3), 1, Value::Blob(vec![1; 4_000]));
    fail_meta.set(true);
    let mut sealed = Vec::new();
    assert_eq!(rec.tick(1, &mut log, &mut sealed), Err(StorageError::Io));
    assert!(is_declared(&log, Class::P2, 0));
    assert_eq!(sealed.len(), 1, "the durable declaration is reported");
    assert_eq!(sealed[0].class, Class::P0);
}

#[test]
fn a_block_lost_while_making_room_is_accounted_for_like_any_dropped_block() {
    let fail_meta = Cell::new(false);
    let fail_p0 = Cell::new(false);
    let storage = Faulty {
        inner: MemStorage::new(1_000 + DECLARATION_RESERVE),
        fail_meta: &fail_meta,
        fail_p0: &fail_p0,
    };
    let (mut log, _) = DurableLog::open(storage).unwrap();
    let mut rec = eager();
    for t in 0..3 {
        put(&mut rec, &mut log, Class::P2, t, 200);
    }
    // The eviction's declaration fails to write, so the P1 block is lost.
    rec.sample(Class::P1, &def(2), 3, Value::Blob(vec![3; 400]));
    fail_p0.set(true);
    let mut sealed = Vec::new();
    assert_eq!(rec.tick(3, &mut log, &mut sealed), Err(StorageError::Io));
    fail_p0.set(false);
    assert!(log.next_seq(Class::P1) > 0, "its numbers are used up");

    // The next block of that signal carries its definition again, and the loss is declared.
    let sealed = put(&mut rec, &mut log, Class::P1, 4, 10);
    let block = sealed.iter().find(|s| s.class == Class::P1).unwrap();
    let frame = log
        .read_all(Class::P1)
        .unwrap()
        .into_iter()
        .find(|f| f.header.first_seq == block.first_seq)
        .unwrap();
    assert_eq!(Block::decode(&frame.payload).unwrap().defines.len(), 1);
    assert!(is_declared(&log, Class::P1, 0));
}

#[test]
fn open_repairs_a_flipped_bit_in_each_of_the_two_newest_headers() {
    let mut log = open(100_000);
    log.append(Class::P1, 0, [1; 16], 3, &[1; 100]).unwrap();
    let second = log.storage().end(Class::P1);
    log.append(Class::P1, 0, [2; 16], 5, &[2; 100]).unwrap();
    let third = log.storage().end(Class::P1);
    log.append(Class::P1, 0, [3; 16], 2, &[3; 100]).unwrap();
    // The metadata was never written, so only the frames say where the sequence stands.
    log.storage_mut().corrupt(Class::P1, second + 20);
    log.storage_mut().corrupt(Class::P1, third + 20);

    let (mut log, recovery) = reopen(log);
    assert_eq!(recovery.truncated_bytes, [0; 3]);
    assert_eq!(
        recovery.corrupt,
        [
            LostRange {
                class: Class::P1,
                first_seq: 3,
                count: 5
            },
            LostRange {
                class: Class::P1,
                first_seq: 8,
                count: 2
            }
        ]
    );
    assert_eq!(log.append(Class::P1, 0, [9; 16], 1, b"x").unwrap(), 10);
}

#[test]
fn rot_found_in_a_full_store_is_declared_by_evicting_rather_than_left_blocking_the_trim() {
    // Ordinary frames fill their room; the oldest one rots.
    let mut log = open(1_000 + DECLARATION_RESERVE);
    for k in 0..5u8 {
        log.append(Class::P0, 0, [k; 16], 1, &[k; 200 - HEADER_LEN]).unwrap();
    }
    assert_eq!(log.used(), 1_000);
    log.storage_mut().corrupt(Class::P0, (HEADER_LEN + 10) as u64);
    let frame = log.peek_unsent(Class::P0).unwrap().unwrap();
    assert_eq!(frame.header.first_seq, 1);
    assert_eq!(log.undeclared().len(), 1);

    // There is no room for the declaration above the part of the reserve kept for evictions,
    // so it goes out with one, and the trim is no longer held at the rot.
    let mut rec = eager();
    let mut sealed = Vec::new();
    rec.tick(1, &mut log, &mut sealed).unwrap();
    assert_eq!(sealed.len(), 1);
    assert!(log.undeclared().is_empty());
    assert!(is_declared(&log, Class::P0, 0));
    let first = log.first_retained_seq(Class::P0).unwrap();
    for seq in 0..first {
        assert!(is_declared(&log, Class::P0, seq), "P0 {seq} lost without a gap");
    }
}

// The backup mark the log keeps never passes a loss that no durable gap declares
// (STOR-005). The server commits across a hole the upload stepped over, so its mark can lie
// above records it does not hold; and after a restart the stored mark is all that says where
// a loss at the very front of a class begins.

/// Five P2 frames of two records each and one P1 frame. The header of the second P2 frame
/// (records 2 and 3) has rotted.
fn log_with_a_rotted_header() -> DurableLog<MemStorage> {
    let mut log = open(100_000);
    for k in 0..5u8 {
        log.append(Class::P2, 0, [k; 16], 2, &[k; 100]).unwrap();
    }
    log.append(Class::P1, 0, [9; 16], 1, &[9; 100]).unwrap();
    log.storage_mut().corrupt(Class::P2, (HEADER_LEN + 100 + 20) as u64);
    log
}

const ROT: LostRange = LostRange {
    class: Class::P2,
    first_seq: 2,
    count: 2,
};

/// Send everything that reads, as a session does.
fn upload<S: Storage>(log: &mut DurableLog<S>) {
    for class in Class::ALL {
        while let Some(frame) = log.peek_unsent(class).unwrap() {
            log.mark_sent(&frame);
        }
    }
}

/// The server has committed and backed up everything it was sent. Emptying P1 is what makes
/// the log write its metadata. A failed write is a power cut.
fn ack_all<S: Storage>(log: &mut DurableLog<S>) -> Result<(), StorageError> {
    log.ack(Class::P2, 10, 10)?;
    log.ack(Class::P1, 1, 1)
}

/// A restart, as a device does it: open, declare what `open` found, then a new session whose
/// Welcome carries the server's marks. The rot must be declared, or still held, at every step.
fn restart_and_finish(log: DurableLog<MemStorage>, at: &str) {
    let mut storage = log.into_storage();
    storage.power_on();
    let (mut log, recovery) = DurableLog::open(storage).unwrap();
    let mut rec = eager();
    let mut sealed = Vec::new();
    rec.report_recovery(&recovery, 50, &mut log, &mut sealed).unwrap();
    let covered = |log: &DurableLog<MemStorage>| is_declared(log, Class::P2, 2) && is_declared(log, Class::P2, 3);
    let held = |log: &DurableLog<MemStorage>| log.first_retained_seq(Class::P2).unwrap() <= 4;

    ack_all(&mut log).unwrap();
    assert!(
        covered(&log) || held(&log),
        "{at}: trimmed undeclared after the Welcome"
    );
    upload(&mut log);
    rec.tick(60, &mut log, &mut sealed).unwrap();
    assert!(covered(&log), "{at}: the rot was never declared");
    ack_all(&mut log).unwrap();
    assert_eq!(
        log.first_retained_seq(Class::P2).unwrap(),
        10,
        "{at}: the trim never resumed"
    );
    assert_eq!(log.backed_up_next(Class::P2), 10, "{at}: the mark never caught up");
}

#[test]
fn the_backup_mark_is_held_at_an_undeclared_loss() {
    let mut log = log_with_a_rotted_header();
    upload(&mut log);
    assert_eq!(log.undeclared(), [ROT]);

    ack_all(&mut log).unwrap();
    assert_eq!(
        log.first_retained_seq(Class::P2).unwrap(),
        4,
        "frame 0..2 went, the rot is in front"
    );
    assert_eq!(log.backed_up_next(Class::P2), 2, "held at the rot");
    assert_eq!(log.committed_next(Class::P2), 10, "the commit mark is the server's");
    assert_eq!(log.backed_up_next(Class::P1), 1, "another class is not held");

    // Once a durable gap declares the rot, the next ack moves the mark and trims.
    let mut rec = eager();
    let mut sealed = Vec::new();
    rec.tick(5, &mut log, &mut sealed).unwrap();
    assert_eq!(log.backed_up_next(Class::P2), 2, "only an ack moves it");
    ack_all(&mut log).unwrap();
    assert_eq!(log.backed_up_next(Class::P2), 10);
    assert_eq!(log.first_retained_seq(Class::P2).unwrap(), 10);
}

#[test]
fn rot_at_the_front_is_found_again_after_a_restart() {
    let mut log = log_with_a_rotted_header();
    upload(&mut log);
    ack_all(&mut log).unwrap();

    // The crash of STOR-005: the metadata was written by the P1 trim, nothing was declared.
    let (log, recovery) = reopen(log);
    assert_eq!(log.backed_up_next(Class::P2), 2, "the stored mark is the held one");
    assert_eq!(recovery.corrupt, [ROT], "open reports the front loss from the mark");
    assert_eq!(log.undeclared(), [ROT]);
    assert_eq!(log.front_seq(Class::P2), 2, "an eviction would declare from the rot on");
}

#[test]
fn a_restart_at_any_point_between_rot_and_declaration_loses_nothing_silently() {
    // Before the upload has seen the rot.
    restart_and_finish(log_with_a_rotted_header(), "after the rot");

    // After the upload stepped over it.
    let mut log = log_with_a_rotted_header();
    upload(&mut log);
    restart_and_finish(log, "after the upload");

    // After the server's marks passed it.
    let mut log = log_with_a_rotted_header();
    upload(&mut log);
    ack_all(&mut log).unwrap();
    restart_and_finish(log, "after the ack");

    // After the declaration, before the ack that trims past it.
    let mut log = log_with_a_rotted_header();
    upload(&mut log);
    ack_all(&mut log).unwrap();
    let mut sealed = Vec::new();
    eager().tick(5, &mut log, &mut sealed).unwrap();
    restart_and_finish(log, "after the declaration");

    // After the rot itself has been trimmed.
    let mut log = log_with_a_rotted_header();
    upload(&mut log);
    ack_all(&mut log).unwrap();
    let mut sealed = Vec::new();
    eager().tick(5, &mut log, &mut sealed).unwrap();
    ack_all(&mut log).unwrap();
    assert_eq!(log.first_retained_seq(Class::P2).unwrap(), 10);
    restart_and_finish(log, "after the trim");
}

#[test]
fn a_power_cut_at_any_byte_of_the_ack_or_the_declaration_loses_nothing_silently() {
    // The acks write one copy of the metadata; the declaration is one P0 frame.
    for bytes in 0..=200u64 {
        let mut log = log_with_a_rotted_header();
        upload(&mut log);
        log.storage_mut().cut_power_after(bytes);
        let _ = ack_all(&mut log);
        restart_and_finish(log, &format!("ack cut after {bytes} bytes"));

        // The same cut with the previous copy of the metadata already carrying marks.
        let mut log = log_with_a_rotted_header();
        upload(&mut log);
        ack_all(&mut log).unwrap();
        log.storage_mut().cut_power_after(bytes);
        let _ = ack_all(&mut log);
        restart_and_finish(log, &format!("second ack cut after {bytes} bytes"));

        let mut log = log_with_a_rotted_header();
        upload(&mut log);
        ack_all(&mut log).unwrap();
        log.storage_mut().cut_power_after(bytes);
        let mut sealed = Vec::new();
        let _ = eager().tick(5, &mut log, &mut sealed);
        let _ = ack_all(&mut log);
        restart_and_finish(log, &format!("declaration cut after {bytes} bytes"));
    }
}

#[test]
fn rot_found_on_a_second_pass_holds_the_mark_and_the_trim() {
    let mut log = open(100_000);
    for k in 0..3u8 {
        log.append(Class::P1, 0, [k; 16], 1, &[k; 100]).unwrap();
    }
    upload(&mut log);
    // The server holds all three and has backed up the first. The payload of the second
    // then rots, and a Rewind sends the upload over it again.
    log.ack(Class::P1, 3, 1).unwrap();
    log.storage_mut()
        .corrupt(Class::P1, (HEADER_LEN + 100 + HEADER_LEN + 10) as u64);
    log.rewind(Class::P1, 0).unwrap();
    upload(&mut log);
    let rot = LostRange {
        class: Class::P1,
        first_seq: 1,
        count: 1,
    };
    assert_eq!(log.undeclared(), [rot]);
    log.ack(Class::P1, 3, 3).unwrap();
    assert_eq!(log.backed_up_next(Class::P1), 1, "the mark does not pass it");
    assert_eq!(log.first_retained_seq(Class::P1).unwrap(), 1, "nor does the trim");
}
