//! Declare before destroy: the log never removes a record that no durable gap declares.

use core::cell::RefCell;

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
