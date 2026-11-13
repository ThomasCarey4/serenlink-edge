//! Tests written to kill cargo-mutants survivors in `log.rs`, `meta.rs` and `mem_storage.rs`.
//! Each states a property of the log that no other test pinned down.

use core::cell::Cell;

use sl_core::frame::{FORMAT_V1, MAX_PAYLOAD, build_frame};
use sl_core::log::DurableLog;
use sl_core::mem_storage::MemStorage;
use sl_core::storage::{Storage, StorageError};
use sl_proto::ids::Class;

/// `MemStorage` that counts what is done to it.
#[derive(Default)]
struct Counts {
    reads: Cell<u64>,
    truncates: Cell<u64>,
    meta_writes: Cell<u64>,
}

struct Counting<'a> {
    inner: MemStorage,
    counts: &'a Counts,
}

impl Storage for Counting<'_> {
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
        self.inner.append(class, data)
    }
    fn read(&self, class: Class, offset: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        self.counts.reads.set(self.counts.reads.get() + 1);
        self.inner.read(class, offset, buf)
    }
    fn trim_front(&mut self, class: Class, new_start: u64) -> Result<(), StorageError> {
        self.inner.trim_front(class, new_start)
    }
    fn truncate(&mut self, class: Class, new_end: u64) -> Result<(), StorageError> {
        self.counts.truncates.set(self.counts.truncates.get() + 1);
        self.inner.truncate(class, new_end)
    }
    fn read_meta(&self, slot: usize) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.read_meta(slot)
    }
    fn write_meta(&mut self, slot: usize, data: &[u8]) -> Result<(), StorageError> {
        self.counts.meta_writes.set(self.counts.meta_writes.get() + 1);
        self.inner.write_meta(slot, data)
    }
}

fn open(storage: MemStorage) -> DurableLog<MemStorage> {
    DurableLog::open(storage).unwrap().0
}

#[test]
fn a_payload_of_exactly_the_maximum_is_stored_and_read_back() {
    let mut log = open(MemStorage::new(4 << 20));
    let payload = vec![0x5a; MAX_PAYLOAD];
    assert_eq!(log.append(Class::P1, 0, [1; 16], 1, &payload).unwrap(), 0);
    assert_eq!(
        log.append(Class::P1, 0, [2; 16], 1, &vec![0; MAX_PAYLOAD + 1]),
        Err(StorageError::TooLarge)
    );
    let frames = log.read_all(Class::P1).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].payload.len(), MAX_PAYLOAD);

    // And it survives a reopen, where the header's length is checked against the limit.
    let (log, recovery) = DurableLog::open(log.into_storage()).unwrap();
    assert_eq!(recovery.truncated_bytes, [0; 3]);
    assert_eq!(log.read_all(Class::P1).unwrap().len(), 1);
}

#[test]
fn a_stored_frame_over_the_maximum_is_not_a_frame() {
    // Well-formed in every other respect: both checksums hold.
    let mut storage = MemStorage::new(4 << 20);
    let frame = build_frame(FORMAT_V1, 0, 0, 1, [1; 16], [2; 16], &vec![7; MAX_PAYLOAD + 1]);
    storage.append(Class::P2, &frame).unwrap();
    let (log, recovery) = DurableLog::open(storage).unwrap();
    assert!(log.read_all(Class::P2).unwrap().is_empty());
    assert_eq!(recovery.truncated_bytes[Class::P2.index()], frame.len() as u64);
}

#[test]
fn garbage_is_skipped_in_chunks_not_byte_by_byte() {
    let counts = Counts::default();
    let mut inner = MemStorage::new(1 << 20);
    // 64 KiB with no magic byte in it, then a real frame.
    inner.append(Class::P0, &vec![0u8; 64 * 1024]).unwrap();
    let frame = build_frame(FORMAT_V1, 0, 0, 1, [1; 16], [0; 16], b"payload");
    inner.append(Class::P0, &frame).unwrap();
    let storage = Counting { inner, counts: &counts };
    let (log, _) = DurableLog::open(storage).unwrap();
    counts.reads.set(0);
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 1);
    // 256-byte chunks need about 256 reads for 64 KiB; a byte-wise walk needs 65 536.
    assert!(counts.reads.get() < 1_000, "{} reads", counts.reads.get());
}

#[test]
fn opening_an_intact_log_writes_nothing() {
    let mut log = open(MemStorage::new(1 << 20));
    for k in 0..3 {
        log.append(Class::P0, 0, [k; 16], 1, &[k; 50]).unwrap();
    }
    let counts = Counts::default();
    let storage = Counting {
        inner: log.into_storage(),
        counts: &counts,
    };
    let (_, recovery) = DurableLog::open(storage).unwrap();
    assert_eq!(recovery.truncated_bytes, [0; 3]);
    assert_eq!(counts.truncates.get(), 0);
    assert_eq!(counts.meta_writes.get(), 0);
}

#[test]
fn an_ack_that_trims_nothing_writes_no_metadata() {
    let counts = Counts::default();
    let storage = Counting {
        inner: MemStorage::new(1 << 20),
        counts: &counts,
    };
    let (mut log, _) = DurableLog::open(storage).unwrap();
    // An empty class, and a held frame that the marks do not reach.
    log.ack(Class::P1, 0, 0).unwrap();
    log.append(Class::P0, 0, [1; 16], 2, b"x").unwrap();
    log.ack(Class::P0, 1, 1).unwrap();
    assert_eq!(counts.meta_writes.get(), 0);
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 1);
}

#[test]
fn trims_that_leave_frames_write_the_metadata_every_sixty_fifth_time() {
    let counts = Counts::default();
    let storage = Counting {
        inner: MemStorage::new(1 << 20),
        counts: &counts,
    };
    let (mut log, _) = DurableLog::open(storage).unwrap();
    for k in 0..100u8 {
        log.append(Class::P1, 0, [k; 16], 1, &[k; 10]).unwrap();
    }
    for n in 1..=64u64 {
        log.ack(Class::P1, n, n).unwrap();
        assert_eq!(counts.meta_writes.get(), 0, "trim {n}");
    }
    log.ack(Class::P1, 65, 65).unwrap();
    assert_eq!(counts.meta_writes.get(), 1);
    // The count starts again after a write.
    for n in 66..=99u64 {
        log.ack(Class::P1, n, n).unwrap();
    }
    assert_eq!(counts.meta_writes.get(), 1);
}

#[test]
fn corrupting_flips_one_bit_and_corrupting_again_restores_it() {
    let mut storage = MemStorage::new(100);
    storage.append(Class::P0, &[0x00, 0xff]).unwrap();
    let read = |s: &MemStorage| {
        let mut b = [0u8; 2];
        s.read(Class::P0, 0, &mut b).unwrap();
        b
    };
    storage.corrupt(Class::P0, 0);
    storage.corrupt(Class::P0, 1);
    assert_eq!(read(&storage), [0x40, 0xbf]);
    storage.corrupt(Class::P0, 0);
    storage.corrupt(Class::P0, 1);
    assert_eq!(read(&storage), [0x00, 0xff]);
}
