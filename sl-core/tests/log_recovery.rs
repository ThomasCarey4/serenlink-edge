use sl_core::frame::{FrameHeader, HEADER_LEN, body_crc, build_frame};
use sl_core::log::{DurableLog, Lineage, LostRange};
use sl_core::mem_storage::MemStorage;
use sl_core::meta::Meta;
use sl_core::storage::{Storage, StorageError};
use sl_proto::block::chain_hash;
use sl_proto::ids::Class;

fn open(storage: MemStorage) -> DurableLog<MemStorage> {
    DurableLog::open(storage).unwrap().0
}

/// Append `n` one-record frames of 100 bytes to `class`.
fn fill(log: &mut DurableLog<MemStorage>, class: Class, n: u8) {
    for k in 0..n {
        log.append(class, 0, [k; 16], 1, &[k; 100]).unwrap();
    }
}

fn reopen(log: DurableLog<MemStorage>) -> (DurableLog<MemStorage>, sl_core::log::Recovery) {
    let mut storage = log.into_storage();
    storage.power_on();
    DurableLog::open(storage).unwrap()
}

/// Remove the oldest frame of a class, as the recorder's eviction does once it has declared it.
fn evict_oldest(log: &mut DurableLog<MemStorage>, class: Class) -> Option<LostRange> {
    let oldest = *log.front_frames(class, 1).unwrap().first()?;
    Some(log.evict_through(class, oldest.next_offset).unwrap())
}

fn first_seqs(log: &DurableLog<MemStorage>, class: Class) -> Vec<u64> {
    log.read_all(class)
        .unwrap()
        .iter()
        .map(|f| f.header.first_seq)
        .collect()
}

#[test]
fn appended_frames_read_back_in_order_with_sequences() {
    let mut log = open(MemStorage::new(10_000));
    assert_eq!(log.append(Class::P0, 1, [1; 16], 3, b"first").unwrap(), 0);
    assert_eq!(log.append(Class::P0, 0, [2; 16], 2, b"second").unwrap(), 3);
    assert_eq!(log.append(Class::P1, 0, [3; 16], 1, b"other").unwrap(), 0);
    assert_eq!(log.next_seq(Class::P0), 5);

    let frames = log.read_all(Class::P0).unwrap();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].payload, b"first");
    assert_eq!((frames[0].header.compression, frames[0].header.hash), (1, [1; 16]));
    assert_eq!((frames[1].header.first_seq, frames[1].end_seq()), (3, 5));
}

#[test]
fn sequences_continue_after_reopening() {
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P1, 3);
    let (mut log, recovery) = reopen(log);
    assert_eq!(recovery.truncated_bytes, [0; 3]);
    assert_eq!(log.append(Class::P1, 0, [9; 16], 1, b"x").unwrap(), 3);
}

#[test]
fn a_torn_tail_is_truncated_and_its_sequences_are_reused() {
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P0, 2);
    log.storage_mut().cut_power_after(60);
    assert_eq!(log.append(Class::P0, 0, [2; 16], 1, &[2; 100]), Err(StorageError::Io));

    let (mut log, recovery) = reopen(log);
    assert_eq!(recovery.truncated_bytes, [60, 0, 0]);
    assert!(recovery.corrupt.is_empty());
    assert_eq!(first_seqs(&log, Class::P0), [0, 1]);
    assert_eq!(log.append(Class::P0, 0, [3; 16], 1, b"again").unwrap(), 2);
}

#[test]
fn a_frame_of_unknown_version_is_kept_and_offered_for_upload() {
    let mut storage = MemStorage::new(10_000);
    storage
        .append(
            Class::P1,
            &build_frame(9, 0, 0, 4, [1; 16], [0; 16], b"from the future"),
        )
        .unwrap();
    let mut log = open(storage);
    assert_eq!(log.append(Class::P1, 0, [2; 16], 1, b"now").unwrap(), 4);

    let (log, recovery) = reopen(log);
    assert_eq!(recovery.truncated_bytes, [0; 3]);
    let frames = log.read_all(Class::P1).unwrap();
    assert_eq!(frames[0].header.version, 9);
    assert_eq!(frames[0].payload, b"from the future");
    assert_eq!(frames[1].header.first_seq, 4);
}

#[test]
fn a_longer_header_from_a_later_version_is_stepped_over() {
    // A later format adds header fields. They sit in the extension, which this version
    // skips: rolling firmware back must not cost the log.
    let (ext, payload) = (b"new field", b"from the future");
    let header = FrameHeader {
        version: 2,
        compression: 0,
        ext_len: ext.len() as u8,
        len: payload.len() as u32,
        first_seq: 0,
        count: 4,
        hash: [1; 16],
        chain: [0; 16],
        body_crc: body_crc(ext, payload),
    };
    let mut storage = MemStorage::new(10_000);
    let frame = [header.encode().as_slice(), ext, payload].concat();
    storage.append(Class::P1, &frame).unwrap();
    let mut log = open(storage);
    assert_eq!(log.append(Class::P1, 0, [2; 16], 1, b"now").unwrap(), 4);

    let (mut log, recovery) = reopen(log);
    assert_eq!(recovery, Default::default());
    let frames = log.read_all(Class::P1).unwrap();
    assert_eq!(
        (frames[0].header.version, frames[0].payload.as_slice()),
        (2, payload.as_slice())
    );
    assert_eq!(frames[1].offset, frame.len() as u64);

    log.ack(Class::P1, 4, 4).unwrap();
    assert_eq!(first_seqs(&log, Class::P1), [4]);
}

#[test]
fn a_leftover_frame_with_older_sequences_is_not_data() {
    // A valid copy of an old frame after the newest one, as an interrupted erase or a reused
    // file can leave behind. Sequences only grow along the log.
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P0, 5);
    let stale = build_frame(1, 0, 1, 1, [1; 16], [0xee; 16], &[1; 100]);
    log.storage_mut().append(Class::P0, &[0x5a; 17]).unwrap();
    log.storage_mut().append(Class::P0, &stale).unwrap();
    assert_eq!(first_seqs(&log, Class::P0), [0, 1, 2, 3, 4]);

    let (mut log, recovery) = reopen(log);
    assert_eq!(recovery.truncated_bytes, [17 + stale.len() as u64, 0, 0]);
    assert!(recovery.corrupt.is_empty());
    assert_eq!(first_seqs(&log, Class::P0), [0, 1, 2, 3, 4]);
    assert_eq!(log.append(Class::P0, 0, [9; 16], 1, b"x").unwrap(), 5);
}

#[test]
fn a_payload_larger_than_the_format_allows_is_refused() {
    let mut log = open(MemStorage::new(4 << 20));
    let too_big = vec![0u8; sl_core::frame::MAX_PAYLOAD + 1];
    assert_eq!(
        log.append(Class::P2, 0, [0; 16], 1, &too_big),
        Err(StorageError::TooLarge)
    );
    assert_eq!((log.next_seq(Class::P2), log.storage().used()), (0, 0));
}

#[test]
fn corruption_in_the_middle_is_skipped_and_reported() {
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P1, 3);
    let second_payload = (HEADER_LEN + 100 + HEADER_LEN + 10) as u64;
    log.storage_mut().corrupt(Class::P1, second_payload);

    let (log, recovery) = reopen(log);
    assert_eq!(
        recovery.corrupt,
        [LostRange {
            class: Class::P1,
            first_seq: 1,
            count: 1
        }]
    );
    assert_eq!(recovery.truncated_bytes, [0; 3]);
    assert_eq!(first_seqs(&log, Class::P1), [0, 2]);
    assert_eq!(log.next_seq(Class::P1), 3);
}

#[test]
fn a_commit_alone_trims_nothing() {
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P0, 4);
    log.ack(Class::P0, 4, 0).unwrap();
    assert_eq!(first_seqs(&log, Class::P0), [0, 1, 2, 3]);
    assert_eq!(log.committed_next(Class::P0), 4);
}

#[test]
fn only_frames_wholly_below_the_backup_mark_are_trimmed() {
    let mut log = open(MemStorage::new(10_000));
    log.append(Class::P0, 0, [0; 16], 3, b"a").unwrap(); // sequences 0..3
    log.append(Class::P0, 0, [1; 16], 3, b"b").unwrap(); // sequences 3..6
    log.ack(Class::P0, 6, 4).unwrap();
    assert_eq!(first_seqs(&log, Class::P0), [3]);
    assert_eq!(log.first_retained_seq(Class::P0).unwrap(), 3);

    // The marks themselves are not written for every trim; the server sends them again.
    let (log, _) = reopen(log);
    assert_eq!(first_seqs(&log, Class::P0), [3]);
    assert_eq!(log.next_seq(Class::P0), 6);
}

#[test]
fn marks_never_reach_past_what_was_written() {
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P0, 3);
    log.ack(Class::P0, u64::MAX, u64::MAX).unwrap();
    assert_eq!((log.committed_next(Class::P0), log.backed_up_next(Class::P0)), (3, 3));

    // What is written afterwards is not covered by the earlier claim.
    fill(&mut log, Class::P0, 2);
    log.ack(Class::P0, 3, 0).unwrap();
    assert_eq!(first_seqs(&log, Class::P0), [3, 4]);

    log.ack(Class::P0, 4, 5).unwrap();
    assert_eq!(log.backed_up_next(Class::P0), 4, "never more backed up than committed");
}

#[test]
fn the_metadata_is_not_rewritten_for_every_trim() {
    let generation = |log: &DurableLog<MemStorage>| Meta::load(log.storage()).unwrap().generation;
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P0, 10);
    for mark in 1..10 {
        log.ack(Class::P0, mark, mark).unwrap();
    }
    assert_eq!(first_seqs(&log, Class::P0), [9]);
    assert_eq!(generation(&log), 0);

    // Emptying the class is different: now only the metadata knows where to continue.
    log.ack(Class::P0, 10, 10).unwrap();
    assert_eq!(generation(&log), 1);
    evict_oldest(&mut log, Class::P0);
    assert_eq!(generation(&log), 1);

    fill(&mut log, Class::P1, 2);
    evict_oldest(&mut log, Class::P1);
    assert_eq!(generation(&log), 1);
    evict_oldest(&mut log, Class::P1);
    assert_eq!(generation(&log), 2);
}

#[test]
fn an_emptied_log_remembers_its_next_sequence() {
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P2, 5);
    log.ack(Class::P2, 5, 5).unwrap();
    assert_eq!(log.storage().used(), 0);

    let (mut log, _) = reopen(log);
    assert_eq!(log.first_retained_seq(Class::P2).unwrap(), 5);
    assert_eq!(log.append(Class::P2, 0, [9; 16], 1, b"x").unwrap(), 5);
}

#[test]
fn the_send_cursor_walks_forward_and_rewinds() {
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P1, 3);

    let first = log.peek_unsent(Class::P1).unwrap().unwrap();
    assert_eq!(first.header.first_seq, 0);
    assert_eq!(log.peek_unsent(Class::P1).unwrap().unwrap(), first);
    log.mark_sent(&first);
    let second = log.peek_unsent(Class::P1).unwrap().unwrap();
    log.mark_sent(&second);
    assert_eq!(log.peek_unsent(Class::P1).unwrap().unwrap().header.first_seq, 2);

    log.rewind(Class::P1, 1).unwrap();
    assert_eq!(log.peek_unsent(Class::P1).unwrap().unwrap().header.first_seq, 1);
    log.rewind(Class::P1, 99).unwrap();
    assert_eq!(log.peek_unsent(Class::P1).unwrap(), None);
}

#[test]
fn a_new_epoch_clears_the_marks_and_resends_from_the_start() {
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P0, 3);
    log.ack(Class::P0, 3, 1).unwrap();
    let sent = log.peek_unsent(Class::P0).unwrap().unwrap();
    log.mark_sent(&sent);

    log.set_epoch([4; 16]).unwrap();
    assert_eq!(log.epoch(), Some([4; 16]));
    assert_eq!((log.committed_next(Class::P0), log.backed_up_next(Class::P0)), (0, 0));
    assert_eq!(log.peek_unsent(Class::P0).unwrap().unwrap().header.first_seq, 1);

    let (log, _) = reopen(log);
    assert_eq!(log.epoch(), Some([4; 16]));
}

#[test]
fn evicting_removes_the_oldest_frame_and_says_what_was_lost() {
    let mut log = open(MemStorage::new(10_000));
    log.append(Class::P2, 0, [0; 16], 4, b"old").unwrap();
    log.append(Class::P2, 0, [1; 16], 2, b"new").unwrap();

    assert_eq!(
        evict_oldest(&mut log, Class::P2),
        Some(LostRange {
            class: Class::P2,
            first_seq: 0,
            count: 4
        })
    );
    assert_eq!(first_seqs(&log, Class::P2), [4]);
    assert_eq!(log.peek_unsent(Class::P2).unwrap().unwrap().header.first_seq, 4);
    evict_oldest(&mut log, Class::P2);
    assert_eq!(evict_oldest(&mut log, Class::P2), None);
    assert_eq!(log.next_seq(Class::P2), 6);
}

#[test]
fn each_frame_chains_from_the_one_before_even_across_an_emptied_log() {
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P1, 3);
    let frames = log.read_all(Class::P1).unwrap();
    assert_eq!(
        frames[0].header.chain,
        chain_hash(&[0; 16], 0, 1, &frames[0].header.hash)
    );
    assert_eq!(
        frames[2].header.chain,
        chain_hash(&frames[1].header.chain, 2, 1, &frames[2].header.hash)
    );

    let tail = frames[2].header.chain;
    log.ack(Class::P1, 3, 3).unwrap();
    let (mut log, _) = reopen(log);
    log.append(Class::P1, 0, [7; 16], 1, b"next").unwrap();
    assert_eq!(
        log.read_all(Class::P1).unwrap()[0].header.chain,
        chain_hash(&tail, 3, 1, &[7; 16])
    );
}

#[test]
fn lineage_compares_the_chain_at_the_servers_mark() {
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P1, 3); // sequences 0, 1, 2
    log.append(Class::P1, 0, [9; 16], 3, b"three records").unwrap(); // sequences 3..6
    let frames = log.read_all(Class::P1).unwrap();
    let chain_at = |end: usize| frames[end - 1].header.chain;
    let lineage = |log: &DurableLog<MemStorage>, mark, chain: [u8; 16]| log.lineage(Class::P1, mark, &chain).unwrap();

    assert_eq!(lineage(&log, 2, chain_at(2)), Lineage::Matches);
    assert_eq!(lineage(&log, 2, [0xaa; 16]), Lineage::Diverged);
    assert_eq!(lineage(&log, 6, frames[3].header.chain), Lineage::Matches);
    assert_eq!(
        lineage(&log, 4, [0xaa; 16]),
        Lineage::Diverged,
        "a mark inside one of our frames"
    );
    assert_eq!(
        lineage(&log, 7, [0xaa; 16]),
        Lineage::Diverged,
        "a mark beyond anything we wrote"
    );

    log.ack(Class::P1, 2, 2).unwrap();
    assert_eq!(lineage(&log, 1, [0xaa; 16]), Lineage::Unknown, "that frame is trimmed");
    assert_eq!(lineage(&log, 2, [0xaa; 16]), Lineage::Unknown);

    log.ack(Class::P1, 6, 6).unwrap();
    assert_eq!(
        lineage(&log, 6, frames[3].header.chain),
        Lineage::Matches,
        "the tail is remembered"
    );
    assert_eq!(lineage(&log, 6, [0xaa; 16]), Lineage::Diverged);
}

#[test]
fn a_mark_in_a_hole_of_the_log_is_not_this_logs_history() {
    // Three frames never sent, then a dropped block. A server mark in the hole, or at its
    // far end, can only describe another device: this log sent nothing that ends there.
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P0, 3);
    log.skip(Class::P0, 5).unwrap();
    assert_eq!(log.lineage(Class::P0, 8, &[0x99; 16]).unwrap(), Lineage::Diverged);
    assert_eq!(log.lineage(Class::P0, 5, &[0x99; 16]).unwrap(), Lineage::Diverged);

    fill(&mut log, Class::P0, 1); // sequence 8
    assert_eq!(log.lineage(Class::P0, 8, &[0x99; 16]).unwrap(), Lineage::Diverged);
    assert_eq!(log.lineage(Class::P0, 5, &[0x99; 16]).unwrap(), Lineage::Diverged);
}

#[test]
fn losing_the_newest_frame_does_not_break_the_chain() {
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P0, 3);
    let frames = log.read_all(Class::P0).unwrap();
    let tail = frames[2].header.chain;
    log.set_epoch([4; 16]).unwrap(); // writes the metadata: next sequence 3, chain `tail`
    log.storage_mut().corrupt(Class::P0, frames[2].next_offset - 1);

    // The frame rotted but it was written, and perhaps uploaded. It is kept and declared lost,
    // not taken for a torn write. Its sequence number is not handed out again, and the next
    // frame continues from it, not from the one before.
    let (mut log, recovery) = reopen(log);
    assert_eq!(recovery.truncated_bytes, [0; 3]);
    assert_eq!(
        recovery.corrupt,
        [LostRange {
            class: Class::P0,
            first_seq: 2,
            count: 1
        }]
    );
    assert_eq!(log.lineage(Class::P0, 3, &tail).unwrap(), Lineage::Matches);
    assert_eq!(log.append(Class::P0, 0, [7; 16], 1, b"next").unwrap(), 3);
    assert_eq!(
        log.read_all(Class::P0).unwrap()[2].header.chain,
        chain_hash(&tail, 3, 1, &[7; 16])
    );
}

#[test]
fn skipped_sequences_are_never_reused() {
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P2, 2);
    assert_eq!(log.skip(Class::P2, 5).unwrap(), 2);
    assert_eq!(log.next_seq(Class::P2), 7);

    log.ack(Class::P2, 2, 2).unwrap();
    let (mut log, _) = reopen(log);
    assert_eq!(log.append(Class::P2, 0, [1; 16], 1, b"x").unwrap(), 7);
}

#[test]
fn corruption_of_the_oldest_frame_is_reported_too() {
    let mut log = open(MemStorage::new(10_000));
    fill(&mut log, Class::P1, 3);
    log.ack(Class::P1, 1, 1).unwrap();
    let oldest_payload = log.storage().start(Class::P1) + HEADER_LEN as u64 + 10;
    log.storage_mut().corrupt(Class::P1, oldest_payload);

    let (log, recovery) = reopen(log);
    // The frame's header is sound, so the report names exactly its records.
    assert_eq!(
        recovery.corrupt,
        [LostRange {
            class: Class::P1,
            first_seq: 1,
            count: 1
        }]
    );
    assert_eq!(first_seqs(&log, Class::P1), [2]);
}
