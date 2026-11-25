//! How long a long log takes to open and to rewind on a `FileStore`: the agent pays the open at
//! every start and a rewind per class at every Welcome. Not a test; run it by hand, in release:
//!
//! ```text
//! cargo test --release -p sl-agent --test open_bench -- --ignored --nocapture
//! SL_BENCH_FRAMES=86400 cargo test ...   # one day instead of fourteen
//! ```
//!
//! The log is 14 days of one P0 frame a second (1,209,600 frames), built in memory and copied
//! into the file store in one append per class, so building it costs no fsync per frame.
use std::time::Instant;

use sl_agent::file_store::FileStore;
use sl_core::log::DurableLog;
use sl_core::mem_storage::MemStorage;
use sl_core::storage::{META_SLOTS, Storage};
use sl_proto::ids::Class;

#[test]
#[ignore]
fn open_and_rewind_a_fourteen_day_log() {
    let frames: u64 = std::env::var("SL_BENCH_FRAMES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(14 * 86_400);
    let t = Instant::now();
    let (mut log, _) = DurableLog::open(MemStorage::new(1 << 40)).unwrap();
    // About what one second of P0 seals to: a few dozen bytes of zstd.
    let payload = [0x5au8; 60];
    for i in 0..frames {
        log.append(Class::P0, 0, [(i % 251) as u8; 16], 1, &payload).unwrap();
    }
    let mem = log.into_storage();
    let dir = tempfile::tempdir().unwrap();
    {
        let mut fs = FileStore::open(dir.path(), 1 << 40).unwrap();
        for class in Class::ALL {
            let (start, end) = (mem.start(class), mem.end(class));
            let mut bytes = vec![0u8; (end - start) as usize];
            mem.read(class, start, &mut bytes).unwrap();
            fs.append(class, &bytes).unwrap();
        }
        for slot in 0..META_SLOTS {
            if let Some(m) = mem.read_meta(slot).unwrap() {
                fs.write_meta(slot, &m).unwrap();
            }
        }
    }
    let bytes = mem.end(Class::P0) - mem.start(Class::P0);
    eprintln!("built {frames} frames, {bytes} bytes, in {:?}", t.elapsed());

    let t = Instant::now();
    let fs = FileStore::open(dir.path(), 1 << 40).unwrap();
    let store_open = t.elapsed();
    let (mut log, recovery) = DurableLog::open(fs).unwrap();
    let log_open = t.elapsed();
    assert_eq!(recovery.truncated_bytes, [0; 3]);
    assert_eq!(log.next_seq(Class::P0), frames);

    let t = Instant::now();
    log.rewind(Class::P0, frames / 2).unwrap();
    let rewind_mid = t.elapsed();
    let t = Instant::now();
    log.rewind(Class::P0, frames).unwrap();
    let rewind_end = t.elapsed();
    eprintln!(
        "FileStore::open {store_open:?}; DurableLog::open {log_open:?} in all; \
         rewind to the middle {rewind_mid:?}; rewind to the end {rewind_end:?}"
    );
}
