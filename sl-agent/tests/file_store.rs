#[path = "../../sl-core/tests/storage_contract.rs"]
mod storage_contract;

use std::fs;
use std::path::Path;

use sl_agent::file_store::FileStore;
use sl_core::device::{Device, DeviceConfig};
use sl_core::mem_sink::MemSink;
use sl_core::recorder::RecorderConfig;
use sl_core::storage::Storage;
use sl_proto::compress::Compression;
use sl_proto::ids::Class;
use sl_proto::record::{Define, Kind};
use sl_proto::trust::SignedTrustStore;
use sl_proto::value::{Value, ValueType};

#[test]
fn the_file_store_meets_the_contract() {
    let dir = tempfile::tempdir().unwrap();
    let n = std::cell::Cell::new(0);
    storage_contract::check_all(&|capacity| {
        n.set(n.get() + 1);
        FileStore::open_with_segment(&dir.path().join(n.get().to_string()), capacity, 3).unwrap()
    });
}

#[test]
fn what_was_written_is_there_after_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = FileStore::open_with_segment(dir.path(), 1_000, 4).unwrap();
    s.append(Class::P0, b"0123456789").unwrap();
    s.trim_front(Class::P0, 5).unwrap();
    s.write_meta(1, b"meta").unwrap();
    drop(s);
    let s = FileStore::open_with_segment(dir.path(), 1_000, 4).unwrap();
    assert_eq!((s.start(Class::P0), s.end(Class::P0)), (5, 10));
    let mut buf = [0u8; 5];
    s.read(Class::P0, 5, &mut buf).unwrap();
    assert_eq!(&buf, b"56789");
    assert_eq!(s.read_meta(1).unwrap().as_deref(), Some(&b"meta"[..]));
}

#[test]
fn segments_wholly_below_the_start_are_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = FileStore::open_with_segment(dir.path(), 1_000, 4).unwrap();
    for _ in 0..5 {
        s.append(Class::P1, b"abcd").unwrap();
    }
    s.trim_front(Class::P1, 13).unwrap();
    let segs = fs::read_dir(dir.path().join("p1"))
        .unwrap()
        .filter(|e| e.as_ref().unwrap().path().extension().is_some_and(|x| x == "seg"))
        .count();
    assert_eq!(segs, 2, "segments 12.. and 16.. remain");
}

#[test]
fn a_missing_middle_segment_fails_the_open() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = FileStore::open_with_segment(dir.path(), 1_000, 4).unwrap();
    for _ in 0..3 {
        s.append(Class::P2, b"abcd").unwrap();
    }
    drop(s);
    fs::remove_file(dir.path().join("p2").join(format!("{:020}.seg", 4))).unwrap();
    assert!(FileStore::open_with_segment(dir.path(), 1_000, 4).is_err());
}

fn segments(dir: &Path) -> Vec<u64> {
    let mut v: Vec<u64> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "seg"))
        .map(|p| p.file_stem().unwrap().to_str().unwrap().parse().unwrap())
        .collect();
    v.sort_unstable();
    v
}

fn seg_path(dir: &Path, off: u64) -> std::path::PathBuf {
    dir.join(format!("{off:020}.seg"))
}

#[test]
fn segments_left_below_the_start_by_a_trim_are_deleted_at_open() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = FileStore::open_with_segment(dir.path(), 1_000, 4).unwrap();
    s.append(Class::P0, b"abcdefghijkl").unwrap();
    s.trim_front(Class::P0, 9).unwrap();
    drop(s);
    let p0 = dir.path().join("p0");
    assert_eq!(segments(&p0), [8]);
    // The delete of segment 0 did not reach the disk; the delete of segment 4 did.
    fs::write(seg_path(&p0, 0), b"abcd").unwrap();
    let s = FileStore::open_with_segment(dir.path(), 1_000, 4).unwrap();
    assert_eq!((s.start(Class::P0), s.end(Class::P0)), (9, 12));
    assert_eq!(segments(&p0), [8]);
    let mut buf = [0u8; 3];
    s.read(Class::P0, 9, &mut buf).unwrap();
    assert_eq!(&buf, b"jkl");
}

#[test]
fn a_short_segment_followed_by_more_fails_the_open_and_deletes_nothing() {
    // A truncate syncs its deletes before it cuts the tail, so no crash leaves a short segment
    // with later ones after it: that is damage, and the log is kept whole for the agent to set
    // aside.
    let dir = tempfile::tempdir().unwrap();
    let mut s = FileStore::open_with_segment(dir.path(), 1_000, 4).unwrap();
    s.append(Class::P1, b"abcdefghijkl").unwrap();
    drop(s);
    let p1 = dir.path().join("p1");
    fs::OpenOptions::new()
        .write(true)
        .open(seg_path(&p1, 4))
        .unwrap()
        .set_len(2)
        .unwrap();
    assert!(FileStore::open_with_segment(dir.path(), 1_000, 4).is_err());
    assert_eq!(segments(&p1), [0, 4, 8]);
}

#[test]
fn a_truncate_interrupted_between_its_deletes_leaves_a_lane_that_opens() {
    // Deletes go newest first and are synced before the cut: a crash part way leaves the lane
    // contiguous and longer than meant, which the log's recovery truncates again.
    let dir = tempfile::tempdir().unwrap();
    let mut s = FileStore::open_with_segment(dir.path(), 1_000, 4).unwrap();
    s.append(Class::P1, b"abcdefghijkl").unwrap();
    drop(s);
    let p1 = dir.path().join("p1");
    // A truncate to 2 deleted segment 8 and crashed before deleting 4 and cutting 0.
    fs::remove_file(seg_path(&p1, 8)).unwrap();
    let mut s = FileStore::open_with_segment(dir.path(), 1_000, 4).unwrap();
    assert_eq!((s.start(Class::P1), s.end(Class::P1)), (0, 8));
    s.truncate(Class::P1, 2).unwrap();
    s.append(Class::P1, b"XY").unwrap();
    drop(s);
    let s = FileStore::open_with_segment(dir.path(), 1_000, 4).unwrap();
    let mut buf = [0u8; 4];
    s.read(Class::P1, 0, &mut buf).unwrap();
    assert_eq!(&buf, b"abXY");
}

#[test]
fn an_overlap_between_segments_fails_the_open() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = FileStore::open_with_segment(dir.path(), 1_000, 4).unwrap();
    s.append(Class::P2, b"abcdefgh").unwrap();
    drop(s);
    fs::write(seg_path(&dir.path().join("p2"), 0), b"abcdefg").unwrap();
    assert!(FileStore::open_with_segment(dir.path(), 1_000, 4).is_err());
}

#[test]
fn reads_see_a_segment_written_again_after_a_truncate() {
    // The read handle of a deleted segment must not serve the new file at its offset.
    let dir = tempfile::tempdir().unwrap();
    let mut s = FileStore::open_with_segment(dir.path(), 1_000, 4).unwrap();
    s.append(Class::P0, b"abcdefgh").unwrap();
    let mut buf = [0u8; 4];
    s.read(Class::P0, 4, &mut buf).unwrap();
    assert_eq!(&buf, b"efgh");
    s.truncate(Class::P0, 4).unwrap();
    s.append(Class::P0, b"WXYZ").unwrap();
    s.read(Class::P0, 4, &mut buf).unwrap();
    assert_eq!(&buf, b"WXYZ");
}

fn baseline() -> SignedTrustStore {
    use sl_proto::auth::{KeySigner, Signer as _};
    use sl_proto::trust::{ReleaseKey, TrustStore};
    let seed = [0x11; 32];
    let store = TrustStore {
        version: 1,
        release_keys: vec![ReleaseKey {
            id: 1,
            pubkey: KeySigner::from_seed(seed).public_key().to_vec(),
        }],
        min_serial: 1,
        revoked_serials: vec![],
        tls_roots: vec![],
    };
    SignedTrustStore::sign(&store, 1, &seed)
}

fn device(dir: &Path, boot: u32) -> (Device<FileStore, MemSink>, sl_core::log::Recovery) {
    device_with(dir, boot, sl_agent::file_store::SEGMENT_BYTES)
}

fn device_with(dir: &Path, boot: u32, segment_bytes: u64) -> (Device<FileStore, MemSink>, sl_core::log::Recovery) {
    let cfg = DeviceConfig {
        device_id: [1; 16],
        seed: [2; 32],
        hostname: "ingest.sim".into(),
        boot_id: boot,
        running: [0, 1, 1, 0],
        recorder: RecorderConfig {
            compression: Compression::Zstd,
            table_version: 1,
            ..RecorderConfig::default()
        },
        max_batches_per_poll: 32,
        control_lane: true,
    };
    let store = FileStore::open_with_segment(dir, 1 << 30, segment_bytes).unwrap();
    Device::open(cfg, store, MemSink::new(), &baseline()).unwrap()
}

#[test]
fn a_torn_tail_is_truncated_and_what_was_sealed_before_it_survives() {
    let dir = tempfile::tempdir().unwrap();
    let def = Define {
        local_id: 1,
        stable_key: 0,
        path: "navigation.speedOverGround".into(),
        source: 0,
        value_type: ValueType::F64,
        unit: String::new(),
        kind: Kind::Linear,
    };
    let (mut d, _) = device(dir.path(), 1);
    let mut sealed = Vec::new();
    for t in 0..3u64 {
        d.sample(Class::P1, &def, t * 10_000, Value::F64(t as f64));
        d.flush(t * 10_000 + 1, &mut sealed).unwrap();
    }
    assert_eq!(
        d.log().next_seq(Class::P1),
        sealed[2].first_seq + sealed[2].count as u64
    );
    let end_of_second = sealed[1].first_seq + sealed[1].count as u64;
    drop(d);
    // Tear the last frame: cut the newest segment's last 5 bytes.
    let p1 = dir.path().join("p1");
    let mut segs: Vec<_> = fs::read_dir(&p1)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "seg"))
        .collect();
    segs.sort();
    let last = segs.last().unwrap();
    let len = fs::metadata(last).unwrap().len();
    fs::OpenOptions::new()
        .write(true)
        .open(last)
        .unwrap()
        .set_len(len - 5)
        .unwrap();
    let (mut d, recovery) = device(dir.path(), 2);
    assert!(recovery.truncated_bytes[Class::P1.index()] > 0);
    assert_eq!(d.log().next_seq(Class::P1), end_of_second);
    d.report_recovery(&recovery, 0, &mut sealed).unwrap();
}

#[test]
fn a_torn_frame_spanning_segments_is_truncated_across_them() {
    let dir = tempfile::tempdir().unwrap();
    let def = Define {
        local_id: 1,
        stable_key: 0,
        path: "navigation.speedOverGround".into(),
        source: 0,
        value_type: ValueType::F64,
        unit: String::new(),
        kind: Kind::Linear,
    };
    // Segments far smaller than a frame: every frame spans several.
    let seg = 16;
    let (mut d, _) = device_with(dir.path(), 1, seg);
    let mut sealed = Vec::new();
    for t in 0..3u64 {
        d.sample(Class::P1, &def, t * 10_000, Value::F64(t as f64));
        d.flush(t * 10_000 + 1, &mut sealed).unwrap();
    }
    let end_of_second = sealed[1].first_seq + sealed[1].count as u64;
    drop(d);
    let p1 = dir.path().join("p1");
    let before = segments(&p1);
    // The power went while the last frame was being written: only one byte of its newest
    // segment reached the disk.
    let last = *before.last().unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(seg_path(&p1, last))
        .unwrap()
        .set_len(1)
        .unwrap();
    let (mut d, recovery) = device_with(dir.path(), 2, seg);
    assert!(recovery.truncated_bytes[Class::P1.index()] > seg);
    assert_eq!(d.log().next_seq(Class::P1), end_of_second);
    let after = segments(&p1);
    assert!(after.len() < before.len(), "{before:?} -> {after:?}");
    d.report_recovery(&recovery, 0, &mut sealed).unwrap();
    d.sample(Class::P1, &def, 40_000, Value::F64(4.0));
    sealed.clear();
    d.flush(40_001, &mut sealed).unwrap();
    let next = d.log().next_seq(Class::P1);
    drop(d);
    let (d, recovery) = device_with(dir.path(), 3, seg);
    assert_eq!(recovery.truncated_bytes, [0; 3]);
    assert!(recovery.corrupt.is_empty());
    assert_eq!(d.log().next_seq(Class::P1), next);
}
