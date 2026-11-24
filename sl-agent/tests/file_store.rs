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
    Device::open(cfg, FileStore::open(dir, 1 << 30).unwrap(), MemSink::new(), &baseline()).unwrap()
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
