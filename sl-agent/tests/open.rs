use std::fs;
use std::os::unix::fs::PermissionsExt;

use sl_agent::run::{RUNNING, highest_boot_in_log, open_device};
use sl_core::device::DeviceConfig;
use sl_core::recorder::RecorderConfig;
use sl_core::storage::Storage as _;
use sl_proto::compress::Compression;
use sl_proto::ids::Class;
use sl_proto::trust::SignedTrustStore;

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

fn cfg() -> DeviceConfig {
    DeviceConfig {
        device_id: [1; 16],
        seed: [2; 32],
        hostname: "ingest.sim".into(),
        boot_id: 1,
        running: RUNNING,
        recorder: RecorderConfig {
            compression: Compression::Zstd,
            table_version: 1,
            ..RecorderConfig::default()
        },
        max_batches_per_poll: 32,
        control_lane: true,
    }
}

#[test]
fn a_log_that_will_not_open_is_set_aside_and_a_fresh_one_started() {
    let state = tempfile::tempdir().unwrap();
    let (dev, _, moved) = open_device(state.path(), 1 << 30, cfg(), &baseline(), 1_790_000_000).unwrap();
    assert!(moved.is_none());
    drop(dev);
    fs::write(state.path().join("log").join("p0").join("start"), [1, 2, 3]).unwrap();

    let (dev, recovery, moved) = open_device(state.path(), 1 << 30, cfg(), &baseline(), 1_790_000_000).unwrap();
    let broken = state.path().join("log.broken-1790000000");
    assert_eq!(moved.as_deref(), Some(broken.as_path()));
    assert_eq!(fs::read(broken.join("p0").join("start")).unwrap(), [1, 2, 3]);
    assert_eq!(recovery, Default::default());
    assert_eq!(dev.log().storage().end(Class::P0), 0);
    assert!(!state.path().join("log.new-1790000000").exists());
    drop(dev);

    // The same second again (a restart loop) does not overwrite the first broken log.
    fs::write(state.path().join("log").join("p1").join("start"), [9]).unwrap();
    let (_, _, moved) = open_device(state.path(), 1 << 30, cfg(), &baseline(), 1_790_000_000).unwrap();
    assert_eq!(moved.unwrap(), state.path().join("log.broken-1790000000-1"));
    assert!(broken.exists());
}

#[test]
fn a_log_is_left_in_place_when_no_fresh_one_can_be_made() {
    let state = tempfile::tempdir().unwrap();
    drop(open_device(state.path(), 1 << 30, cfg(), &baseline(), 1).unwrap());
    fs::write(state.path().join("log").join("p0").join("start"), [1, 2, 3]).unwrap();
    // A state directory that takes no new entries, as a read-only or full disk would not.
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let r = open_device(state.path(), 1 << 30, cfg(), &baseline(), 1);
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(r.is_err());
    assert_eq!(
        fs::read(state.path().join("log").join("p0").join("start")).unwrap(),
        [1, 2, 3]
    );
    let names: Vec<_> = fs::read_dir(state.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["log"]);
}

fn trust_version(log: &std::path::Path) -> u32 {
    let store = sl_agent::file_store::FileStore::open(log, 1 << 30).unwrap();
    sl_core::trust::TrustAnchor::open(&store, &baseline())
        .unwrap()
        .active()
        .version
}

#[test]
fn a_set_aside_log_hands_its_newer_trust_store_to_the_fresh_one() {
    use sl_proto::auth::{KeySigner, Signer as _};
    use sl_proto::trust::{ReleaseKey, TrustStore};
    let state = tempfile::tempdir().unwrap();
    drop(open_device(state.path(), 1 << 30, cfg(), &baseline(), 1).unwrap());
    let log = state.path().join("log");
    {
        let mut store = sl_agent::file_store::FileStore::open(&log, 1 << 30).unwrap();
        let mut anchor = sl_core::trust::TrustAnchor::open(&store, &baseline()).unwrap();
        let seed = [0x11; 32];
        let next = TrustStore {
            version: 2,
            release_keys: vec![ReleaseKey {
                id: 1,
                pubkey: KeySigner::from_seed(seed).public_key().to_vec(),
            }],
            min_serial: 1,
            revoked_serials: vec![],
            tls_roots: vec![],
        };
        anchor
            .offer(&mut store, &SignedTrustStore::sign(&next, 1, &seed))
            .unwrap();
    }
    assert_eq!(trust_version(&log), 2);
    // The other slot holds rot, which must not be carried.
    let meta = log.join("meta");
    let rot_slot = if meta.join("2").exists() { "3" } else { "2" };
    fs::write(meta.join(rot_slot), b"rot").unwrap();
    fs::write(log.join("p0").join("start"), [1, 2, 3]).unwrap();

    let (dev, _, moved) = open_device(state.path(), 1 << 30, cfg(), &baseline(), 1_790_000_000).unwrap();
    assert!(moved.is_some());
    drop(dev);
    assert_eq!(trust_version(&log), 2);
    assert!(!log.join("meta").join(rot_slot).exists());
}

#[test]
fn the_highest_boot_in_a_log_is_its_newest_frames() {
    use sl_proto::record::{Define, Kind};
    use sl_proto::value::{Value, ValueType};
    let state = tempfile::tempdir().unwrap();
    let log = state.path().join("log");
    assert_eq!(highest_boot_in_log(&log), None);
    for boot in [3, 7] {
        let mut c = cfg();
        c.boot_id = boot;
        let (mut dev, _, _) = open_device(state.path(), 1 << 30, c, &baseline(), 1).unwrap();
        let def = Define {
            local_id: 1,
            stable_key: 0,
            path: "navigation.speedOverGround".into(),
            source: 0,
            value_type: ValueType::F64,
            unit: String::new(),
            kind: Kind::Linear,
        };
        dev.sample(Class::P1, &def, 10, Value::F64(1.0));
        dev.flush(20, &mut Vec::new()).unwrap();
    }
    assert_eq!(highest_boot_in_log(&log), Some(7));
}
