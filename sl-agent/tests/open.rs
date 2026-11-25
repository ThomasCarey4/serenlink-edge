use std::fs;
use std::os::unix::fs::PermissionsExt;

use sl_agent::run::{RUNNING, open_device};
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
