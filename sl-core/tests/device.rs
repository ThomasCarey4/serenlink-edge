mod common;

use sl_core::device::{Device, DeviceConfig};
use sl_core::mem_sink::MemSink;
use sl_core::mem_storage::MemStorage;
use sl_core::recorder::RecorderConfig;
use sl_core::session::{Phase, SessionError};
use sl_proto::artifact::ArtifactKind;
use sl_proto::auth::{KeySigner, Signer as _};
use sl_proto::ids::Class;
use sl_proto::record::{Define, Kind};
use sl_proto::trust::SignedTrustStore;
use sl_proto::value::{Value, ValueType};
use sl_proto::wire::{Body, Envelope, Offer};

fn baseline() -> SignedTrustStore {
    common::keys::baseline()
}

fn cfg(boot_id: u32) -> DeviceConfig {
    DeviceConfig {
        device_id: [3; 16],
        seed: [4; 32],
        hostname: "ingest.sim".into(),
        boot_id,
        running: [0, 1, 1, 0],
        recorder: RecorderConfig::default(),
        max_batches_per_poll: 32,
        control_lane: true,
    }
}

fn def() -> Define {
    Define {
        local_id: 1,
        stable_key: 0,
        path: "environment.depth.belowTransducer".into(),
        source: 0,
        value_type: ValueType::F64,
        unit: String::new(),
        kind: Kind::Linear,
    }
}

#[test]
fn a_fresh_device_says_hello_with_what_it_runs() {
    let (mut d, _) = Device::open(cfg(1), MemStorage::new(1 << 20), MemSink::new(), &baseline()).unwrap();
    assert_eq!(d.phase(), Phase::Disconnected);
    let hello = d.connect([9; 32], 0).expect("a hello");
    let Some(Body::Hello(h)) = hello.body else {
        panic!("not a hello")
    };
    assert_eq!(
        (h.config_version, h.table_version, h.firmware_version, h.trust_version),
        (0, 1, 1, 1)
    );
    assert_eq!(h.device_id, vec![3; 16]);
    assert_eq!(d.phase(), Phase::AwaitChallenge);
    assert_eq!(d.running(ArtifactKind::Configuration), 0);
}

#[test]
fn sealed_samples_survive_into_parts_and_reopen() {
    let (mut d, _) = Device::open(cfg(1), MemStorage::new(1 << 20), MemSink::new(), &baseline()).unwrap();
    d.sample(Class::P1, &def(), 10, Value::F64(4.5));
    let mut sealed = Vec::new();
    d.flush(20, &mut sealed).unwrap();
    assert_eq!(sealed.len(), 1);
    let end = sealed[0].first_seq + u64::from(sealed[0].count);
    assert_eq!(d.log().next_seq(Class::P1), end);
    let (storage, sink) = d.into_parts();
    let (d2, recovery) = Device::open(cfg(2), storage, sink, &baseline()).unwrap();
    assert_eq!(recovery.truncated_bytes, [0; 3]);
    assert_eq!(d2.log().next_seq(Class::P1), end);
}

#[test]
fn an_offer_outside_an_active_session_is_the_sessions_and_drops_the_link() {
    let (mut d, _) = Device::open(cfg(1), MemStorage::new(1 << 20), MemSink::new(), &baseline()).unwrap();
    d.connect([9; 32], 0).unwrap();
    let offer = Envelope {
        body: Some(Body::Offer(Offer::default())),
    };
    assert_eq!(d.receive(offer, 1), Err(SessionError::Unexpected));
    assert_eq!(d.phase(), Phase::Disconnected);
    assert!(d.poll().is_empty());
}

#[test]
fn a_device_without_a_control_lane_sends_offers_to_the_session() {
    let mut c = cfg(1);
    c.control_lane = false;
    let (mut d, _) = Device::open(c, MemStorage::new(1 << 20), MemSink::new(), &baseline()).unwrap();
    assert!(!d.config().control_lane);
    assert!(d.poll().is_empty());
}

#[test]
fn the_public_key_is_the_seeds() {
    let (d, _) = Device::open(cfg(1), MemStorage::new(1 << 20), MemSink::new(), &baseline()).unwrap();
    assert_eq!(d.public_key(), KeySigner::from_seed([4; 32]).public_key());
}
