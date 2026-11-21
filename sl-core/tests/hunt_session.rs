//! Tests written to kill cargo-mutants survivors in `session.rs`.

use sl_core::log::DurableLog;
use sl_core::mem_storage::MemStorage;
use sl_core::session::{Phase, Session, SessionConfig};
use sl_proto::auth::KeySigner;
use sl_proto::wire::{Body, Challenge, DeviceState, Envelope, Welcome};

fn session() -> Session<KeySigner> {
    let cfg = SessionConfig {
        device_id: [1; 16],
        hostname: "ingest.example".into(),
        firmware_version: 0,
        config_version: 0,
        table_version: 0,
        trust_version: 0,
        max_batches_per_poll: 8,
    };
    Session::new(cfg, KeySigner::from_seed([2; 32]))
}

fn connect_with_state(state: DeviceState) -> Session<KeySigner> {
    let (mut log, _) = DurableLog::open(MemStorage::new(1 << 16)).unwrap();
    let mut s = session();
    s.on_connected(&log, [0xB1; 32]).unwrap();
    s.on_message(
        Envelope::of(Body::Challenge(Challenge {
            nonce: vec![3; 32],
            ..Challenge::default()
        })),
        &mut log,
    )
    .unwrap();
    s.on_message(
        Envelope::of(Body::Welcome(
            Welcome {
                protocol_version: 1,
                state: state as i32,
                server_time_ms: 0,
                epoch: vec![4; 16],
                marks: Vec::new(),
                check: Vec::new(),
            }
            .with_check(),
        )),
        &mut log,
    )
    .unwrap();
    assert_eq!(s.phase(), Phase::Active);
    s
}

#[test]
fn the_state_reported_in_the_welcome_is_kept() {
    assert_eq!(session().state(), DeviceState::Unclaimed);
    for state in [
        DeviceState::Active,
        DeviceState::Hold,
        DeviceState::Revoked,
        DeviceState::Stolen,
    ] {
        assert_eq!(connect_with_state(state).state(), state);
    }
}
