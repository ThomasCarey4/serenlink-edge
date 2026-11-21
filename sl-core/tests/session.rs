use sl_core::log::DurableLog;
use sl_core::mem_storage::MemStorage;
use sl_core::session::{Phase, Session, SessionConfig, SessionError};
use sl_proto::auth::{KeySigner, Signer, auth_message, verify};
use sl_proto::ids::Class;
use sl_proto::wire::{Ack, Batch, Body, Challenge, Credit, DeviceState, Envelope, Mark, Resync, Rewind, Welcome};

const DEVICE: [u8; 16] = [0xd1; 16];
const HOST: &str = "ingest.example";
const EPOCH: [u8; 16] = [0xe1; 16];

fn session() -> Session<KeySigner> {
    let cfg = SessionConfig {
        device_id: DEVICE,
        hostname: HOST.into(),
        firmware_version: 1,
        config_version: 2,
        table_version: 3,
        trust_version: 4,
        max_batches_per_poll: 8,
    };
    Session::new(cfg, KeySigner::from_seed([5; 32]))
}

fn log_with(p0: u8, p1: u8) -> DurableLog<MemStorage> {
    let (mut log, _) = DurableLog::open(MemStorage::new(1 << 20)).unwrap();
    for k in 0..p0 {
        log.append(Class::P0, 0, [k; 16], 1, &[k; 100]).unwrap();
    }
    for k in 0..p1 {
        log.append(Class::P1, 0, [k; 16], 1, &[k; 100]).unwrap();
    }
    log
}

/// A Welcome as an honest server sends it: each mark above zero carries the chain of the
/// frame that ends there.
fn welcome(
    log: &DurableLog<MemStorage>,
    epoch: [u8; 16],
    state: i32,
    committed: [u64; 3],
    backed_up: [u64; 3],
) -> Envelope {
    let marks = Class::ALL
        .map(|c| Mark {
            class: c as u32,
            committed_next: committed[c.index()],
            backed_up_next: backed_up[c.index()],
            chain: log
                .read_all(c)
                .unwrap()
                .iter()
                .find(|f| f.end_seq() == committed[c.index()])
                .map(|f| f.header.chain.to_vec())
                .unwrap_or_default(),
        })
        .to_vec();
    Envelope::of(Body::Welcome(
        Welcome {
            protocol_version: 1,
            state,
            server_time_ms: 0,
            epoch: epoch.to_vec(),
            marks,
            check: Vec::new(),
        }
        .with_check(),
    ))
}

fn credit(class: Class, bytes: u64) -> Envelope {
    Envelope::of(Body::Credit(Credit {
        class: class as u32,
        bytes,
    }))
}

/// Run the handshake to `Active` with the given Welcome.
fn connect(s: &mut Session<KeySigner>, log: &mut DurableLog<MemStorage>, welcome: Envelope) {
    s.on_connected(log, [0xB1; 32]).unwrap();
    s.on_message(
        Envelope::of(Body::Challenge(Challenge {
            nonce: vec![7; 32],
            ..Challenge::default()
        })),
        log,
    )
    .unwrap();
    assert!(s.on_message(welcome, log).unwrap().is_empty());
    assert_eq!(s.phase(), Phase::Active);
}

const ACTIVE: i32 = DeviceState::Active as i32;

fn fresh(s: &mut Session<KeySigner>, log: &mut DurableLog<MemStorage>) {
    let welcome = welcome(log, EPOCH, ACTIVE, [0; 3], [0; 3]);
    connect(s, log, welcome);
}

fn ack(committed_next: u64, backed_up_next: u64) -> Envelope {
    Envelope::of(Body::Ack(
        Ack {
            class: 0,
            committed_next,
            backed_up_next,
            check: Vec::new(),
        }
        .with_check(),
    ))
}

fn batches(out: Vec<Envelope>) -> Vec<Batch> {
    out.into_iter()
        .map(|e| match e.body {
            Some(Body::Batch(b)) => b,
            other => panic!("expected a batch, got {other:?}"),
        })
        .collect()
}

fn sent(s: &mut Session<KeySigner>, log: &mut DurableLog<MemStorage>) -> Vec<(u32, u64)> {
    batches(s.poll(log).unwrap())
        .iter()
        .map(|b| (b.class, b.first_seq))
        .collect()
}

#[test]
fn hello_describes_the_device_and_what_it_holds() {
    let mut s = session();
    let mut log = log_with(3, 1);
    log.ack(Class::P0, 1, 1).unwrap();

    let Some(Body::Hello(hello)) = s.on_connected(&log, [0xB1; 32]).unwrap().body else {
        panic!("expected Hello");
    };
    assert_eq!(hello.device_id, DEVICE);
    assert!(hello.epoch.is_empty());
    assert_eq!(hello.protocol_versions, [1]);
    assert_eq!((hello.firmware_version, hello.table_version), (1, 3));
    let p0 = &hello.cursors[0];
    assert_eq!((p0.class, p0.first_retained_seq, p0.next_seq), (0, 1, 3));
    assert_eq!(hello.cursors[2].next_seq, 0);
    assert_eq!(s.phase(), Phase::AwaitChallenge);
}

#[test]
fn the_challenge_is_answered_with_a_signature_over_nonce_device_and_host() {
    let mut s = session();
    let mut log = log_with(0, 0);
    s.on_connected(&log, [0xB1; 32]).unwrap();
    let challenge = Envelope::of(Body::Challenge(Challenge {
        nonce: vec![7; 32],
        ..Challenge::default()
    }));
    let out = s.on_message(challenge, &mut log).unwrap();

    let [
        Envelope {
            body: Some(Body::Auth(auth)),
        },
    ] = out.as_slice()
    else {
        panic!("expected one Auth");
    };
    let public_key = KeySigner::from_seed([5; 32]).public_key();
    assert!(verify(
        &public_key,
        &auth_message(&[7; 32], &DEVICE, HOST, &[0xB1; 32]),
        &auth.signature
    ));
    assert_eq!(s.phase(), Phase::AwaitWelcome);
}

#[test]
fn nothing_is_sent_without_credit() {
    let mut s = session();
    let mut log = log_with(2, 0);
    fresh(&mut s, &mut log);
    assert!(s.poll(&mut log).unwrap().is_empty());
}

#[test]
fn credit_limits_the_bytes_sent() {
    let mut s = session();
    let mut log = log_with(5, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 200), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 0), (0, 1)]);
    assert!(s.poll(&mut log).unwrap().is_empty());
    s.on_message(credit(Class::P0, 100), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 2)]);
}

#[test]
fn a_frame_larger_than_the_credit_still_goes() {
    // Otherwise it would never be sent, and would hold back every class below it for good.
    let mut s = session();
    let mut log = log_with(2, 1);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 30), &mut log).unwrap();
    s.on_message(credit(Class::P1, 30), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 0)], "one frame, and the credit is used up");
    assert!(s.poll(&mut log).unwrap().is_empty());

    // The frame cost its whole length, 100: the balance is -70, and the server hands back
    // the whole length when it commits.
    s.on_message(credit(Class::P0, 100), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 1), (1, 0)]);
}

#[test]
fn the_balance_is_the_credit_received_less_the_bytes_sent_and_can_go_below_zero() {
    // The server counts the same way, so a device that sends only on a positive balance is
    // never closed for want of credit, whatever is still on its way to it.
    let mut s = session();
    let mut log = log_with(3, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 150), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 0), (0, 1)], "150, then 50, then -50");
    s.on_message(credit(Class::P0, 49), &mut log).unwrap();
    assert!(s.poll(&mut log).unwrap().is_empty(), "-1");
    s.on_message(credit(Class::P0, 1), &mut log).unwrap();
    assert!(s.poll(&mut log).unwrap().is_empty(), "0 is no credit");
    s.on_message(credit(Class::P0, 1), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 2)], "1 lets one frame go");
}

#[test]
fn a_batch_carries_the_frame_as_stored() {
    let mut s = session();
    let mut log = log_with(1, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    let batch = batches(s.poll(&mut log).unwrap()).remove(0);
    assert_eq!((batch.count, batch.format_version, batch.compression), (1, 1, 0));
    assert_eq!(batch.hash, [0; 16]);
    assert_eq!(batch.block, [0; 100]);
}

#[test]
fn a_higher_class_goes_first_and_holds_back_the_lower_ones() {
    let mut s = session();
    let mut log = log_with(2, 2);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P1, 1_000), &mut log).unwrap();
    assert!(s.poll(&mut log).unwrap().is_empty(), "P1 must wait while P0 has data");

    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 0), (0, 1), (1, 0), (1, 1)]);
}

#[test]
fn a_poll_sends_a_bounded_number_of_batches() {
    let mut s = session();
    let mut log = log_with(20, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 1 << 20), &mut log).unwrap();
    assert_eq!(s.poll(&mut log).unwrap().len(), 8);
    assert_eq!(s.poll(&mut log).unwrap().len(), 8);
    assert_eq!(s.poll(&mut log).unwrap().len(), 4);
}

#[test]
fn an_ack_trims_only_what_is_backed_up() {
    let mut s = session();
    let mut log = log_with(4, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log).len(), 4);
    s.on_message(ack(4, 0), &mut log).unwrap();
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 4);
    s.on_message(ack(4, 3), &mut log).unwrap();
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 1);
}

#[test]
fn an_ack_for_more_than_was_sent_is_refused() {
    // A server, or whoever sits in its place, must not be able to make a device discard
    // records it has not uploaded.
    let mut s = session();
    let mut log = log_with(5, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 150), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log).len(), 2);

    for lie in [ack(u64::MAX, u64::MAX), ack(3, 3), ack(1, 2)] {
        assert_eq!(s.on_message(lie, &mut log), Err(SessionError::BadAck));
    }
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 5);
    assert_eq!(log.backed_up_next(Class::P0), 0);

    s.on_message(ack(2, 2), &mut log).unwrap();
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 3);
}

#[test]
fn reconnecting_resends_what_was_sent_but_not_committed() {
    let mut s = session();
    let mut log = log_with(3, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log).len(), 3);

    s.on_disconnected();
    assert_eq!(s.phase(), Phase::Disconnected);
    let again = welcome(&log, EPOCH, ACTIVE, [1, 0, 0], [0; 3]);
    connect(&mut s, &mut log, again);
    assert!(
        s.poll(&mut log).unwrap().is_empty(),
        "credit does not carry across connections"
    );
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 1), (0, 2)]);
}

#[test]
fn a_new_epoch_resends_everything_still_held() {
    let mut s = session();
    let mut log = log_with(3, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    sent(&mut s, &mut log);
    s.on_message(ack(3, 1), &mut log).unwrap();

    s.on_disconnected();
    let new_epoch = welcome(&log, [0xe2; 16], ACTIVE, [0; 3], [0; 3]);
    connect(&mut s, &mut log, new_epoch);
    assert_eq!(log.epoch(), Some([0xe2; 16]));
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 1), (0, 2)]);
}

#[test]
fn a_rewind_sends_from_the_requested_sequence_again() {
    let mut s = session();
    let mut log = log_with(3, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 10_000), &mut log).unwrap();
    sent(&mut s, &mut log);
    s.on_message(rewind(1), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 1), (0, 2)]);
}

fn rewind(from_seq: u64) -> Envelope {
    Envelope::of(Body::Rewind(
        Rewind {
            class: 0,
            from_seq,
            check: Vec::new(),
        }
        .with_check(),
    ))
}

#[test]
fn a_rewind_above_the_cursor_is_refused() {
    // It would move the cursor past frames that were never sent. The next batch would then
    // raise what an Ack may claim above them, and the Ack would trim them unsent.
    let mut s = session();
    let mut log = log_with(5, 0);
    fresh(&mut s, &mut log);
    for from_seq in [1, 3, 5, u64::MAX] {
        assert_eq!(
            s.on_message(rewind(from_seq), &mut log),
            Err(SessionError::BadRewind),
            "nothing sent yet, rewind to {from_seq}"
        );
    }

    s.on_message(credit(Class::P0, 200), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 0), (0, 1)]);
    for from_seq in [3, 5, u64::MAX] {
        assert_eq!(s.on_message(rewind(from_seq), &mut log), Err(SessionError::BadRewind));
    }
    // The cursor has not moved, and nothing was lost.
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 2), (0, 3), (0, 4)]);
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 5);
}

#[test]
fn a_rewind_to_the_cursor_or_below_is_honoured() {
    let mut s = session();
    let mut log = log_with(4, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 200), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 0), (0, 1)]);

    // To where the cursor stands: nothing changes.
    s.on_message(rewind(2), &mut log).unwrap();
    s.on_message(credit(Class::P0, 100), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 2)]);

    // Back, and then the way forward is closed again above where it was put.
    s.on_message(rewind(1), &mut log).unwrap();
    assert_eq!(s.on_message(rewind(2), &mut log), Err(SessionError::BadRewind));
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 1), (0, 2), (0, 3)]);
}

#[test]
fn a_rewind_after_a_reconnect_is_bounded_by_the_servers_mark() {
    let mut s = session();
    let mut log = log_with(4, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log).len(), 4);

    // The cursor of the new session starts at the mark, whatever an earlier one sent.
    s.on_disconnected();
    let again = welcome(&log, EPOCH, ACTIVE, [2, 0, 0], [0; 3]);
    connect(&mut s, &mut log, again);
    assert_eq!(s.on_message(rewind(3), &mut log), Err(SessionError::BadRewind));
    s.on_message(rewind(2), &mut log).unwrap();
    s.on_message(rewind(0), &mut log).unwrap();
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 0), (0, 1), (0, 2), (0, 3)]);
}

/// `(first_seq, cursor_seq)` of each batch a poll sends.
fn cursors(s: &mut Session<KeySigner>, log: &mut DurableLog<MemStorage>) -> Vec<(u64, Option<u64>)> {
    batches(s.poll(log).unwrap())
        .iter()
        .map(|b| (b.first_seq, b.cursor_seq))
        .collect()
}

#[test]
fn a_batch_states_where_the_cursor_stood_before_it() {
    let mut s = session();
    let mut log = log_with(3, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    // Several batches before any Ack: each follows the one before it.
    assert_eq!(cursors(&mut s, &mut log), [(0, Some(0)), (1, Some(1)), (2, Some(2))]);

    // A new session starts from the server's mark.
    s.on_disconnected();
    let again = welcome(&log, EPOCH, ACTIVE, [1, 0, 0], [0; 3]);
    connect(&mut s, &mut log, again);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(cursors(&mut s, &mut log), [(1, Some(1)), (2, Some(2))]);

    // A Rewind puts it back to where the server asked from.
    s.on_message(rewind(1), &mut log).unwrap();
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(cursors(&mut s, &mut log), [(1, Some(1)), (2, Some(2))]);

    // A new epoch starts from nothing.
    s.on_disconnected();
    let new_epoch = welcome(&log, [0xe2; 16], ACTIVE, [0; 3], [0; 3]);
    connect(&mut s, &mut log, new_epoch);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(cursors(&mut s, &mut log), [(0, Some(0)), (1, Some(1)), (2, Some(2))]);
}

#[test]
fn a_batch_carries_a_check_over_its_header() {
    let mut s = session();
    let mut log = log_with(2, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    for batch in batches(s.poll(&mut log).unwrap()) {
        assert_eq!(batch.check, batch.header_check());
    }
}

#[test]
fn a_batch_after_dropped_sequences_states_the_cursor_below_its_first_sequence() {
    // The device says it stepped over the sequences itself. The server would otherwise have
    // to guess whether they were skipped or are still on their way.
    let mut s = session();
    let mut log = log_with(2, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 150), &mut log).unwrap();
    assert_eq!(cursors(&mut s, &mut log), [(0, Some(0)), (1, Some(1))]);

    log.skip(Class::P0, 5).unwrap();
    log.append(Class::P0, 0, [9; 16], 1, &[9; 100]).unwrap();
    log.append(Class::P0, 0, [10; 16], 1, &[10; 100]).unwrap();
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(cursors(&mut s, &mut log), [(7, Some(2)), (8, Some(8))]);
}

#[test]
fn a_batch_after_evicted_frames_states_the_cursor_below_its_first_sequence() {
    let mut s = session();
    let mut log = log_with(5, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 100), &mut log).unwrap();
    assert_eq!(cursors(&mut s, &mut log), [(0, Some(0))]);

    // Frames 1 and 2 are evicted before they were sent.
    let front = log.front_frames(Class::P0, 480).unwrap();
    assert_eq!(front.last().unwrap().end_seq(), 3);
    log.evict_through(Class::P0, front.last().unwrap().next_offset).unwrap();
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(cursors(&mut s, &mut log), [(3, Some(1)), (4, Some(4))]);
}

#[test]
fn a_batch_after_a_rotted_frame_states_the_cursor_below_its_first_sequence() {
    let mut s = session();
    let mut log = log_with(3, 0);
    fresh(&mut s, &mut log);
    // The payload of the second frame rots.
    let second = log.front_frames(Class::P0, u64::MAX).unwrap()[1];
    log.storage_mut().corrupt(Class::P0, second.next_offset - 1);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(cursors(&mut s, &mut log), [(0, Some(0)), (2, Some(1))]);
}

#[test]
fn credit_decides_what_is_sent_and_the_reported_state_does_not() {
    // The server withholds credit from a device it will not take data from. A state this
    // build has never heard of therefore needs no handling here.
    let mut s = session();
    let mut log = log_with(2, 0);
    let unclaimed = welcome(&log, EPOCH, DeviceState::Unclaimed as i32, [0; 3], [0; 3]);
    connect(&mut s, &mut log, unclaimed);
    assert_eq!(s.state(), DeviceState::Unclaimed);
    assert!(s.poll(&mut log).unwrap().is_empty());

    s.on_disconnected();
    let from_the_future = welcome(&log, EPOCH, 9, [0; 3], [0; 3]);
    connect(&mut s, &mut log, from_the_future);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log).len(), 2);
}

#[test]
fn messages_this_build_does_not_know_are_ignored_once_active() {
    let mut s = session();
    let mut log = log_with(1, 0);
    fresh(&mut s, &mut log);
    let unknown_class = [
        Envelope::of(Body::Credit(Credit { class: 7, bytes: 1 })),
        Envelope::of(Body::Rewind(
            Rewind {
                class: 7,
                from_seq: 0,
                check: Vec::new(),
            }
            .with_check(),
        )),
        Envelope::of(Body::Ack(
            Ack {
                class: 7,
                committed_next: 5,
                backed_up_next: 5,
                check: Vec::new(),
            }
            .with_check(),
        )),
        // What a message kind added later decodes to.
        Envelope::default(),
    ];
    for msg in unknown_class {
        assert_eq!(s.on_message(msg, &mut log), Ok(Vec::new()));
    }
    assert_eq!(s.phase(), Phase::Active);
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 1);
}

#[test]
fn messages_out_of_place_are_errors() {
    let mut s = session();
    let mut log = log_with(0, 0);
    assert_eq!(
        s.on_message(credit(Class::P0, 1), &mut log),
        Err(SessionError::Unexpected)
    );

    s.on_connected(&log, [0xB1; 32]).unwrap();
    let no_nonce = Envelope::of(Body::Challenge(Challenge::default()));
    assert_eq!(s.on_message(no_nonce, &mut log), Err(SessionError::BadChallenge));
    let long_nonce = Envelope::of(Body::Challenge(Challenge {
        nonce: vec![7; 33],
        ..Challenge::default()
    }));
    assert_eq!(s.on_message(long_nonce, &mut log), Err(SessionError::BadChallenge));
    s.on_message(challenge(), &mut log).unwrap();

    let short_epoch = Envelope::of(Body::Welcome(
        Welcome {
            protocol_version: 1,
            epoch: vec![1; 4],
            ..Welcome::default()
        }
        .with_check(),
    ));
    assert_eq!(s.on_message(short_epoch, &mut log), Err(SessionError::BadWelcome));
    let version_not_offered = Envelope::of(Body::Welcome(
        Welcome {
            protocol_version: 2,
            epoch: EPOCH.to_vec(),
            ..Welcome::default()
        }
        .with_check(),
    ));
    assert_eq!(
        s.on_message(version_not_offered, &mut log),
        Err(SessionError::BadWelcome)
    );
    assert_eq!(
        s.on_message(Envelope::default(), &mut log),
        Err(SessionError::Unexpected)
    );
}

/// A Welcome for the epoch already held, whose P0 mark carries `chain`.
fn welcome_with_chain(committed_next: u64, backed_up_next: u64, chain: &[u8]) -> Envelope {
    let mark = Mark {
        class: 0,
        committed_next,
        backed_up_next,
        chain: chain.to_vec(),
    };
    Envelope::of(Body::Welcome(
        Welcome {
            protocol_version: 1,
            state: ACTIVE,
            server_time_ms: 0,
            epoch: EPOCH.to_vec(),
            marks: vec![mark],
            check: Vec::new(),
        }
        .with_check(),
    ))
}

fn challenge() -> Envelope {
    Envelope::of(Body::Challenge(Challenge {
        nonce: vec![7; 32],
        ..Challenge::default()
    }))
}

#[test]
fn a_batch_carries_the_chain_of_its_frame() {
    let mut s = session();
    let mut log = log_with(2, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    let sent = batches(s.poll(&mut log).unwrap());
    let frames = log.read_all(Class::P0).unwrap();
    assert_eq!(sent[1].chain, frames[1].header.chain);
}

#[test]
fn a_welcome_that_agrees_with_the_log_is_accepted() {
    let mut s = session();
    let mut log = log_with(3, 0);
    fresh(&mut s, &mut log);
    s.on_disconnected();
    let chain = log.read_all(Class::P0).unwrap()[1].header.chain;
    connect(&mut s, &mut log, welcome_with_chain(2, 0, &chain));
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 2)]);
}

#[test]
fn a_welcome_that_contradicts_the_log_is_answered_with_a_resync() {
    let mut s = session();
    let mut log = log_with(3, 0);
    fresh(&mut s, &mut log);
    s.on_disconnected();

    // Same epoch and a mark at the end of our log, but for content we never sent: the
    // sign of another device with our identity. Skipping to the mark would lose our data.
    s.on_connected(&log, [0xB1; 32]).unwrap();
    s.on_message(challenge(), &mut log).unwrap();
    let out = s.on_message(welcome_with_chain(3, 0, &[0xaa; 16]), &mut log).unwrap();
    assert_eq!(out, [Envelope::of(Body::Resync(Resync {}))]);
    assert_eq!(s.phase(), Phase::AwaitWelcome);
    assert!(s.on_message(credit(Class::P0, 1_000), &mut log).unwrap().is_empty());

    let fresh_epoch = welcome(&log, [0xe9; 16], ACTIVE, [0; 3], [0; 3]);
    assert!(s.on_message(fresh_epoch, &mut log).unwrap().is_empty());
    assert_eq!((s.phase(), log.epoch()), (Phase::Active, Some([0xe9; 16])));
    assert!(
        s.poll(&mut log).unwrap().is_empty(),
        "credit from before the resync must not count"
    );
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 0), (0, 1), (0, 2)]);
}

/// The Welcome of a reconnecting session, sent to a device that already holds `EPOCH`.
fn reconnect(
    s: &mut Session<KeySigner>,
    log: &mut DurableLog<MemStorage>,
    welcome: Envelope,
) -> Result<Vec<Envelope>, SessionError> {
    s.on_disconnected();
    s.on_connected(log, [0xB1; 32]).unwrap();
    s.on_message(challenge(), log).unwrap();
    s.on_message(welcome, log)
}

#[test]
fn a_mark_that_cannot_be_checked_is_refused() {
    let mut s = session();
    let mut log = log_with(3, 0);
    fresh(&mut s, &mut log);

    // Without a chain there is nothing to compare, and the marks would be trimmed against.
    for chain in [&[][..], &[0xaa; 4][..]] {
        let unchecked = welcome_with_chain(3, 3, chain);
        assert_eq!(reconnect(&mut s, &mut log, unchecked), Err(SessionError::BadWelcome));
    }
    let chain = log.read_all(Class::P0).unwrap()[2].header.chain;
    let more_backed_up_than_committed = welcome_with_chain(3, 4, &chain);
    assert_eq!(
        reconnect(&mut s, &mut log, more_backed_up_than_committed),
        Err(SessionError::BadWelcome)
    );
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 3);
}

#[test]
fn a_mark_in_a_hole_of_the_log_is_answered_with_a_resync() {
    // This device holds three frames it never sent, then dropped a block. Another device
    // with the same identity uploaded as far as sequence 8. No frame of ours ends there, so
    // the mark cannot be compared; accepting it would discard the three frames.
    let mut s = session();
    let mut log = log_with(3, 0);
    fresh(&mut s, &mut log);
    log.skip(Class::P0, 5).unwrap();

    let out = reconnect(&mut s, &mut log, welcome_with_chain(8, 8, &[0x99; 16])).unwrap();
    assert_eq!(out, [Envelope::of(Body::Resync(Resync {}))]);
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 3);
}

/// The same message with its check taken away, as a server that predates it would send it.
fn without_check(mut msg: Envelope) -> Envelope {
    match msg.body.as_mut() {
        Some(Body::Ack(a)) => a.check.clear(),
        Some(Body::Rewind(r)) => r.check.clear(),
        Some(Body::Welcome(w)) => w.check.clear(),
        other => panic!("no check on {other:?}"),
    }
    msg
}

/// The same message with `change` made to it on the way, after its check was taken.
fn damaged<F: FnOnce(&mut Body)>(mut msg: Envelope, change: F) -> Envelope {
    change(msg.body.as_mut().unwrap());
    msg
}

#[test]
fn an_ack_is_acted_on_only_with_its_check() {
    // ADV-005: one bit flipped on the way raised the backup mark inside the bounds the
    // device checks, and the device trimmed a frame no backup held.
    let mut s = session();
    let mut log = log_with(4, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log).len(), 4);
    s.on_message(ack(4, 1), &mut log).unwrap();
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 3);

    let flipped = damaged(ack(4, 1), |b| {
        if let Body::Ack(a) = b {
            a.backed_up_next = 3;
        }
    });
    let wrong = damaged(ack(4, 3), |b| {
        if let Body::Ack(a) = b {
            a.check[0] ^= 1;
        }
    });
    for bad in [without_check(ack(4, 3)), flipped, wrong] {
        assert_eq!(s.on_message(bad, &mut log), Err(SessionError::BadCheck));
        assert_eq!(log.read_all(Class::P0).unwrap().len(), 3, "nothing trimmed");
        assert_eq!(log.backed_up_next(Class::P0), 1);
    }

    s.on_message(ack(4, 3), &mut log).unwrap();
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 1);
}

#[test]
fn an_ack_for_a_class_this_build_does_not_know_is_still_checked() {
    let mut s = session();
    let mut log = log_with(1, 0);
    fresh(&mut s, &mut log);
    let unknown = Envelope::of(Body::Ack(Ack {
        class: 7,
        committed_next: 5,
        backed_up_next: 5,
        check: Vec::new(),
    }));
    assert_eq!(s.on_message(unknown, &mut log), Err(SessionError::BadCheck));
}

#[test]
fn a_rewind_is_acted_on_only_with_its_check() {
    let mut s = session();
    let mut log = log_with(4, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 200), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 0), (0, 1)]);

    let flipped = damaged(rewind(1), |b| {
        if let Body::Rewind(r) = b {
            r.from_seq = 0;
        }
    });
    let wrong = damaged(rewind(0), |b| {
        if let Body::Rewind(r) = b {
            r.check[7] ^= 0x80;
        }
    });
    for bad in [without_check(rewind(0)), flipped, wrong] {
        assert_eq!(s.on_message(bad, &mut log), Err(SessionError::BadCheck));
    }
    // The cursor has not moved.
    s.on_message(credit(Class::P0, 100), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 2)]);

    s.on_message(rewind(0), &mut log).unwrap();
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log), [(0, 0), (0, 1), (0, 2), (0, 3)]);
}

#[test]
fn a_welcome_is_believed_only_with_its_check() {
    let mut s = session();
    let mut log = log_with(3, 0);
    fresh(&mut s, &mut log);
    s.on_message(credit(Class::P0, 1_000), &mut log).unwrap();
    assert_eq!(sent(&mut s, &mut log).len(), 3);
    let chain = log.read_all(Class::P0).unwrap()[2].header.chain;

    // A mark's backup raised by a flip, the epoch changed, the check missing or wrong.
    let backed_up = damaged(welcome_with_chain(3, 1, &chain), |b| {
        if let Body::Welcome(w) = b {
            w.marks[0].backed_up_next = 3;
        }
    });
    let epoch = damaged(welcome_with_chain(3, 1, &chain), |b| {
        if let Body::Welcome(w) = b {
            w.epoch[0] ^= 1;
        }
    });
    let wrong = damaged(welcome_with_chain(3, 3, &chain), |b| {
        if let Body::Welcome(w) = b {
            w.check[3] ^= 4;
        }
    });
    for bad in [without_check(welcome_with_chain(3, 3, &chain)), backed_up, epoch, wrong] {
        assert_eq!(reconnect(&mut s, &mut log, bad), Err(SessionError::BadCheck));
        assert_eq!(s.phase(), Phase::AwaitWelcome);
        assert_eq!(log.epoch(), Some(EPOCH), "the epoch is kept");
        assert_eq!(log.read_all(Class::P0).unwrap().len(), 3, "nothing trimmed");
        assert_eq!(log.backed_up_next(Class::P0), 0);
    }

    let out = reconnect(&mut s, &mut log, welcome_with_chain(3, 1, &chain)).unwrap();
    assert!(out.is_empty());
    assert_eq!(s.phase(), Phase::Active);
    assert_eq!(log.read_all(Class::P0).unwrap().len(), 2);
}

#[test]
fn a_first_welcome_is_believed_only_with_its_check() {
    // A first Welcome trims nothing, but it names the epoch the device adopts for good.
    let mut s = session();
    let mut log = log_with(2, 0);
    s.on_connected(&log, [0xB1; 32]).unwrap();
    s.on_message(challenge(), &mut log).unwrap();
    let bad = without_check(welcome(&log, EPOCH, ACTIVE, [0; 3], [0; 3]));
    assert_eq!(s.on_message(bad, &mut log), Err(SessionError::BadCheck));
    assert_eq!(log.epoch(), None);
    assert_eq!(s.phase(), Phase::AwaitWelcome);
}

#[test]
fn the_auth_signs_the_channel_binding() {
    let mut s = session();
    let mut log = log_with(0, 0);
    s.on_connected(&log, [0xB1; 32]).unwrap();
    let out = s
        .on_message(
            Envelope::of(Body::Challenge(Challenge {
                nonce: vec![7; 32],
                ..Challenge::default()
            })),
            &mut log,
        )
        .unwrap();
    let Some(Body::Auth(auth)) = &out[0].body else {
        panic!("expected an Auth")
    };
    let key = KeySigner::from_seed([5; 32]).public_key();
    assert!(verify(
        &key,
        &auth_message(&[7; 32], &DEVICE, HOST, &[0xB1; 32]),
        &auth.signature
    ));
    assert!(!verify(
        &key,
        &auth_message(&[7; 32], &DEVICE, HOST, &[0xB2; 32]),
        &auth.signature
    ));
}
