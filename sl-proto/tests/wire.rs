use prost::Message;
use sl_proto::auth::{KeySigner, Signer, auth_message, verify};
use sl_proto::wire::{
    Ack, Auth, Batch, Body, Challenge, Credit, Cursor, DeviceState, Envelope, Hello, Mark, PROTOCOL_VERSION, Resync,
    Rewind, Welcome,
};

fn every_body() -> Vec<Body> {
    vec![
        Body::Hello(Hello {
            protocol_versions: vec![PROTOCOL_VERSION],
            device_id: vec![1; 16],
            epoch: vec![2; 16],
            cursors: vec![Cursor {
                class: 0,
                first_retained_seq: 5,
                next_seq: 9,
            }],
            firmware_version: 3,
            config_version: 4,
            table_version: 5,
            trust_version: 6,
        }),
        Body::Challenge(Challenge {
            nonce: vec![7; 32],
            server_identity_proof: vec![8; 4],
        }),
        Body::Auth(Auth { signature: vec![9; 64] }),
        Body::Welcome(Welcome {
            protocol_version: PROTOCOL_VERSION,
            state: DeviceState::Hold as i32,
            server_time_ms: 1_794_487_144_000,
            epoch: vec![2; 16],
            marks: vec![Mark {
                class: 1,
                committed_next: 40,
                backed_up_next: 30,
                chain: vec![6; 16],
            }],
        }),
        Body::Batch(Batch {
            class: 2,
            first_seq: 100,
            count: 12,
            format_version: 1,
            compression: 1,
            hash: vec![3; 16],
            block: vec![4; 300],
            chain: vec![5; 16],
            cursor_seq: Some(96),
            check: vec![6; 8],
        }),
        Body::Ack(Ack {
            class: 0,
            committed_next: 112,
            backed_up_next: 100,
        }),
        Body::Rewind(Rewind { class: 1, from_seq: 77 }),
        Body::Credit(Credit {
            class: 0,
            bytes: 65_536,
        }),
        Body::Resync(Resync {}),
    ]
}

#[test]
fn every_message_round_trips() {
    for body in every_body() {
        let bytes = Envelope::of(body.clone()).encode_to_vec();
        assert_eq!(Envelope::decode(bytes.as_slice()).unwrap().body, Some(body));
    }
}

#[test]
fn unknown_fields_are_skipped() {
    let env = Envelope::of(Body::Credit(Credit { class: 0, bytes: 9 }));
    let mut bytes = env.encode_to_vec();
    // Field 99, varint wire type, value 1: something a newer peer might add.
    bytes.extend_from_slice(&[0x98, 0x06, 0x01]);
    assert_eq!(Envelope::decode(bytes.as_slice()).unwrap(), env);
}

#[test]
fn a_batch_says_whether_it_states_its_cursor() {
    let batch = |cursor_seq| Batch {
        class: 1,
        first_seq: 7,
        count: 2,
        cursor_seq,
        ..Batch::default()
    };
    // A cursor at zero is still a statement, and is not the same as saying nothing.
    let stated = Envelope::of(Body::Batch(batch(Some(0)))).encode_to_vec();
    let silent = Envelope::of(Body::Batch(batch(None))).encode_to_vec();
    assert_ne!(stated, silent);
    for (bytes, cursor_seq) in [(stated, Some(0)), (silent, None)] {
        let Some(Body::Batch(back)) = Envelope::decode(bytes.as_slice()).unwrap().body else {
            panic!("expected a Batch");
        };
        assert_eq!(back.cursor_seq, cursor_seq);
    }
}

fn checked_batch() -> Batch {
    Batch {
        class: 2,
        first_seq: 100,
        count: 12,
        format_version: 1,
        compression: 1,
        hash: vec![3; 16],
        block: vec![4; 300],
        chain: vec![5; 16],
        cursor_seq: Some(96),
        check: Vec::new(),
    }
}

/// What the header check is taken over, byte for byte. A server built from another copy of
/// this code must arrive at the same bytes.
#[test]
fn the_batch_header_check_is_frozen() {
    use sha2::{Digest, Sha256};
    let expected: Vec<u8> = [
        b"serenlink-batch-v1".as_slice(),
        &[2, 0, 0, 0],
        &[100, 0, 0, 0, 0, 0, 0, 0],
        &[12, 0, 0, 0],
        &[1, 0, 0, 0],
        &[1, 0, 0, 0],
        &[16, 0, 0, 0],
        &[3; 16],
        &[16, 0, 0, 0],
        &[5; 16],
        &[1],
        &[96, 0, 0, 0, 0, 0, 0, 0],
    ]
    .concat();
    assert_eq!(checked_batch().header_check()[..], Sha256::digest(&expected)[..8]);

    let mut silent = checked_batch();
    silent.cursor_seq = None;
    let n = expected.len() - 9;
    let expected = [&expected[..n], &[0]].concat();
    assert_eq!(silent.header_check()[..], Sha256::digest(&expected)[..8]);
}

#[test]
fn the_header_check_covers_every_field_but_the_block() {
    let base = checked_batch().header_check();
    let changes: [fn(&mut Batch); 10] = [
        |b| b.class = 0,
        |b| b.first_seq = 108,
        |b| b.count = 13,
        |b| b.format_version = 5,
        |b| b.compression = 0,
        |b| b.hash[15] ^= 1,
        |b| b.chain[0] ^= 0x80,
        |b| b.cursor_seq = Some(100),
        |b| b.cursor_seq = None,
        |b| b.cursor_seq = Some(0),
    ];
    for change in changes {
        let mut b = checked_batch();
        change(&mut b);
        assert_ne!(b.header_check(), base);
    }
    // A byte cannot move from the hash to the chain unseen.
    let mut b = checked_batch();
    b.chain.insert(0, b.hash.pop().unwrap());
    assert_ne!(b.header_check(), base);
    // The block has its own hash, and the check does not cover itself.
    let mut b = checked_batch();
    b.block.clear();
    b.check = vec![1; 8];
    assert_eq!(b.header_check(), base);
}

#[test]
fn welcome_state_reads_back_as_an_enum() {
    let w = Welcome {
        state: DeviceState::Stolen as i32,
        ..Welcome::default()
    };
    assert_eq!(w.state(), DeviceState::Stolen);
    assert_eq!(Welcome::default().state(), DeviceState::Unclaimed);
}

#[test]
fn a_signature_verifies_only_for_its_key_and_message() {
    let signer = KeySigner::from_seed([5; 32]);
    let message = auth_message(&[1; 32], &[2; 16], "ingest.example");
    let signature = signer.sign(&message);

    assert!(verify(&signer.public_key(), &message, &signature));
    assert!(!verify(
        &KeySigner::from_seed([6; 32]).public_key(),
        &message,
        &signature
    ));
    assert!(!verify(
        &signer.public_key(),
        &auth_message(&[9; 32], &[2; 16], "ingest.example"),
        &signature
    ));
    assert!(!verify(&signer.public_key(), &message, &signature[..63]));
}

#[test]
fn auth_message_fields_cannot_run_together() {
    assert_ne!(auth_message(b"ab", b"c", "d"), auth_message(b"a", b"bc", "d"));
    assert_ne!(auth_message(b"a", b"b", "cd"), auth_message(b"a", b"bc", "d"));
}

/// What a device signs, byte for byte. A server built from another copy of this code must
/// arrive at the same bytes.
#[test]
fn the_auth_message_is_frozen() {
    let message = auth_message(&[0xaa; 4], &[0xbb; 2], "host");
    let expected: Vec<u8> = [
        b"serenlink-auth-v1".as_slice(),
        &[4, 0, 0, 0, 0xaa, 0xaa, 0xaa, 0xaa],
        &[2, 0, 0, 0, 0xbb, 0xbb],
        &[4, 0, 0, 0],
        b"host",
    ]
    .concat();
    assert_eq!(message, expected);
}
