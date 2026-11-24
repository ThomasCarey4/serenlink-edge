use sl_core::frame::{FORMAT_V1, FrameHeader, HEADER_LEN, body_crc, build_frame};
use sl_core::mem_storage::MemStorage;
use sl_core::meta::Meta;
use sl_core::storage::{Storage, StorageError};
use sl_proto::ids::Class;

#[path = "storage_contract.rs"]
mod storage_contract;

#[test]
fn mem_storage_meets_the_contract() {
    storage_contract::check_all(&|capacity| MemStorage::new(capacity));
}

#[test]
fn offsets_are_logical_and_survive_trimming() {
    let mut s = MemStorage::new(1_000);
    s.append(Class::P1, b"abcdef").unwrap();
    s.trim_front(Class::P1, 4).unwrap();
    assert_eq!((s.start(Class::P1), s.end(Class::P1)), (4, 6));

    let mut buf = [0u8; 2];
    s.read(Class::P1, 4, &mut buf).unwrap();
    assert_eq!(&buf, b"ef");
    assert_eq!(s.read(Class::P1, 3, &mut buf), Err(StorageError::Io));

    s.append(Class::P1, b"gh").unwrap();
    assert_eq!(s.end(Class::P1), 8);
    s.truncate(Class::P1, 6).unwrap();
    assert_eq!(s.end(Class::P1), 6);
    assert_eq!(s.used(), 2);
}

#[test]
fn a_full_store_refuses_without_writing() {
    let mut s = MemStorage::new(4);
    assert_eq!(s.capacity(), 4);
    assert_eq!(s.append(Class::P0, b"abcde"), Err(StorageError::Full));
    assert_eq!(s.end(Class::P0), 0);
    s.append(Class::P0, b"abcd").unwrap();
}

#[test]
fn a_power_cut_leaves_a_torn_write_and_a_dead_store() {
    let mut s = MemStorage::new(1_000);
    s.cut_power_after(3);
    assert_eq!(s.append(Class::P0, b"abcdef"), Err(StorageError::Io));
    assert!(s.is_dead());
    assert_eq!(s.end(Class::P0), 3);
    assert_eq!(s.append(Class::P0, b"x"), Err(StorageError::Io));

    s.power_on();
    assert!(!s.is_dead());
    s.append(Class::P0, b"x").unwrap();
    assert_eq!(s.end(Class::P0), 4);
}

#[test]
fn a_write_that_fits_the_remaining_budget_completes() {
    let mut s = MemStorage::new(1_000);
    s.cut_power_after(6);
    s.append(Class::P0, b"abcdef").unwrap();
    assert!(!s.is_dead());
    assert_eq!(s.append(Class::P0, b"g"), Err(StorageError::Io));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn frames_carry_checksums_over_header_and_payload() {
    let frame = build_frame(FORMAT_V1, 1, 42, 3, [7; 16], [8; 16], b"payload");
    assert_eq!(frame.len(), HEADER_LEN + 7);

    let raw: [u8; HEADER_LEN] = frame[..HEADER_LEN].try_into().unwrap();
    let header = FrameHeader::parse(&raw).unwrap();
    assert_eq!(
        (header.version, header.compression, header.ext_len, header.len),
        (FORMAT_V1, 1, 0, 7)
    );
    assert_eq!((header.first_seq, header.count, header.end_seq()), (42, 3, 45));
    assert_eq!((header.hash, header.chain), ([7; 16], [8; 16]));
    assert_eq!(header.encode(), raw);
    assert_eq!(body_crc(&[], b"payload"), header.body_crc);
    assert_ne!(body_crc(&[], b"pay1oad"), header.body_crc);
    assert_eq!(body_crc(b"pay", b"load"), header.body_crc);
}

#[test]
fn a_damaged_header_does_not_parse() {
    let frame = build_frame(FORMAT_V1, 0, 42, 3, [7; 16], [8; 16], b"payload");
    let raw: [u8; HEADER_LEN] = frame[..HEADER_LEN].try_into().unwrap();
    // Every byte is covered, the length included: a header that parses can be believed
    // before any payload is read.
    for at in 0..HEADER_LEN {
        let mut altered = raw;
        altered[at] ^= 1;
        assert_eq!(FrameHeader::parse(&altered), None, "byte {at}");
    }
}

#[test]
fn a_sequence_range_at_the_top_of_the_number_space_does_not_overflow() {
    let frame = build_frame(FORMAT_V1, 0, u64::MAX, 5, [0; 16], [0; 16], b"");
    let raw: [u8; HEADER_LEN] = frame[..HEADER_LEN].try_into().unwrap();
    assert_eq!(FrameHeader::parse(&raw).unwrap().end_seq(), u64::MAX);
}

/// The stored layout, byte for byte. If this test has to change, devices in the field can
/// no longer read their own logs.
#[test]
fn the_frame_layout_is_frozen() {
    let frame = build_frame(
        FORMAT_V1,
        1,
        0x0102_0304_0506_0708,
        3,
        [0x11; 16],
        [0x22; 16],
        b"payload",
    );
    assert_eq!(
        hex(&frame),
        "a5010100070000000807060504030201030000001111111111111111111111111111111122222222222222222222222222222222156a2c4283cc0d027061796c6f6164"
    );
}

#[test]
fn meta_round_trips_and_rejects_damage() {
    let meta = Meta {
        generation: 9,
        epoch: Some([3; 16]),
        next_seq: [10, 20, 30],
        committed_next: [9, 19, 29],
        backed_up_next: [8, 18, 28],
        chain: [[4; 16], [5; 16], [6; 16]],
    };
    let bytes = meta.encode();
    assert_eq!(Meta::decode(&bytes), Some(meta));

    let mut damaged = bytes.clone();
    damaged[20] ^= 0x40;
    assert_eq!(Meta::decode(&damaged), None);
    assert_eq!(Meta::decode(&bytes[..bytes.len() - 1]), None);
}

/// As for frames: the stored layout, byte for byte.
#[test]
fn the_meta_layout_is_frozen() {
    let meta = Meta {
        generation: 9,
        epoch: Some([3; 16]),
        next_seq: [10, 20, 30],
        committed_next: [9, 19, 29],
        backed_up_next: [8, 18, 28],
        chain: [[4; 16], [5; 16], [6; 16]],
    };
    assert_eq!(
        hex(&meta.encode()),
        "534c4d31090000000000000001030303030303030303030303030303030a0000000000000014000000000000001e00000000000000090000000000000013000000000000001d00000000000000080000000000000012000000000000001c000000000000000404040404040404040404040404040405050505050505050505050505050505060606060606060606060606060606066d37ffae"
    );
}

#[test]
fn a_copy_with_the_last_possible_generation_is_not_trusted() {
    // No copy could ever replace it, so every later write would be ignored on load.
    let meta = Meta {
        generation: u64::MAX,
        ..Meta::default()
    };
    assert_eq!(Meta::decode(&meta.encode()), None);
}

#[test]
fn meta_survives_a_torn_write_by_keeping_the_previous_copy() {
    let mut s = MemStorage::new(1_000);
    let mut meta = Meta {
        next_seq: [1, 2, 3],
        ..Meta::default()
    };
    meta.store(&mut s).unwrap();
    meta.next_seq = [4, 5, 6];
    meta.store(&mut s).unwrap();
    assert_eq!(Meta::load(&s).unwrap().next_seq, [4, 5, 6]);

    meta.next_seq = [7, 8, 9];
    s.cut_power_after(10);
    assert_eq!(meta.store(&mut s), Err(StorageError::Io));
    s.power_on();
    assert_eq!(Meta::load(&s).unwrap().next_seq, [4, 5, 6]);
}

#[test]
fn missing_meta_loads_as_default() {
    assert_eq!(Meta::load(&MemStorage::new(10)), Ok(Meta::default()));
}
