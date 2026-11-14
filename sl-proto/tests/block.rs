use sl_proto::block::{Block, block_hash, chain_hash};
use sl_proto::compress::{Compression, compress, decompress};
use sl_proto::error::DecodeError;
use sl_proto::record::{AnchorSource, Define, Gap, GapReason, Kind, TimeAnchor};
use sl_proto::value::{Value, ValueType};

fn sample_block() -> Block {
    let mut b = Block::new(7, 14);
    b.defines.push(Define {
        local_id: 1,
        stable_key: 1_290_250_001,
        path: "navigation.position".into(),
        source: 0xc078_af00_8ff6_7ca1,
        value_type: ValueType::Position,
        unit: "deg".into(),
        kind: Kind::Linear,
    });
    b.anchors.push(TimeAnchor {
        mono_ms: 1_000,
        utc_ms: 1_794_487_144_000,
        source: AnchorSource::Gnss,
        quality: 3,
    });
    b.gaps.push(Gap {
        reason: GapReason::PowerOff,
        lost_class: 0,
        from_boot: 6,
        from_mono_ms: 99,
        to_mono_ms: 0,
        lost_first_seq: 0,
        lost_records: 0,
    });
    for i in 0..50u64 {
        let t = 1_000 + i * 1_000;
        let k = i as i32;
        b.push_sample(
            1,
            t,
            Value::Position {
                lat_e7: 515_000_000 + k * 7,
                lon_e7: -1_000_000 - k,
            },
        );
        b.push_sample(2, t, Value::F64(4.2 + i as f64 * 0.01));
        b.push_sample(3, t, Value::F32(180.0 - i as f32));
        b.push_sample(4, t, Value::I64(-5 + i as i64 * 1_000_000_007));
        b.push_sample(5, t, Value::Bool(i % 3 == 0));
        b.push_sample(6, t, Value::Enum(i as u32 % 4));
    }
    b.push_sample(7, 5, Value::Blob(vec![1, 2, 3]));
    b.push_sample(7, 9, Value::Blob(Vec::new()));
    b
}

fn encoded(b: &Block) -> Vec<u8> {
    let mut out = Vec::new();
    b.encode(&mut out);
    out
}

#[test]
fn block_round_trips() {
    let b = sample_block();
    assert_eq!(Block::decode(&encoded(&b)), Ok(b));
}

#[test]
fn record_count_counts_every_record() {
    assert_eq!(sample_block().record_count(), 1 + 1 + 1 + 50 * 6 + 2);
    assert!(Block::new(1, 1).is_empty());
}

#[test]
fn samples_of_one_signal_share_a_column() {
    let b = sample_block();
    assert_eq!(b.columns.len(), 7);
    assert_eq!(b.columns[0].samples().len(), 50);
    assert_eq!(
        (b.columns[0].local_id(), b.columns[0].value_type()),
        (1, ValueType::Position)
    );
}

#[test]
fn a_type_change_starts_a_new_column() {
    let mut b = Block::new(1, 1);
    b.push_sample(9, 1, Value::F64(1.0));
    b.push_sample(9, 2, Value::I64(2));
    b.push_sample(9, 3, Value::I64(3));
    assert_eq!(b.columns.len(), 2);
    assert_eq!(Block::decode(&encoded(&b)), Ok(b));
}

#[test]
fn every_truncation_is_an_error_not_a_panic() {
    let bytes = encoded(&sample_block());
    for n in 0..bytes.len() {
        assert!(Block::decode(&bytes[..n]).is_err(), "prefix of {n} bytes decoded");
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = encoded(&sample_block());
    bytes.push(0);
    assert_eq!(Block::decode(&bytes), Err(DecodeError::Trailing));
}

#[test]
fn an_impossible_count_is_rejected_before_allocating() {
    // version, boot_id, table_version, then a define count of about four billion.
    let bytes = [1, 0, 0, 0xff, 0xff, 0xff, 0xff, 0x0f];
    assert_eq!(Block::decode(&bytes), Err(DecodeError::BadLength));
}

#[test]
fn a_bounded_decode_takes_a_block_up_to_the_limit_and_no_further() {
    let block = sample_block();
    let bytes = encoded(&block);
    let n = block.record_count();
    assert_eq!(Block::decode_bounded(&bytes, n), Ok(block.clone()));
    assert_eq!(Block::decode_bounded(&bytes, u32::MAX), Ok(block));
    for limit in [0, 1, 2, 3, 52, n - 1] {
        assert_eq!(
            Block::decode_bounded(&bytes, limit),
            Err(DecodeError::TooManyRecords),
            "limit {limit}"
        );
    }
}

#[test]
fn the_record_limit_counts_every_kind_of_record() {
    // One of each kind, and each alone is over a limit of nothing.
    let mut defines = Block::new(1, 1);
    defines.defines.push(sample_block().defines.remove(0));
    let mut anchors = Block::new(1, 1);
    anchors.anchors.push(sample_block().anchors.remove(0));
    let mut gaps = Block::new(1, 1);
    gaps.gaps.push(sample_block().gaps.remove(0));
    let mut samples = Block::new(1, 1);
    samples.push_sample(1, 5, Value::Bool(true));
    for block in [defines, anchors, gaps, samples] {
        let bytes = encoded(&block);
        assert_eq!(Block::decode_bounded(&bytes, 0), Err(DecodeError::TooManyRecords));
        assert_eq!(Block::decode_bounded(&bytes, 1), Ok(block));
    }
    assert_eq!(
        Block::decode_bounded(&encoded(&Block::new(1, 1)), 0),
        Ok(Block::new(1, 1))
    );
}

#[test]
fn a_column_over_the_record_limit_is_refused_before_its_samples_are_read() {
    // The column says it holds three samples and then stops: with room for three records
    // the samples are looked for and found missing, without it they are never looked for.
    let mut bytes = vec![1, 0, 0, 0, 0, 0, 1, 1, 4, 3, 0, 0, 0];
    assert_eq!(Block::decode_bounded(&bytes, 3), Err(DecodeError::Truncated));
    assert_eq!(Block::decode_bounded(&bytes, 2), Err(DecodeError::TooManyRecords));
    bytes.extend([0, 1, 0]);
    assert_eq!(Block::decode_bounded(&bytes, 3).map(|b| b.record_count()), Ok(3));
}

#[test]
fn an_unknown_block_version_is_rejected() {
    let mut bytes = encoded(&sample_block());
    bytes[0] = 9;
    assert_eq!(Block::decode(&bytes), Err(DecodeError::BadTag(9)));
}

#[test]
fn a_boolean_byte_other_than_zero_or_one_is_rejected() {
    let mut b = Block::new(1, 1);
    b.push_sample(1, 0, Value::Bool(true));
    let mut bytes = encoded(&b);
    let last = bytes.len() - 1;
    assert_eq!(bytes[last], 1);
    bytes[last] = 2;
    assert_eq!(Block::decode(&bytes), Err(DecodeError::BadTag(2)));
}

#[test]
fn the_chain_depends_on_everything_before_it() {
    let start = [0u8; 16];
    let a = chain_hash(&start, 0, 3, &[1; 16]);
    assert_eq!(a, chain_hash(&start, 0, 3, &[1; 16]));
    assert_ne!(a, chain_hash(&[9; 16], 0, 3, &[1; 16]));
    assert_ne!(a, chain_hash(&start, 1, 3, &[1; 16]));
    assert_ne!(a, chain_hash(&start, 0, 4, &[1; 16]));
    assert_ne!(a, chain_hash(&start, 0, 3, &[2; 16]));
    assert_ne!(chain_hash(&a, 3, 1, &[5; 16]), chain_hash(&start, 3, 1, &[5; 16]));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The encoding and both hashes, byte for byte. Round-trip tests pass when the encoder and
/// the decoder change together; devices in the field and blocks already stored do not.
#[test]
fn the_block_encoding_and_hashes_are_frozen() {
    let mut b = Block::new(7, 14);
    b.defines.push(Define {
        local_id: 1,
        stable_key: 300,
        path: "a.b".into(),
        source: 9,
        value_type: ValueType::F32,
        unit: "m".into(),
        kind: Kind::WrappingAngle,
    });
    b.anchors.push(TimeAnchor {
        mono_ms: 1_000,
        utc_ms: 2_000,
        source: AnchorSource::Gnss,
        quality: 3,
    });
    b.gaps.push(Gap {
        reason: GapReason::BufferEvicted,
        lost_class: 2,
        from_boot: 6,
        from_mono_ms: 99,
        to_mono_ms: 100,
        lost_first_seq: 5,
        lost_records: 4,
    });
    b.push_sample(1, 1_000, Value::F32(1.5));
    b.push_sample(1, 2_000, Value::F32(1.5));
    b.push_sample(
        2,
        1_000,
        Value::Position {
            lat_e7: 10,
            lon_e7: -10,
        },
    );
    b.push_sample(3, 1_000, Value::I64(-3));
    b.push_sample(4, 1_000, Value::Bool(true));
    b.push_sample(5, 1_000, Value::Enum(2));
    b.push_sample(6, 1_000, Value::F64(0.5));
    b.push_sample(7, 1_000, Value::Blob(vec![0xab, 0xcd]));

    let bytes = encoded(&b);
    assert_eq!(
        hex(&bytes),
        "01070e0101ac0203612e620901016d0101e807d00f0103010202066364050407010102d00fd00f0000c03f00000000020601d00f1413030301d00f05040401d00f01050501d00f02060201d00f000000000000e03f070701d00f02abcd"
    );
    let hash = block_hash(&bytes);
    assert_eq!(hex(&hash), "768a9be7f8187578e845693c6b30fc1b");
    assert_eq!(
        hex(&chain_hash(&[0x11; 16], 42, 12, &hash)),
        "47e7a33d0053833799b6943280d2bb24"
    );
}

#[test]
fn hash_depends_on_content() {
    let a = encoded(&sample_block());
    let mut other = sample_block();
    other.push_sample(1, 99_999, Value::Position { lat_e7: 0, lon_e7: 0 });
    assert_ne!(block_hash(&a), block_hash(&encoded(&other)));
    assert_eq!(block_hash(&a), block_hash(&a));
}

#[test]
fn no_compression_is_the_identity() {
    let data = encoded(&sample_block());
    let packed = compress(Compression::None, &data).unwrap();
    assert_eq!(packed, data);
    assert_eq!(decompress(Compression::None, &packed, data.len()).unwrap(), data);
    assert_eq!(
        decompress(Compression::None, &packed, data.len() - 1),
        Err(DecodeError::BadLength)
    );
    assert_eq!(Compression::from_u8(1), Some(Compression::Zstd));
    assert_eq!(Compression::from_u8(2), None);
}

#[cfg(feature = "zstd")]
#[test]
fn zstd_round_trips_and_shrinks_steady_signals() {
    let mut b = Block::new(1, 1);
    for i in 0..1_000u64 {
        b.push_sample(1, i * 1_000, Value::F64(12.6));
    }
    let data = encoded(&b);
    let packed = compress(Compression::Zstd, &data).unwrap();
    assert!(packed.len() < 200, "compressed to {} bytes", packed.len());
    assert_eq!(decompress(Compression::Zstd, &packed, 1 << 20).unwrap(), data);
}

#[cfg(not(feature = "zstd"))]
#[test]
fn zstd_is_reported_unsupported_without_the_feature() {
    assert_eq!(compress(Compression::Zstd, b"x"), Err(DecodeError::Unsupported));
}
