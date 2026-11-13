//! Tests written to kill cargo-mutants survivors in `sl-proto`: every enum tag decodes to
//! its own variant, the block size limit, column accessors, and the build without zstd.

use sl_proto::block::{Block, MAX_BLOCK_BYTES};
use sl_proto::compress::{Compression, compress, decompress};
use sl_proto::error::DecodeError;
use sl_proto::ids::Class;
use sl_proto::record::{AnchorSource, Define, Gap, GapReason, Kind, TimeAnchor};
use sl_proto::value::{Value, ValueType};

#[test]
fn every_class_tag_decodes_to_its_class() {
    for class in Class::ALL {
        assert_eq!(Class::from_u8(class as u8), Some(class));
        assert_eq!(Class::from_u32(class as u32), Some(class));
    }
    assert_eq!(Class::from_u8(3), None);
}

#[test]
fn every_compression_tag_decodes_to_its_compression() {
    for c in [Compression::None, Compression::Zstd] {
        assert_eq!(Compression::from_u8(c as u8), Some(c));
    }
    assert_eq!(Compression::from_u8(2), None);
}

const KINDS: [Kind; 6] = [
    Kind::Linear,
    Kind::WrappingAngle,
    Kind::SignedAngle,
    Kind::Enum,
    Kind::Bitfield,
    Kind::Counter,
];

const SOURCES: [AnchorSource; 6] = [
    AnchorSource::Gnss,
    AnchorSource::N2k,
    AnchorSource::Nmea0183,
    AnchorSource::Ntp,
    AnchorSource::Server,
    AnchorSource::Rtc,
];

const REASONS: [GapReason; 8] = [
    GapReason::PowerOff,
    GapReason::BufferEvicted,
    GapReason::SourceSilent,
    GapReason::OverQuotaDrop,
    GapReason::UpdateReboot,
    GapReason::Corrupt,
    GapReason::Quarantined,
    GapReason::HardwareSwap,
];

#[test]
fn every_record_tag_decodes_to_its_variant() {
    for k in KINDS {
        assert_eq!(Kind::from_u8(k as u8), Some(k));
    }
    assert_eq!(Kind::from_u8(6), None);
    for s in SOURCES {
        assert_eq!(AnchorSource::from_u8(s as u8), Some(s));
    }
    assert_eq!(AnchorSource::from_u8(0), None);
    assert_eq!(AnchorSource::from_u8(7), None);
    for r in REASONS {
        assert_eq!(GapReason::from_u8(r as u8), Some(r));
    }
    assert_eq!(GapReason::from_u8(0), None);
    assert_eq!(GapReason::from_u8(9), None);
}

#[test]
fn a_block_with_every_record_variant_round_trips() {
    let mut block = Block::new(1, 2);
    for (i, kind) in KINDS.into_iter().enumerate() {
        block.defines.push(Define {
            local_id: i as u32,
            stable_key: 0,
            path: "p".into(),
            source: 0,
            value_type: ValueType::F64,
            unit: String::new(),
            kind,
        });
    }
    for source in SOURCES {
        block.anchors.push(TimeAnchor {
            mono_ms: 1,
            utc_ms: 2,
            source,
            quality: 3,
        });
    }
    for reason in REASONS {
        block.gaps.push(Gap {
            reason,
            lost_class: 0,
            from_boot: 0,
            from_mono_ms: 0,
            to_mono_ms: 0,
            lost_first_seq: 0,
            lost_records: 0,
        });
    }
    let mut encoded = Vec::new();
    block.encode(&mut encoded);
    assert_eq!(Block::decode(&encoded), Ok(block));
}

#[test]
fn the_block_limit_is_one_mebibyte() {
    // The delivery-spine plan: no encoded block is larger than 1 MiB.
    assert_eq!(MAX_BLOCK_BYTES, 1024 * 1024);
}

#[test]
fn a_block_is_empty_until_it_holds_a_record() {
    let mut block = Block::new(0, 0);
    assert!(block.is_empty());
    block.push_sample(7, 0, Value::Bool(true));
    assert!(!block.is_empty());
}

#[test]
fn a_column_reports_its_signal() {
    let mut block = Block::new(0, 0);
    block.push_sample(7, 0, Value::I64(1));
    block.push_sample(0, 0, Value::I64(1));
    let ids: Vec<u32> = block.columns.iter().map(|c| c.local_id()).collect();
    assert_eq!(ids, [7, 0]);
}

#[cfg(not(feature = "zstd"))]
#[test]
fn without_zstd_the_codec_is_refused_not_faked() {
    assert_eq!(compress(Compression::Zstd, b"data"), Err(DecodeError::Unsupported));
    assert_eq!(
        decompress(Compression::Zstd, b"data", MAX_BLOCK_BYTES),
        Err(DecodeError::Unsupported)
    );
}

#[cfg(feature = "zstd")]
#[test]
fn with_zstd_the_codec_round_trips() {
    let data = vec![42u8; 4096];
    let packed = compress(Compression::Zstd, &data).unwrap();
    assert!(packed.len() < data.len());
    assert_eq!(decompress(Compression::Zstd, &packed, MAX_BLOCK_BYTES), Ok(data));
    assert_eq!(
        decompress(Compression::Zstd, &packed, 4095),
        Err(DecodeError::BadLength)
    );
}
