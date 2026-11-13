use sl_proto::error::DecodeError;
use sl_proto::ids::Class;
use sl_proto::record::{AnchorSource, GapReason, Kind};
use sl_proto::value::{Value, ValueType};
use sl_proto::varint::{get_i64, get_u64, put_i64, put_u64};

#[test]
fn varint_round_trips_edge_values() {
    for v in [0u64, 1, 127, 128, 300, u64::from(u32::MAX), u64::MAX] {
        let mut buf = Vec::new();
        put_u64(&mut buf, v);
        let mut pos = 0;
        assert_eq!(get_u64(&buf, &mut pos), Ok(v));
        assert_eq!(pos, buf.len());
    }
}

#[test]
fn zigzag_round_trips_signed_values() {
    for v in [0i64, -1, 1, -123_456, i64::MIN, i64::MAX] {
        let mut buf = Vec::new();
        put_i64(&mut buf, v);
        let mut pos = 0;
        assert_eq!(get_i64(&buf, &mut pos), Ok(v));
    }
}

#[test]
fn small_magnitudes_take_one_byte() {
    let mut buf = Vec::new();
    put_i64(&mut buf, -3);
    assert_eq!(buf.len(), 1);
}

#[test]
fn truncated_varint_is_an_error() {
    let mut pos = 0;
    assert_eq!(get_u64(&[0x80], &mut pos), Err(DecodeError::Truncated));
}

#[test]
fn overlong_varint_is_an_error() {
    let mut pos = 0;
    assert_eq!(get_u64(&[0xff; 11], &mut pos), Err(DecodeError::Overflow));
}

#[test]
fn a_tenth_byte_may_carry_only_the_top_bit() {
    let mut max = vec![0xff; 9];
    max.push(0x01);
    assert_eq!(get_u64(&max, &mut 0), Ok(u64::MAX));
    // Bits that do not fit in 64 must not be dropped in silence.
    let mut beyond = vec![0xff; 9];
    beyond.push(0x02);
    assert_eq!(get_u64(&beyond, &mut 0), Err(DecodeError::Overflow));
}

#[test]
fn class_indexes_and_conversions_are_stable() {
    assert_eq!(Class::ALL.map(Class::index), [0, 1, 2]);
    assert_eq!(Class::from_u8(1), Some(Class::P1));
    assert_eq!(Class::from_u8(3), None);
    assert_eq!(Class::from_u32(2), Some(Class::P2));
    assert_eq!(Class::from_u32(256), None);
}

#[test]
fn value_reports_its_type() {
    assert_eq!(Value::F64(1.0).value_type(), ValueType::F64);
    assert_eq!(
        Value::Position { lat_e7: 1, lon_e7: 2 }.value_type(),
        ValueType::Position
    );
    assert_eq!(ValueType::from_u8(7), Some(ValueType::Blob));
    assert_eq!(ValueType::from_u8(0), None);
}

#[test]
fn record_enums_reject_unknown_tags() {
    assert_eq!(Kind::from_u8(1), Some(Kind::WrappingAngle));
    assert_eq!(Kind::from_u8(6), None);
    assert_eq!(AnchorSource::from_u8(1), Some(AnchorSource::Gnss));
    assert_eq!(AnchorSource::from_u8(0), None);
    assert_eq!(GapReason::from_u8(8), Some(GapReason::HardwareSwap));
    assert_eq!(GapReason::from_u8(9), None);
}
