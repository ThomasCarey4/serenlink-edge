use serde_json::json;
use sl_agent::defines::{Defines, MAX_BLOB_BYTES, to_value};
use sl_proto::value::{Value, ValueType};

#[test]
fn json_maps_to_values() {
    assert_eq!(to_value("a", &json!(2.5)), Some(Value::F64(2.5)));
    assert_eq!(to_value("a", &json!(3)), Some(Value::F64(3.0)));
    assert_eq!(to_value("a", &json!(true)), Some(Value::Bool(true)));
    assert_eq!(
        to_value("navigation.position", &json!({"latitude": 50.75, "longitude": -1.25})),
        Some(Value::Position {
            lat_e7: 507_500_000,
            lon_e7: -12_500_000
        })
    );
    assert_eq!(
        to_value("a", &json!("House")),
        Some(Value::Blob(br#""House""#.to_vec()))
    );
    assert_eq!(
        to_value("a", &json!({"x": [1]})),
        Some(Value::Blob(br#"{"x":[1]}"#.to_vec()))
    );
    assert_eq!(to_value("a", &serde_json::Value::Null), None);
}

#[test]
fn a_bad_position_or_an_oversized_blob_is_dropped() {
    assert_eq!(
        to_value("navigation.position", &json!({"latitude": 91.0, "longitude": 0.5})),
        None
    );
    assert_eq!(to_value("navigation.position", &json!({"latitude": 1.0})), None);
    let big = "x".repeat(MAX_BLOB_BYTES);
    assert_eq!(to_value("a", &json!(big)), None);
}

#[test]
fn a_define_per_path_source_and_type_with_local_ids_from_one() {
    let mut d = Defines::new();
    let a = d.get("navigation.speedThroughWater", 7, ValueType::F64).clone();
    assert_eq!((a.local_id, a.stable_key, a.source, a.unit.as_str()), (1, 0, 7, ""));
    assert_eq!(d.get("navigation.speedThroughWater", 7, ValueType::F64).local_id, 1);
    assert_eq!(d.get("navigation.speedThroughWater", 8, ValueType::F64).local_id, 2);
    assert_eq!(d.get("navigation.speedThroughWater", 7, ValueType::Blob).local_id, 3);
    assert_eq!(d.len(), 3);
}
