use serde_json::json;
use sl_agent::signalk::{names, parse_delta, sources_url, utc_ms};

#[test]
fn a_delta_yields_each_value_with_its_source_time_and_null_and_skips_meta() {
    let u = parse_delta(include_str!("fixtures/delta-n2k.json"));
    let got: Vec<_> = u.iter().map(|u| (u.path.as_str(), u.source.as_str())).collect();
    assert_eq!(
        got,
        [
            ("navigation.position", "can0.115"),
            ("navigation.speedThroughWater", "can0.35"),
            ("navigation.log", "can0.35"),
            ("electrical.batteries.0.voltage", "venus.com.victronenergy.battery"),
            ("electrical.batteries.0.name", "venus.com.victronenergy.battery"),
        ]
    );
    assert_eq!(u[1].value, json!(2.31));
    assert_eq!(u[2].value, json!(null));
    assert_eq!(u[1].utc_ms, Some(1_795_514_400_100));
}

#[test]
fn hello_and_garbage_yield_nothing() {
    assert!(parse_delta(r#"{"name":"signalk-server","version":"2.8.0","self":"vessels.x"}"#).is_empty());
    assert!(parse_delta("not json").is_empty());
}

#[test]
fn a_source_without_dollar_source_is_named_from_label_and_src() {
    let u = parse_delta(r#"{"updates":[{"source":{"label":"can0","src":"7"},"values":[{"path":"a.b","value":1}]}]}"#);
    assert_eq!(u[0].source, "can0.7");
}

#[test]
fn names_come_from_can_names_in_hex() {
    let doc: serde_json::Value = serde_json::from_str(include_str!("fixtures/sources.json")).unwrap();
    let n = names(&doc);
    assert_eq!(n.get("can0.115"), Some(&0xc078_8c00_e7e0_4312));
    assert_eq!(n.get("can0.35"), Some(&0xc050_a000_2fa0_0b9e));
    assert_eq!(n.get("venus"), None);
}

#[test]
fn the_sources_url_is_on_the_streams_host() {
    assert_eq!(
        sources_url("ws://localhost:3000/signalk/v1/stream").as_deref(),
        Some("http://localhost:3000/signalk/v1/api/sources")
    );
    assert_eq!(
        sources_url("wss://h:3443/x").as_deref(),
        Some("https://h:3443/signalk/v1/api/sources")
    );
    assert_eq!(sources_url("bogus"), None);
}

#[test]
fn times_are_read_to_the_millisecond_and_bad_ones_are_not_read() {
    assert_eq!(utc_ms("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(utc_ms("2000-02-29T23:59:59.9Z"), Some(951_868_799_900));
    assert_eq!(utc_ms("2024-03-01T00:00:00.1239Z"), Some(1_709_251_200_123));
    for bad in [
        "",
        "Z",
        "2026-13-01T00:00:00Z",
        "2026-11-25",
        "2026-11-25T11:28:22+01:00",
        "2026-11-25T1:28:22Z",
        "2026-11-25T11:28:22.Z",
    ] {
        assert_eq!(utc_ms(bad), None, "{bad}");
    }
}

#[test]
fn a_values_own_time_comes_before_its_updates() {
    let u = parse_delta(
        r#"{"updates":[{"timestamp":"1970-01-01T00:00:01Z","values":[
            {"path":"a.b","value":1,"timestamp":"1970-01-01T00:00:02Z"},{"path":"a.c","value":1}]}]}"#,
    );
    assert_eq!((u[0].utc_ms, u[1].utc_ms), (Some(2_000), Some(1_000)));
}
