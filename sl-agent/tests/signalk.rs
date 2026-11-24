use serde_json::json;
use sl_agent::signalk::{names, parse_delta, sources_url};

#[test]
fn a_delta_yields_each_value_with_its_source_and_skips_nulls_and_meta() {
    let u = parse_delta(include_str!("fixtures/delta-n2k.json"));
    let got: Vec<_> = u.iter().map(|u| (u.path.as_str(), u.source.as_str())).collect();
    assert_eq!(
        got,
        [
            ("navigation.position", "can0.115"),
            ("navigation.speedThroughWater", "can0.35"),
            ("electrical.batteries.0.voltage", "venus.com.victronenergy.battery"),
            ("electrical.batteries.0.name", "venus.com.victronenergy.battery"),
        ]
    );
    assert_eq!(u[1].value, json!(2.31));
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
