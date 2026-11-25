use serde_json::json;
use sl_agent::policy::{Category, Policy, categorize};
use sl_proto::ids::Class;

#[test]
fn paths_categorise_as_the_compressor_does() {
    let cases = [
        ("navigation.position", Category::Position),
        ("navigation.speedOverGround", Category::Sensor),
        ("environment.wind.speedApparent", Category::Sensor),
        ("electrical.batteries.0.voltage", Category::Sensor),
        ("propulsion.port.temperature", Category::Sensor),
        ("propulsion.port.revolutions", Category::Sensor),
        ("propulsion.port.gear", Category::State),
        ("propulsion.port.runTime", Category::State),
        ("steering.autopilot.state", Category::State),
        ("navigation.gnss.methodQuality", Category::State),
        ("navigation.magneticVariation", Category::State),
        ("notifications.mob", Category::State),
        ("electrical.batteries.0.capacity.stateOfCharge", Category::State),
        ("electrical.solar.1.yieldToday", Category::State),
        ("navigation.courseRhumbline.nextPoint.position", Category::State),
        ("electrical.chargers.1.chargingMode", Category::State),
        ("navigation.gnss.satellitesInView", Category::Dump),
        ("electrical.batteries.279.voltage", Category::Dump),
        ("electrical.solar.0.totalPanelPower", Category::Dump),
        ("propulsion.port.diagnostic.code", Category::Dump),
        ("electrical.batteries.0.consumedCharge", Category::Dump),
        ("design.length", Category::Dump),
        ("tanks.fuel.0.currentLevel", Category::Dump),
    ];
    for (path, want) in cases {
        assert_eq!(categorize(path), want, "{path}");
    }
}

#[test]
fn sensors_are_rate_limited_per_path_to_two_seconds_in_p1() {
    let mut p = Policy::new();
    let v = json!(1.5);
    assert_eq!(p.decide("navigation.speedOverGround", &v, 10_000), Some(Class::P1));
    assert_eq!(p.decide("navigation.speedOverGround", &v, 11_999), None);
    assert_eq!(p.decide("navigation.headingTrue", &v, 11_999), Some(Class::P1));
    assert_eq!(p.decide("navigation.speedOverGround", &v, 12_000), Some(Class::P1));
}

#[test]
fn positions_are_every_second_in_p0_and_zero_ones_are_skipped_after_the_limit() {
    let mut p = Policy::new();
    let good = json!({"latitude": 50.1, "longitude": -1.2});
    let zero = json!({"latitude": 0.0, "longitude": -1.2});
    assert_eq!(p.decide("navigation.position", &zero, 10_000), None);
    // The zero position used the window: as the compressor, which stamps the time first.
    assert_eq!(p.decide("navigation.position", &good, 10_500), None);
    assert_eq!(p.decide("navigation.position", &good, 11_000), Some(Class::P0));
}

#[test]
fn states_are_every_five_seconds_and_only_on_change_in_p0() {
    let mut p = Policy::new();
    assert_eq!(
        p.decide("propulsion.port.gear", &json!("neutral"), 10_000),
        Some(Class::P0)
    );
    assert_eq!(p.decide("propulsion.port.gear", &json!("forward"), 12_000), None);
    assert_eq!(p.decide("propulsion.port.gear", &json!("neutral"), 15_000), None);
    assert_eq!(
        p.decide("propulsion.port.gear", &json!("forward"), 20_000),
        Some(Class::P0)
    );
}

#[test]
fn dumped_and_unmatched_paths_are_dropped() {
    let mut p = Policy::new();
    assert_eq!(p.decide("navigation.gnss.satellitesInView", &json!({}), 0), None);
    assert_eq!(p.decide("design.length", &json!(12), 0), None);
}

#[test]
fn the_first_sample_of_a_path_at_time_zero_is_recorded() {
    let mut p = Policy::new();
    assert_eq!(p.decide("navigation.speedOverGround", &json!(1), 0), Some(Class::P1));
}

/// The compressor's source is outside `edge/`, which the published repo does not have, so this
/// test exists only with `--features monorepo-tests` (`include_str!` is resolved at compile time).
#[cfg(feature = "monorepo-tests")]
#[test]
fn the_lists_are_the_compressors() {
    use sl_agent::policy::{DUMP, POSITION, SENSOR, STATE};
    let src = include_str!("../../../signalkCompressor/src/main.rs");
    for p in [DUMP, STATE, POSITION, SENSOR].concat() {
        assert!(
            src.contains(&format!("Regex::new(r\"{p}\")")),
            "{p} is not in the compressor"
        );
    }
}

#[test]
fn a_null_is_recorded_once_at_once_and_the_next_value_is_recorded() {
    let mut p = Policy::new();
    let null = json!(null);
    for (path, value, every, class) in [
        ("navigation.speedOverGround", json!(1.5), 2_000, Class::P1),
        ("propulsion.port.gear", json!("neutral"), 5_000, Class::P0),
        (
            "navigation.position",
            json!({"latitude": 50.1, "longitude": -1.2}),
            1_000,
            Class::P0,
        ),
    ] {
        assert_eq!(p.decide(path, &value, 10_000), Some(class), "{path}");
        assert_eq!(p.decide(path, &null, 10_001), Some(class), "{path}");
        assert_eq!(p.decide(path, &null, 30_000), None, "{path}");
        assert_eq!(
            p.decide(path, &value, 10_000 + every),
            Some(class),
            "{path}: the same value again"
        );
        assert_eq!(p.decide(path, &null, 10_001 + every), Some(class), "{path}");
    }
    assert_eq!(p.decide("design.length", &null, 0), None);
}
