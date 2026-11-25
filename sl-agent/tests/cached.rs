use serde_json::{Value, json};
use sl_agent::cached::{Gate, OLD_MS, WINDOW_MS};
use sl_agent::signalk::Update;

const NOW: u64 = 1_795_607_548_571;
const POS: &str = "navigation.position";
const SOG: &str = "navigation.speedOverGround";
const HOURS: &str = "propulsion.port.runTime";

fn up(path: &str, source: &str, age: Option<u64>, value: Value) -> Update {
    Update {
        path: path.into(),
        source: source.into(),
        utc_ms: age.map(|a| NOW - a),
        value,
    }
}

#[test]
fn old_numbers_and_positions_are_dropped_and_live_ones_pass() {
    let mut g = Gate::new(0);
    let fix = json!({"latitude": 14.41, "longitude": -60.88});
    assert!(
        g.admit(up(POS, "gps2", Some(133_649_000), fix.clone()), 5, NOW)
            .is_none()
    );
    assert!(
        g.admit(up(SOG, "gps2", Some(OLD_MS + 1), json!(0.04)), 5, NOW)
            .is_none()
    );
    assert!(g.admit(up(POS, "gps1", Some(100), fix), 5, NOW).is_some());
    assert!(g.admit(up(SOG, "gps1", Some(OLD_MS), json!(1.0)), 5, NOW).is_some());
    assert!(g.release(WINDOW_MS).is_empty());
    assert_eq!(g.dropped, 2);
}

#[test]
fn no_timestamp_and_a_future_one_are_live() {
    let mut g = Gate::new(0);
    assert!(g.admit(up(SOG, "a", None, json!(1.0)), 5, NOW).is_some());
    let mut u = up(SOG, "a", None, json!(1.0));
    u.utc_ms = Some(NOW + 86_400_000);
    assert!(g.admit(u, 5, NOW).is_some());
}

#[test]
fn the_newest_old_state_is_recorded_when_the_window_ends_once() {
    let mut g = Gate::new(1_000);
    assert!(g.admit(up(HOURS, "a", Some(200_000), json!(7)), 1_001, NOW).is_none());
    assert!(g.admit(up(HOURS, "b", Some(100_000), json!(8)), 1_001, NOW).is_none());
    assert!(g.admit(up(HOURS, "c", Some(300_000), json!(6)), 1_001, NOW).is_none());
    assert!(g.release(1_000 + WINDOW_MS - 1).is_empty());
    assert_eq!(g.due_in(1_000 + WINDOW_MS - 1), Some(1));
    let got = g.release(1_000 + WINDOW_MS);
    assert_eq!(got.iter().map(|u| &u.value).collect::<Vec<_>>(), [&json!(8)]);
    assert!(g.release(1_000 + WINDOW_MS).is_empty());
    assert_eq!(g.due_in(1_000 + WINDOW_MS), None);
}

#[test]
fn a_live_value_beats_a_held_one_in_either_order() {
    for live_first in [true, false] {
        let mut g = Gate::new(0);
        let old = up("navigation.gnss.type", "gps2", Some(133_649_000), json!("GLONASS"));
        let new = up("navigation.gnss.type", "gps1", Some(10), json!("GPS"));
        for u in if live_first { [new, old] } else { [old, new] } {
            g.admit(u, 5, NOW);
        }
        assert!(g.release(WINDOW_MS).is_empty(), "live first: {live_first}");
    }
}

#[test]
fn an_old_null_is_held_unless_a_newer_number_was_replayed() {
    let mut g = Gate::new(0);
    g.admit(up(SOG, "a", Some(200_000), Value::Null), 5, NOW);
    assert_eq!(g.release(WINDOW_MS).len(), 1);
    for number_first in [true, false] {
        let mut g = Gate::new(0);
        let null = up(SOG, "a", Some(200_000), Value::Null);
        let number = up(SOG, "b", Some(100_000), json!(1.0));
        for u in if number_first { [number, null] } else { [null, number] } {
            g.admit(u, 5, NOW);
        }
        assert!(g.release(WINDOW_MS).is_empty(), "number first: {number_first}");
    }
}

#[test]
fn after_the_window_an_old_timestamp_is_live() {
    let mut g = Gate::new(0);
    assert!(
        g.admit(up(SOG, "a", Some(133_649_000), json!(1.0)), WINDOW_MS, NOW)
            .is_some()
    );
}
