//! What the agent records, and how often: the old compressor's choice, unchanged (agent spec
//! 3.3), so the dual-run compares like with like. The rules engine replaces it later.
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value as Json;
use sl_proto::ids::Class;

pub const POSITION_EVERY_MS: u64 = 1_000;
pub const SENSOR_EVERY_MS: u64 = 2_000;
pub const STATE_EVERY_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Dump,
    State,
    Position,
    Sensor,
}

pub const DUMP: &[&str] = &[
    r"^(.*)(totalPanel)(.*)$",
    r"^(.*)(ModeNumber)(.*)$",
    r"^(.*)(consumedCharge)(.*)$",
    r"^(electrical\.batteries.279)(.*)$",
    r"^(propulsion\.)([^.]+)(\..*(diagnostic|status|raw|error|fault).*)$",
    r"^(navigation\.gnss\.satellitesInView)$",
];
pub const STATE: &[&str] = &[
    r"^(.*)(([mM])ode)$",
    r"^(.*)\.(name)$",
    r"^(.*)\.(state)$",
    r"^(propulsion\.)([^.]+)(\.(gear|tiltTrim|runTime))$",
    r"^(electrical\.batteries\.)([0-9]+)(\.capacity\.dischargedEnergy)$",
    r"^(electrical\.batteries\.)([0-9]+)(\.capacity\.stateOfCharge)$",
    r"^(electrical\.batteries\.)([0-9]+)(\.lifetimeDischarge)$",
    r"^(electrical\.solar\.)([0-9]+)(\.systemYield)$",
    r"^(electrical\.solar\.)([0-9]+)(\.yieldToday)$",
    r"^(electrical\.solar\.)([0-9]+)(\.yieldYesterday)$",
    r"^(navigation\.courseRhumbline\.nextPoint\.position)$",
    r"^(navigation\.currentRoute\.)(.*)$",
    r"^(navigation\.gns)(.*)$",
    r"^(navigation\.magneticVariation)$",
    r"^(navigation\.trip\.log)$",
    r"^(notifications)(.*)$",
    r"^(sensors\.ais)(.*)$",
    r"^(steering)(.*)$",
];
pub const POSITION: &[&str] = &[r"^(navigation\.position)$"];
pub const SENSOR: &[&str] = &[
    r"^(.*)([cC]urrent)$",
    r"^(.*)([pP]ower)$",
    r"^(.*)([vV]oltage)$",
    r"^(.*)([tT]emperature)$",
    r"^(environment)(.*)$",
    r"^(navigation)(.*)$",
    r"^(propulsion)(.*)$",
];

static PATTERNS: LazyLock<[(Category, Vec<Regex>); 4]> = LazyLock::new(|| {
    let build = |list: &[&str]| {
        list.iter()
            .map(|p| Regex::new(p).expect("a fixed pattern compiles"))
            .collect()
    };
    [
        (Category::Dump, build(DUMP)),
        (Category::State, build(STATE)),
        (Category::Position, build(POSITION)),
        (Category::Sensor, build(SENSOR)),
    ]
});

/// The compressor's `categorize_data`: the first list with a match decides, in the order
/// dump, state, position, sensor; no match is `Dump`.
pub fn categorize(path: &str) -> Category {
    for (category, patterns) in PATTERNS.iter() {
        if patterns.iter().any(|r| r.is_match(path)) {
            return *category;
        }
    }
    Category::Dump
}

/// The compressor's `is_zero_position`.
fn is_zero_position(v: &Json) -> bool {
    match (
        v.get("latitude").and_then(Json::as_f64),
        v.get("longitude").and_then(Json::as_f64),
    ) {
        (Some(lat), Some(lon)) => lat == 0.0 || lon == 0.0,
        _ => false,
    }
}

#[derive(Default)]
pub struct Policy {
    last_at: HashMap<String, u64>,
    last_state: HashMap<String, Json>,
    /// Paths whose last recorded value is null.
    null: HashSet<String>,
}

impl Policy {
    pub fn new() -> Self {
        Self::default()
    }

    /// The class to record `value` of `path` in at `now_ms`, or None to drop it.
    pub fn decide(&mut self, path: &str, value: &Json, now_ms: u64) -> Option<Class> {
        let (class, every) = match categorize(path) {
            Category::Dump => return None,
            Category::Position => (Class::P0, POSITION_EVERY_MS),
            Category::State => (Class::P0, STATE_EVERY_MS),
            Category::Sensor => (Class::P1, SENSOR_EVERY_MS),
        };
        // A null is recorded once, when the path stops having a value (or has none when first
        // heard), outside the rate limit: the last word of a source that went away must not be
        // lost to a value recorded just before it. The compressor repeats nulls.
        if value.is_null() {
            self.last_state.remove(path);
            return self.null.insert(path.to_string()).then_some(class);
        }
        // The compressor's RateLimiter: a path never seen counts as last sent at time 0, and the
        // window is stamped before any later check can drop the sample.
        let last = self.last_at.get(path).copied();
        if last.is_some_and(|t| now_ms.saturating_sub(t) < every) {
            return None;
        }
        self.last_at.insert(path.to_string(), now_ms);
        match categorize(path) {
            Category::Position if is_zero_position(value) => None,
            Category::State => {
                if self.last_state.get(path) == Some(value) {
                    return None;
                }
                self.last_state.insert(path.to_string(), value.clone());
                self.null.remove(path);
                Some(class)
            }
            _ => {
                self.null.remove(path);
                Some(class)
            }
        }
    }
}
