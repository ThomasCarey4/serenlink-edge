//! A device-local id and definition for each signal the agent records, and SignalK JSON as a
//! wire value (agent spec 3.4).
use std::collections::HashMap;

use serde_json::Value as Json;
use sl_proto::record::{Define, Kind};
use sl_proto::value::{Value, ValueType};

/// A string or structure whose JSON text is this long or longer is dropped.
pub const MAX_BLOB_BYTES: usize = 4096;

/// SignalK JSON as a wire value. `navigation.position` becomes a position in e7 degrees;
/// other objects, arrays and strings become their JSON text as a blob. Null, a non-finite
/// number, an out-of-range position and an oversized blob yield `None`.
pub fn to_value(path: &str, v: &Json) -> Option<Value> {
    match v {
        Json::Null => None,
        Json::Bool(b) => Some(Value::Bool(*b)),
        Json::Number(n) => n.as_f64().filter(|x| x.is_finite()).map(Value::F64),
        Json::Object(o) if path == "navigation.position" => {
            let lat = o.get("latitude")?.as_f64()?;
            let lon = o.get("longitude")?.as_f64()?;
            if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
                return None;
            }
            Some(Value::Position {
                lat_e7: (lat * 1e7).round() as i32,
                lon_e7: (lon * 1e7).round() as i32,
            })
        }
        other => {
            let text = serde_json::to_vec(other).ok()?;
            (text.len() < MAX_BLOB_BYTES).then_some(Value::Blob(text))
        }
    }
}

/// The definitions the agent has announced, keyed by (path, source, value type).
#[derive(Default)]
pub struct Defines {
    by_key: HashMap<(String, u64, ValueType), Define>,
}

impl Defines {
    pub fn new() -> Self {
        Self::default()
    }

    /// The define for this signal, created with the next local id (from 1) on first use.
    pub fn get(&mut self, path: &str, source: u64, value_type: ValueType) -> &Define {
        let next = self.by_key.len() as u32 + 1;
        self.by_key
            .entry((path.to_string(), source, value_type))
            .or_insert_with(|| Define {
                local_id: next,
                stable_key: 0,
                path: path.to_string(),
                source,
                value_type,
                unit: String::new(),
                kind: Kind::Linear,
            })
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}
