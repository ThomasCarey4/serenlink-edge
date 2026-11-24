//! The SignalK side: delta messages from the WebSocket stream, and the source document that
//! turns a `$source` into an NMEA 2000 NAME.
use std::collections::HashMap;

use serde_json::Value as Json;

#[derive(Clone, Debug, PartialEq)]
pub struct Update {
    pub path: String,
    pub source: String,
    pub value: Json,
}

/// Every (path, $source, value) a delta text carries; meta, null values and non-delta
/// messages yield nothing.
pub fn parse_delta(text: &str) -> Vec<Update> {
    let Ok(doc) = serde_json::from_str::<Json>(text) else {
        return Vec::new();
    };
    let Some(updates) = doc.get("updates").and_then(Json::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for update in updates {
        let source = match update.get("$source").and_then(Json::as_str) {
            Some(s) => s.to_string(),
            None => {
                let src = update.get("source");
                let label = src.and_then(|s| s.get("label")).and_then(Json::as_str).unwrap_or("");
                match src.and_then(|s| s.get("src")).and_then(Json::as_str) {
                    Some(n) => format!("{label}.{n}"),
                    None => label.to_string(),
                }
            }
        };
        let Some(values) = update.get("values").and_then(Json::as_array) else {
            continue;
        };
        for v in values {
            let (Some(path), Some(value)) = (v.get("path").and_then(Json::as_str), v.get("value")) else {
                continue;
            };
            if value.is_null() || path.is_empty() {
                continue;
            }
            out.push(Update {
                path: path.to_string(),
                source: source.clone(),
                value: value.clone(),
            });
        }
    }
    out
}

/// `$source` → 64-bit NAME from the `/signalk/v1/api/sources` document; unknown or non-N2K: none.
pub fn names(sources: &Json) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    let Some(labels) = sources.as_object() else {
        return out;
    };
    for (label, entries) in labels {
        let Some(entries) = entries.as_object() else {
            continue;
        };
        for (src, entry) in entries {
            let name = entry
                .get("n2k")
                .and_then(|n| n.get("canName"))
                .and_then(Json::as_str)
                .and_then(|h| u64::from_str_radix(h, 16).ok());
            if let Some(name) = name {
                out.insert(format!("{label}.{src}"), name);
            }
        }
    }
    out
}

/// http://host:port/signalk/v1/api/sources from the stream URL ws://host:port/...
pub fn sources_url(stream_url: &str) -> Option<String> {
    let (scheme, rest) = stream_url.split_once("://")?;
    let http = match scheme {
        "ws" => "http",
        "wss" => "https",
        _ => return None,
    };
    let host = rest.split('/').next().filter(|h| !h.is_empty())?;
    Some(format!("{http}://{host}/signalk/v1/api/sources"))
}
