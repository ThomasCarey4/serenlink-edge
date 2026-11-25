//! The SignalK side: delta messages from the WebSocket stream, and the source document that
//! turns a `$source` into an NMEA 2000 NAME.
use std::collections::HashMap;

use serde_json::Value as Json;

#[derive(Clone, Debug, PartialEq)]
pub struct Update {
    pub path: String,
    pub source: String,
    /// When SignalK says the value was heard, if it says so readably.
    pub utc_ms: Option<u64>,
    /// Null when the source reports that it has no value.
    pub value: Json,
}

/// Every (path, $source, value) a delta text carries; meta and non-delta messages
/// yield nothing.
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
        let heard = update.get("timestamp");
        for v in values {
            let (Some(path), Some(value)) = (v.get("path").and_then(Json::as_str), v.get("value")) else {
                continue;
            };
            if path.is_empty() {
                continue;
            }
            out.push(Update {
                path: path.to_string(),
                source: source.clone(),
                utc_ms: v.get("timestamp").or(heard).and_then(Json::as_str).and_then(utc_ms),
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

/// Epoch milliseconds of an RFC 3339 time in UTC, the form SignalK writes
/// (`2026-11-25T11:28:22.613Z`, any or no fraction); None for anything else.
pub fn utc_ms(text: &str) -> Option<u64> {
    let t = text.strip_suffix('Z')?;
    let (date, clock) = t.split_once('T')?;
    let (clock, fraction) = clock.split_once('.').unwrap_or((clock, "0"));
    let digits = |s: &str, n: usize| -> Option<u64> {
        (s.len() == n && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok())?
    };
    let mut d = date.split('-');
    let (y, m, day) = (digits(d.next()?, 4)?, digits(d.next()?, 2)?, digits(d.next()?, 2)?);
    let mut c = clock.split(':');
    let (h, min, sec) = (digits(c.next()?, 2)?, digits(c.next()?, 2)?, digits(c.next()?, 2)?);
    if d.next().is_some() || c.next().is_some() || y < 1970 || !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    if h > 23 || min > 59 || sec > 60 || fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ms = fraction
        .bytes()
        .chain(*b"00")
        .take(3)
        .fold(0, |n, b| n * 10 + u64::from(b - b'0'));
    // Days since 1970-01-01 in the Gregorian calendar, counting years from March.
    let (yy, mm) = if m > 2 { (y, m - 3) } else { (y - 1, m + 9) };
    let days = yy * 365 + yy / 4 - yy / 100 + yy / 400 + (mm * 153 + 2) / 5 + day - 1 - 719_468;
    Some((((days * 24 + h) * 60 + min) * 60 + sec) * 1_000 + ms)
}
