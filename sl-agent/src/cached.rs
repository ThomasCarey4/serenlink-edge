//! What SignalK replays on connect. It answers a new subscription with the last value it has
//! of every path and source, however old (days, for a GPS since switched off), under the time it
//! was heard. Recorded as arriving now, an old position would put a jump in the track.
//!
//! So for the first `WINDOW_MS` of a connection, a value older than `OLD_MS` is not recorded as
//! it comes. An old number or position is dropped. An old state or null may still be how things
//! stand (engine hours while the engines are off, a name sent once), so the newest for its path
//! is held, and recorded when the window ends if nothing newer came on the path. After the
//! window every update is live whatever its timestamp says, so a SignalK whose clock is wrong
//! costs ten seconds and not the recording.
use std::collections::{BTreeMap, HashSet};

use crate::policy::{Category, categorize};
use crate::signalk::Update;

pub const WINDOW_MS: u64 = 10_000;
pub const OLD_MS: u64 = 60_000;

/// One SignalK connection's first moments.
pub struct Gate {
    until: u64,
    released: bool,
    live: HashSet<String>,
    held: BTreeMap<String, (u64, Update)>,
    pub dropped: u64,
}

impl Gate {
    pub fn new(now_ms: u64) -> Self {
        Self {
            until: now_ms + WINDOW_MS,
            released: false,
            live: HashSet::new(),
            held: BTreeMap::new(),
            dropped: 0,
        }
    }

    /// Milliseconds until `release` has something to do; None once it has been done.
    pub fn due_in(&self, now_ms: u64) -> Option<u64> {
        (!self.released).then(|| self.until.saturating_sub(now_ms))
    }

    /// The update, if it is to be recorded now. `utc_ms` is the wall clock at its arrival.
    pub fn admit(&mut self, u: Update, now_ms: u64, utc_ms: u64) -> Option<Update> {
        if self.released || now_ms >= self.until {
            return Some(u);
        }
        let Some(ts) = u.utc_ms.filter(|ts| utc_ms.saturating_sub(*ts) > OLD_MS) else {
            self.held.remove(&u.path);
            self.live.insert(u.path.clone());
            return Some(u);
        };
        let keep = match categorize(&u.path) {
            Category::Dump => return None,
            Category::State => true,
            Category::Position | Category::Sensor => u.value.is_null(),
        };
        // Several sources may hold a path; the newest is what it last was. A newer number
        // beats an older null, which must then not be recorded over it.
        let beaten = self.live.contains(&u.path) || self.held.get(&u.path).is_some_and(|(t, _)| *t >= ts);
        if beaten || !keep {
            self.dropped += 1;
        }
        if !beaten {
            self.held.insert(u.path.clone(), (ts, u));
        }
        None
    }

    /// When the window has ended, once: the held values to record.
    pub fn release(&mut self, now_ms: u64) -> Vec<Update> {
        if self.released || now_ms < self.until {
            return Vec::new();
        }
        self.released = true;
        self.live = HashSet::new();
        std::mem::take(&mut self.held)
            .into_values()
            .map(|(_, u)| u)
            .filter(|u| u.value.is_null() || categorize(&u.path) == Category::State)
            .collect()
    }
}
