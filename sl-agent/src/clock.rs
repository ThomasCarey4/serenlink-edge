//! The agent's timeline: milliseconds since the process started, on the monotonic clock, and
//! `Ntp` anchors to UTC while the kernel says the system clock is synchronised.
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sl_core::session::anchor_quality;
use sl_proto::record::{AnchorSource, TimeAnchor};

pub struct Clock {
    zero: Instant,
}

impl Clock {
    pub fn start() -> Self {
        Self { zero: Instant::now() }
    }

    pub fn mono_ms(&self) -> u64 {
        self.zero.elapsed().as_millis() as u64
    }

    /// An anchor now, if `adjtimex` reports the clock synchronised; its quality from the
    /// kernel's estimated error.
    pub fn ntp_anchor(&self) -> Option<TimeAnchor> {
        let mut tx: libc::timex = unsafe { std::mem::zeroed() };
        // modes 0: read only.
        let state = unsafe { libc::adjtimex(&mut tx) };
        if state < 0 || state == libc::TIME_ERROR {
            return None;
        }
        let mono_ms = self.mono_ms();
        let utc_ms = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_millis() as u64;
        let err_ms = (tx.esterror.max(0) as u64) / 1_000;
        Some(TimeAnchor {
            mono_ms,
            utc_ms,
            source: AnchorSource::Ntp,
            quality: anchor_quality(err_ms),
        })
    }
}
