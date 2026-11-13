use alloc::string::String;

use crate::value::ValueType;

/// How a quantity behaves, which decides how deadbands and aggregates treat it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Linear = 0,
    WrappingAngle = 1,
    SignedAngle = 2,
    Enum = 3,
    Bitfield = 4,
    Counter = 5,
}

impl Kind {
    pub fn from_u8(v: u8) -> Option<Kind> {
        match v {
            0 => Some(Kind::Linear),
            1 => Some(Kind::WrappingAngle),
            2 => Some(Kind::SignedAngle),
            3 => Some(Kind::Enum),
            4 => Some(Kind::Bitfield),
            5 => Some(Kind::Counter),
            _ => None,
        }
    }
}

/// Binds a small per-device id to a signal. Sent before the id is first used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Define {
    pub local_id: u32,
    /// PGN and field id for table-decoded signals; 0 when the device invented the path.
    pub stable_key: u64,
    pub path: String,
    /// NMEA 2000 NAME of the source; 0 when unknown.
    pub source: u64,
    pub value_type: ValueType,
    pub unit: String,
    pub kind: Kind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AnchorSource {
    Gnss = 1,
    N2k = 2,
    Nmea0183 = 3,
    Ntp = 4,
    Server = 5,
    Rtc = 6,
}

impl AnchorSource {
    pub fn from_u8(v: u8) -> Option<AnchorSource> {
        match v {
            1 => Some(AnchorSource::Gnss),
            2 => Some(AnchorSource::N2k),
            3 => Some(AnchorSource::Nmea0183),
            4 => Some(AnchorSource::Ntp),
            5 => Some(AnchorSource::Server),
            6 => Some(AnchorSource::Rtc),
            _ => None,
        }
    }
}

/// Ties the monotonic clock of the block's boot to UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeAnchor {
    pub mono_ms: u64,
    pub utc_ms: u64,
    pub source: AnchorSource,
    pub quality: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum GapReason {
    PowerOff = 1,
    BufferEvicted = 2,
    SourceSilent = 3,
    OverQuotaDrop = 4,
    UpdateReboot = 5,
    Corrupt = 6,
    Quarantined = 7,
    HardwareSwap = 8,
}

impl GapReason {
    pub fn from_u8(v: u8) -> Option<GapReason> {
        match v {
            1 => Some(GapReason::PowerOff),
            2 => Some(GapReason::BufferEvicted),
            3 => Some(GapReason::SourceSilent),
            4 => Some(GapReason::OverQuotaDrop),
            5 => Some(GapReason::UpdateReboot),
            6 => Some(GapReason::Corrupt),
            7 => Some(GapReason::Quarantined),
            8 => Some(GapReason::HardwareSwap),
            _ => None,
        }
    }
}

/// A stated break in continuity. `to_mono_ms` is on the timeline of the block's boot;
/// `from_mono_ms` is on the timeline of `from_boot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gap {
    pub reason: GapReason,
    /// Index of the class that lost records; meaningful when `lost_records` is not zero.
    pub lost_class: u8,
    pub from_boot: u32,
    pub from_mono_ms: u64,
    pub to_mono_ms: u64,
    /// First lost sequence number, when records were lost from the log.
    pub lost_first_seq: u64,
    pub lost_records: u64,
}
