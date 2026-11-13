//! Protobuf messages. Field tags are the contract: never reuse or renumber one.
use alloc::vec::Vec;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, PartialEq, prost::Message)]
pub struct Envelope {
    #[prost(oneof = "Body", tags = "1, 2, 3, 4, 5, 6, 7, 8, 9")]
    pub body: Option<Body>,
}

impl Envelope {
    pub fn of(body: Body) -> Self {
        Self { body: Some(body) }
    }
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Body {
    #[prost(message, tag = "1")]
    Hello(Hello),
    #[prost(message, tag = "2")]
    Challenge(Challenge),
    #[prost(message, tag = "3")]
    Auth(Auth),
    #[prost(message, tag = "4")]
    Welcome(Welcome),
    #[prost(message, tag = "5")]
    Batch(Batch),
    #[prost(message, tag = "6")]
    Ack(Ack),
    #[prost(message, tag = "7")]
    Rewind(Rewind),
    #[prost(message, tag = "8")]
    Credit(Credit),
    #[prost(message, tag = "9")]
    Resync(Resync),
}

/// Device → server, first message of a session.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Hello {
    #[prost(uint32, repeated, tag = "1")]
    pub protocol_versions: Vec<u32>,
    #[prost(bytes = "vec", tag = "2")]
    pub device_id: Vec<u8>,
    /// Empty when the device has no epoch yet.
    #[prost(bytes = "vec", tag = "3")]
    pub epoch: Vec<u8>,
    #[prost(message, repeated, tag = "4")]
    pub cursors: Vec<Cursor>,
    #[prost(uint32, tag = "5")]
    pub firmware_version: u32,
    #[prost(uint32, tag = "6")]
    pub config_version: u32,
    #[prost(uint32, tag = "7")]
    pub table_version: u32,
    #[prost(uint32, tag = "8")]
    pub trust_version: u32,
}

/// What the device still holds for one class.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Cursor {
    #[prost(uint32, tag = "1")]
    pub class: u32,
    #[prost(uint64, tag = "2")]
    pub first_retained_seq: u64,
    #[prost(uint64, tag = "3")]
    pub next_seq: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Challenge {
    #[prost(bytes = "vec", tag = "1")]
    pub nonce: Vec<u8>,
    /// Server identity key and its signature by the release key. Verified from part C on.
    #[prost(bytes = "vec", tag = "2")]
    pub server_identity_proof: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Auth {
    #[prost(bytes = "vec", tag = "1")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum DeviceState {
    /// May connect; nothing it sends is stored.
    Unclaimed = 0,
    Active = 1,
    /// Over quota: only P0 is accepted.
    Hold = 2,
    Revoked = 3,
    /// Keeps reporting to its owner; cannot be reclaimed.
    Stolen = 4,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Welcome {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(enumeration = "DeviceState", tag = "2")]
    pub state: i32,
    #[prost(uint64, tag = "3")]
    pub server_time_ms: u64,
    /// The epoch the device must use from now on. Always 16 bytes.
    #[prost(bytes = "vec", tag = "4")]
    pub epoch: Vec<u8>,
    #[prost(message, repeated, tag = "5")]
    pub marks: Vec<Mark>,
}

/// Server's position for one class. Both values are exclusive.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Mark {
    #[prost(uint32, tag = "1")]
    pub class: u32,
    #[prost(uint64, tag = "2")]
    pub committed_next: u64,
    #[prost(uint64, tag = "3")]
    pub backed_up_next: u64,
    /// Chain value of the last batch committed for this class in this epoch; empty when
    /// nothing has been committed. The device compares it with its own log.
    #[prost(bytes = "vec", tag = "4")]
    pub chain: Vec<u8>,
}

/// One sealed block, as it sits in the device's log.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Batch {
    #[prost(uint32, tag = "1")]
    pub class: u32,
    #[prost(uint64, tag = "2")]
    pub first_seq: u64,
    #[prost(uint32, tag = "3")]
    pub count: u32,
    #[prost(uint32, tag = "4")]
    pub format_version: u32,
    #[prost(uint32, tag = "5")]
    pub compression: u32,
    /// 16-byte hash of the block before compression.
    #[prost(bytes = "vec", tag = "6")]
    pub hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub block: Vec<u8>,
    /// 16-byte running hash over the class's frames up to and including this one.
    #[prost(bytes = "vec", tag = "8")]
    pub chain: Vec<u8>,
}

/// Sequences below `committed_next` are in the database; below `backed_up_next` they are
/// also archived off the node, and only those may be trimmed by the device.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Ack {
    #[prost(uint32, tag = "1")]
    pub class: u32,
    #[prost(uint64, tag = "2")]
    pub committed_next: u64,
    #[prost(uint64, tag = "3")]
    pub backed_up_next: u64,
}

/// Server asks for everything from `from_seq` again.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Rewind {
    #[prost(uint32, tag = "1")]
    pub class: u32,
    #[prost(uint64, tag = "2")]
    pub from_seq: u64,
}

/// Adds `bytes` of upload allowance for one class.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Credit {
    #[prost(uint32, tag = "1")]
    pub class: u32,
    #[prost(uint64, tag = "2")]
    pub bytes: u64,
}

/// Device → server, in reply to a Welcome whose marks contradict the device's log: the
/// server holds something under this epoch that this device did not send. The server starts
/// a fresh epoch and sends a new Welcome.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Resync {}
