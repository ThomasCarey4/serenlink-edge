//! Protobuf messages. Field tags are the contract: never reuse or renumber one.
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

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

/// Carries no check: the signature covers everything the device acts on (spec 3.1).
/// Tag 2 (`server_identity_proof`, never filled) is retired and must not be reused.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Challenge {
    #[prost(bytes = "vec", tag = "1")]
    pub nonce: Vec<u8>,
    /// A `SignedIdentityCert`.
    #[prost(bytes = "vec", tag = "3")]
    pub identity_cert: Vec<u8>,
    /// The identity key's signature over `identity::server_message`.
    #[prost(bytes = "vec", tag = "4")]
    pub identity_sig: Vec<u8>,
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
    /// `fields_check` of this Welcome, taken by the server when it sends. The device believes
    /// the marks and the epoch only when it matches: one flipped bit in a mark's
    /// `backed_up_next` would otherwise stay inside the bounds of Decision 14 and trim a
    /// frame no backup holds. A Welcome without it is malformed.
    #[prost(bytes = "vec", tag = "6")]
    pub check: Vec<u8>,
}

impl Welcome {
    /// First 8 bytes of SHA-256 over every field except `check`, the marks included, under a
    /// context of its own. Like every check on a message, it guards against damage on the
    /// way and not against the sender, who can take it over whatever it likes to claim.
    pub fn fields_check(&self) -> [u8; 8] {
        checked(b"serenlink-welcome-v1", |hasher| {
            hasher.update(self.protocol_version.to_le_bytes());
            hasher.update(self.state.to_le_bytes());
            hasher.update(self.server_time_ms.to_le_bytes());
            update_bytes(hasher, &self.epoch);
            hasher.update((self.marks.len() as u32).to_le_bytes());
            for mark in &self.marks {
                hasher.update(mark.class.to_le_bytes());
                hasher.update(mark.committed_next.to_le_bytes());
                hasher.update(mark.backed_up_next.to_le_bytes());
                update_bytes(hasher, &mark.chain);
            }
        })
    }

    /// This Welcome with its check taken over it as it stands.
    pub fn with_check(mut self) -> Self {
        self.check = self.fields_check().to_vec();
        self
    }

    /// Whether the check is present and matches the other fields.
    pub fn is_intact(&self) -> bool {
        self.check == self.fields_check()
    }
}

/// Server's position for one class. Both values are exclusive. A mark travels only inside a
/// Welcome, and the Welcome's check covers it.
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
    /// Where the device's upload cursor for this class stood just before this frame was
    /// sent: the server's mark from the Welcome for the first batch of a session, the end of
    /// the batch before it otherwise, or where a Rewind put the cursor back to. It equals
    /// `first_seq` unless the device stepped over sequences it no longer holds (evicted,
    /// dropped or rotted), and then it is lower. The server takes a batch that is not a
    /// resend only when this equals its own mark, so a batch that overtook another on the
    /// way is not mistaken for such a jump. A batch without it is malformed.
    #[prost(uint64, optional, tag = "9")]
    pub cursor_seq: Option<u64>,
    /// `header_check` of this batch, taken by the device when it sends. The block has its
    /// hash; this covers every other field, so that a field damaged on the way is seen as
    /// damage and not believed: a changed `first_seq` would otherwise read as a jump the
    /// device made, and a changed `format_version` as a format the server cannot read. A
    /// batch without it is malformed.
    #[prost(bytes = "vec", tag = "10")]
    pub check: Vec<u8>,
}

impl Batch {
    /// First 8 bytes of SHA-256 over every field except `block` and `check`. It guards
    /// against damage, not against the device, which can state whatever it likes.
    pub fn header_check(&self) -> [u8; 8] {
        checked(b"serenlink-batch-v1", |hasher| {
            hasher.update(self.class.to_le_bytes());
            hasher.update(self.first_seq.to_le_bytes());
            hasher.update(self.count.to_le_bytes());
            hasher.update(self.format_version.to_le_bytes());
            hasher.update(self.compression.to_le_bytes());
            for field in [&self.hash, &self.chain] {
                update_bytes(hasher, field);
            }
            match self.cursor_seq {
                Some(cursor_seq) => {
                    hasher.update([1]);
                    hasher.update(cursor_seq.to_le_bytes());
                }
                None => hasher.update([0]),
            }
        })
    }
}

/// The construction every message check shares: the first 8 bytes of SHA-256 over a context
/// naming the message kind, then the message's fields. Each kind has its own context and none
/// is a prefix of another, so a check taken over one kind of message never validates
/// another's fields, even when a flipped bit turns one kind into another on the way.
fn checked(context: &[u8], fields: impl FnOnce(&mut Sha256)) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(context);
    fields(&mut hasher);
    let mut check = [0u8; 8];
    check.copy_from_slice(&hasher.finalize()[..8]);
    check
}

/// A variable-length field, after its length, so that no byte can move between two fields.
fn update_bytes(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u32).to_le_bytes());
    hasher.update(field);
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
    /// `fields_check` of this Ack, taken by the server when it sends. The device trims on
    /// `backed_up_next`, and one flipped bit there can stay inside the bounds it checks, so
    /// it acts on an Ack only when this matches. An Ack without it is malformed.
    #[prost(bytes = "vec", tag = "4")]
    pub check: Vec<u8>,
}

impl Ack {
    /// First 8 bytes of SHA-256 over every field except `check`, under a context of its own.
    /// Integrity against damage on the way, not authentication.
    pub fn fields_check(&self) -> [u8; 8] {
        checked(b"serenlink-ack-v1", |hasher| {
            hasher.update(self.class.to_le_bytes());
            hasher.update(self.committed_next.to_le_bytes());
            hasher.update(self.backed_up_next.to_le_bytes());
        })
    }

    /// This Ack with its check taken over it as it stands.
    pub fn with_check(mut self) -> Self {
        self.check = self.fields_check().to_vec();
        self
    }

    /// Whether the check is present and matches the other fields.
    pub fn is_intact(&self) -> bool {
        self.check == self.fields_check()
    }
}

/// Server asks for everything from `from_seq` again.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Rewind {
    #[prost(uint32, tag = "1")]
    pub class: u32,
    #[prost(uint64, tag = "2")]
    pub from_seq: u64,
    /// `fields_check` of this Rewind, taken by the server when it sends. The device moves
    /// its upload cursor only when it matches. A Rewind without it is malformed.
    #[prost(bytes = "vec", tag = "3")]
    pub check: Vec<u8>,
}

impl Rewind {
    /// First 8 bytes of SHA-256 over every field except `check`, under a context of its own.
    /// Integrity against damage on the way, not authentication.
    pub fn fields_check(&self) -> [u8; 8] {
        checked(b"serenlink-rewind-v1", |hasher| {
            hasher.update(self.class.to_le_bytes());
            hasher.update(self.from_seq.to_le_bytes());
        })
    }

    /// This Rewind with its check taken over it as it stands.
    pub fn with_check(mut self) -> Self {
        self.check = self.fields_check().to_vec();
        self
    }

    /// Whether the check is present and matches the other fields.
    pub fn is_intact(&self) -> bool {
        self.check == self.fields_check()
    }
}

/// Adds `bytes` of upload allowance for one class. It carries no check because it only
/// paces: a damaged one lets the device send more or less than the server meant, and every
/// batch sent is still checked and acknowledged on its own. Nothing is trimmed or skipped on
/// its word.
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
