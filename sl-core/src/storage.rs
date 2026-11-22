use alloc::vec::Vec;

use sl_proto::ids::Class;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    /// Nothing was written; there is no room.
    Full,
    /// Nothing was written; the frame is larger than the log format allows.
    TooLarge,
    /// The write may have been partly applied, or the read was out of range.
    Io,
}

/// Small metadata slots `Storage` holds: 0 and 1 are the log's (`Meta`), 2 and 3 the trust
/// store's (`TrustAnchor`), 4 and 5 the recorder's declared losses (`Summary`).
pub const META_SLOTS: usize = 6;

/// Three append-only byte logs, one per class, plus `META_SLOTS` small metadata slots.
///
/// This is the contract the in-memory store and a file store meet. Raw flash cannot meet it
/// as written; what has to change for that is listed at the end of the part A plan.
///
/// Offsets are logical: they start at 0, only grow, and are not reset when the front of a
/// log is trimmed. `append` is durable when it returns `Ok`. A failed `append` or
/// `write_meta` may leave a partial write behind; callers detect that with checksums.
pub trait Storage {
    /// Most bytes the three logs can hold together.
    fn capacity(&self) -> u64;
    /// Offset of the first byte still held.
    fn start(&self, class: Class) -> u64;
    /// Offset one past the last byte written.
    fn end(&self, class: Class) -> u64;
    fn append(&mut self, class: Class, data: &[u8]) -> Result<(), StorageError>;
    /// Fill `buf` from `offset`. The whole range must lie between `start` and `end`.
    fn read(&self, class: Class, offset: u64, buf: &mut [u8]) -> Result<(), StorageError>;
    /// Discard everything before `new_start`.
    fn trim_front(&mut self, class: Class, new_start: u64) -> Result<(), StorageError>;
    /// Discard everything from `new_end` on.
    fn truncate(&mut self, class: Class, new_end: u64) -> Result<(), StorageError>;
    /// `slot` is below `META_SLOTS`.
    fn read_meta(&self, slot: usize) -> Result<Option<Vec<u8>>, StorageError>;
    /// `slot` is below `META_SLOTS`.
    fn write_meta(&mut self, slot: usize, data: &[u8]) -> Result<(), StorageError>;
}
