use alloc::vec::Vec;

use sl_proto::block::MAX_BLOCK_BYTES;

pub const MAGIC: u8 = 0xA5;
pub const HEADER_LEN: usize = 60;
pub const FORMAT_V1: u8 = 1;
/// Larger payloads are refused on append and treated as corruption on read.
pub const MAX_PAYLOAD: usize = MAX_BLOCK_BYTES;

/// The fixed part of every frame, in every format version. A later version that needs more
/// header fields puts them in the extension (`ext_len` bytes between this header and the
/// payload), which older readers skip; these 60 bytes never change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u8,
    pub compression: u8,
    /// Bytes between the header and the payload that this version does not interpret.
    pub ext_len: u8,
    /// Payload length, not counting the extension.
    pub len: u32,
    pub first_seq: u64,
    pub count: u32,
    /// Hash of the block before compression.
    pub hash: [u8; 16],
    /// Running hash over every frame of the class up to and including this one.
    pub chain: [u8; 16],
    /// CRC-32 over the extension and the payload.
    pub body_crc: u32,
}

impl FrameHeader {
    /// `None` unless the bytes start with the frame magic and pass the header's own CRC, so
    /// the lengths in a header that parses can be trusted before the payload is read.
    pub fn parse(raw: &[u8; HEADER_LEN]) -> Option<FrameHeader> {
        if raw[0] != MAGIC {
            return None;
        }
        let u32_at = |at: usize| u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]);
        if crc32fast::hash(&raw[..56]) != u32_at(56) {
            return None;
        }
        let mut first_seq = [0u8; 8];
        first_seq.copy_from_slice(&raw[8..16]);
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&raw[20..36]);
        let mut chain = [0u8; 16];
        chain.copy_from_slice(&raw[36..52]);
        Some(FrameHeader {
            version: raw[1],
            compression: raw[2],
            ext_len: raw[3],
            len: u32_at(4),
            first_seq: u64::from_le_bytes(first_seq),
            count: u32_at(16),
            hash,
            chain,
            body_crc: u32_at(52),
        })
    }

    /// The header as stored, with its CRC.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut raw = [0u8; HEADER_LEN];
        raw[0] = MAGIC;
        raw[1] = self.version;
        raw[2] = self.compression;
        raw[3] = self.ext_len;
        raw[4..8].copy_from_slice(&self.len.to_le_bytes());
        raw[8..16].copy_from_slice(&self.first_seq.to_le_bytes());
        raw[16..20].copy_from_slice(&self.count.to_le_bytes());
        raw[20..36].copy_from_slice(&self.hash);
        raw[36..52].copy_from_slice(&self.chain);
        raw[52..56].copy_from_slice(&self.body_crc.to_le_bytes());
        let crc = crc32fast::hash(&raw[..56]);
        raw[56..60].copy_from_slice(&crc.to_le_bytes());
        raw
    }

    /// One past the last sequence number the frame covers.
    pub fn end_seq(&self) -> u64 {
        self.first_seq.saturating_add(u64::from(self.count))
    }
}

/// CRC-32 over a frame's extension followed by its payload.
pub fn body_crc(ext: &[u8], payload: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(ext);
    hasher.update(payload);
    hasher.finalize()
}

/// A complete frame with no extension: header, then payload.
pub fn build_frame(
    version: u8,
    compression: u8,
    first_seq: u64,
    count: u32,
    hash: [u8; 16],
    chain: [u8; 16],
    payload: &[u8],
) -> Vec<u8> {
    let header = FrameHeader {
        version,
        compression,
        ext_len: 0,
        len: payload.len() as u32,
        first_seq,
        count,
        hash,
        chain,
        body_crc: body_crc(&[], payload),
    };
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(payload);
    frame
}
