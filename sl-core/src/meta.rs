use alloc::vec::Vec;

use crate::storage::{Storage, StorageError};

const MAGIC: &[u8; 4] = b"SLM1";
const LEN: usize = 4 + 8 + 1 + 16 + 72 + 48 + 4;

/// Small device state kept outside the log. Two copies are written alternately, so a torn
/// write leaves the previous copy intact.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    pub generation: u64,
    pub epoch: Option<[u8; 16]>,
    /// Lower bound on the next sequence per class, for when the log is empty.
    pub next_seq: [u64; 3],
    pub committed_next: [u64; 3],
    pub backed_up_next: [u64; 3],
    /// Chain value of the newest frame per class, for when the log is empty.
    pub chain: [[u8; 16]; 3],
}

fn u64_at(buf: &[u8], at: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&buf[at..at + 8]);
    u64::from_le_bytes(raw)
}

fn bytes16_at(buf: &[u8], at: usize) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&buf[at..at + 16]);
    out
}

impl Meta {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LEN);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.push(u8::from(self.epoch.is_some()));
        out.extend_from_slice(&self.epoch.unwrap_or([0; 16]));
        for group in [&self.next_seq, &self.committed_next, &self.backed_up_next] {
            for value in group {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
        for chain in &self.chain {
            out.extend_from_slice(chain);
        }
        let crc = crc32fast::hash(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Meta> {
        if buf.len() != LEN || &buf[..4] != MAGIC {
            return None;
        }
        let (body, crc) = buf.split_at(LEN - 4);
        if crc32fast::hash(body).to_le_bytes() != crc {
            return None;
        }
        let generation = u64_at(buf, 4);
        // The largest generation has no successor: a copy carrying it could never be
        // replaced, so it is not a copy this code wrote.
        if generation == u64::MAX {
            return None;
        }
        let group = |at: usize| [u64_at(buf, at), u64_at(buf, at + 8), u64_at(buf, at + 16)];
        Some(Meta {
            generation,
            epoch: (buf[12] == 1).then(|| bytes16_at(buf, 13)),
            next_seq: group(29),
            committed_next: group(53),
            backed_up_next: group(77),
            chain: [bytes16_at(buf, 101), bytes16_at(buf, 117), bytes16_at(buf, 133)],
        })
    }

    /// The newest valid copy, or the default when neither slot holds one. A slot that
    /// cannot be read is an error, not an empty slot: treating it as empty would silently
    /// forget the epoch.
    pub fn load<S: Storage>(storage: &S) -> Result<Meta, StorageError> {
        let slot = |i: usize| -> Result<Option<Meta>, StorageError> {
            Ok(storage.read_meta(i)?.and_then(|bytes| Meta::decode(&bytes)))
        };
        Ok(match (slot(0)?, slot(1)?) {
            (Some(a), Some(b)) => {
                if a.generation >= b.generation {
                    a
                } else {
                    b
                }
            }
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => Meta::default(),
        })
    }

    /// Write a new generation into the slot that does not hold the current one.
    pub fn store<S: Storage>(&mut self, storage: &mut S) -> Result<(), StorageError> {
        self.generation += 1;
        storage.write_meta((self.generation % 2) as usize, &self.encode())
    }
}
