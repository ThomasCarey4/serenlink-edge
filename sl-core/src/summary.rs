use alloc::vec::Vec;

use sl_proto::block::Block;
use sl_proto::record::Gap;

use crate::storage::{Storage, StorageError};

const MAGIC: &[u8; 4] = b"SLG1";
/// Metadata slots holding the two copies.
const SLOTS: [usize; 2] = [4, 5];

/// The losses declared and not yet known to be backed up by the server, kept outside the log.
///
/// A declaration is a P0 frame, and a P0 frame can rot before it is uploaded. Its own range
/// is then declared lost, but the gaps it carried cannot be read from it, so they are
/// declared again from here. Kept in two copies written alternately, like `Meta`, and
/// written before the declaration it covers is appended, so it never lags a durable one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub generation: u64,
    /// One past the last P0 sequence of the newest declaration covered. Once the server's
    /// P0 backup mark reaches it, every declaration covered is backed up and `gaps` can go.
    pub carrier_end: u64,
    pub gaps: Vec<Gap>,
}

impl Summary {
    pub fn encode(&self) -> Vec<u8> {
        let mut block = Block::new(0, 0);
        block.gaps = self.gaps.clone();
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&self.carrier_end.to_le_bytes());
        block.encode(&mut out);
        let crc = crc32fast::hash(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Option<Summary> {
        if buf.len() < 4 + 16 + 4 || &buf[..4] != MAGIC {
            return None;
        }
        let (body, crc) = buf.split_at(buf.len() - 4);
        if crc32fast::hash(body).to_le_bytes() != crc {
            return None;
        }
        let u64_at = |at: usize| {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&body[at..at + 8]);
            u64::from_le_bytes(raw)
        };
        let generation = u64_at(4);
        // As for `Meta`: a copy with no successor is not one this code wrote.
        if generation == u64::MAX {
            return None;
        }
        let block = Block::decode(&body[20..]).ok()?;
        Some(Summary {
            generation,
            carrier_end: u64_at(12),
            gaps: block.gaps,
        })
    }

    /// The newest readable copy, or an empty summary when neither slot holds one. A slot
    /// that cannot be read counts as empty: the declarations it covered are still in the log,
    /// and only a second fault, rot in one of them, would make the difference.
    pub fn load<S: Storage>(storage: &S) -> Summary {
        let slot = |i: usize| {
            storage
                .read_meta(i)
                .ok()
                .flatten()
                .and_then(|bytes| Summary::decode(&bytes))
        };
        match (slot(SLOTS[0]), slot(SLOTS[1])) {
            (Some(a), Some(b)) => {
                if a.generation >= b.generation {
                    a
                } else {
                    b
                }
            }
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => Summary::default(),
        }
    }

    /// Write a new generation into the slot that does not hold the current one.
    pub fn store<S: Storage>(&mut self, storage: &mut S) -> Result<(), StorageError> {
        self.generation += 1;
        storage.write_meta(SLOTS[(self.generation % 2) as usize], &self.encode())
    }
}
