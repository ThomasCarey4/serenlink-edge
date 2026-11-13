use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::vec::Vec;

use sl_proto::block::{Block, MAX_BLOCK_BYTES, block_hash};
use sl_proto::compress::{Compression, compress};
use sl_proto::ids::Class;
use sl_proto::record::{Define, Gap, GapReason, TimeAnchor};
use sl_proto::value::Value;

use crate::frame::HEADER_LEN;
use crate::log::{DurableLog, LostRange, Recovery};
use crate::storage::{Storage, StorageError};

#[derive(Clone, Debug)]
pub struct RecorderConfig {
    /// Longest a block stays open, per class.
    pub seal_ms: [u64; 3],
    /// A block is sealed early once its estimated size reaches this.
    pub max_block_bytes: usize,
    pub compression: Compression,
    pub table_version: u32,
}

impl Default for RecorderConfig {
    fn default() -> Self {
        Self {
            seal_ms: [1_000, 5_000, 5_000],
            max_block_bytes: 32 * 1024,
            compression: Compression::None,
            table_version: 0,
        }
    }
}

/// A block that is now durable in the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub class: Class,
    pub first_seq: u64,
    pub count: u32,
    pub hash: [u8; 16],
}

/// Collects records into one open block per class and seals them into the log.
pub struct Recorder {
    cfg: RecorderConfig,
    boot_id: u32,
    open: [Block; 3],
    opened_at: [Option<u64>; 3],
    approx_bytes: [usize; 3],
    /// Where each signal's definition went since this boot, per class: `None` while it is
    /// in the open block, then the first sequence of the block that carried it. An entry is
    /// removed when that block is lost, so the definition is written again.
    defined: [BTreeMap<u32, Option<u64>>; 3],
}

impl Recorder {
    pub fn new(cfg: RecorderConfig, boot_id: u32) -> Self {
        let block = || Block::new(boot_id, cfg.table_version);
        Self {
            open: [block(), block(), block()],
            opened_at: [None; 3],
            approx_bytes: [0; 3],
            defined: [BTreeMap::new(), BTreeMap::new(), BTreeMap::new()],
            boot_id,
            cfg,
        }
    }

    /// Record one value. The signal's definition is written the first time a class uses it,
    /// and again if the block that carried it is lost before upload.
    pub fn sample(&mut self, class: Class, def: &Define, mono_ms: u64, value: Value) {
        let i = class.index();
        if let Entry::Vacant(slot) = self.defined[i].entry(def.local_id) {
            slot.insert(None);
            self.approx_bytes[i] += 32 + def.path.len() + def.unit.len();
            self.open[i].defines.push(def.clone());
        }
        self.approx_bytes[i] += match &value {
            Value::Blob(bytes) => 12 + bytes.len(),
            _ => 12,
        };
        self.open[i].push_sample(def.local_id, mono_ms, value);
        self.opened_at[i].get_or_insert(mono_ms);
    }

    /// Record a time anchor. Anchors describe the device, not a class, and go out first.
    pub fn anchor(&mut self, anchor: TimeAnchor) {
        let i = Class::P0.index();
        self.open[i].anchors.push(anchor);
        self.approx_bytes[i] += 20;
        self.opened_at[i].get_or_insert(anchor.mono_ms);
    }

    pub fn gap(&mut self, class: Class, gap: Gap) {
        let i = class.index();
        self.open[i].gaps.push(gap);
        self.approx_bytes[i] += 24;
        self.opened_at[i].get_or_insert(gap.to_mono_ms);
    }

    /// Record what `DurableLog::open` found missing, so that the server learns of records
    /// lost to corruption. Call once after opening the log, before the first `tick`.
    pub fn report_recovery(&mut self, recovery: &Recovery, now_ms: u64) {
        for lost in &recovery.corrupt {
            self.gap(
                Class::P0,
                Gap {
                    reason: GapReason::Corrupt,
                    lost_class: lost.class as u8,
                    from_boot: self.boot_id,
                    from_mono_ms: now_ms,
                    to_mono_ms: now_ms,
                    lost_first_seq: lost.first_seq,
                    lost_records: lost.count,
                },
            );
        }
    }

    /// Seal every block that has been open for its interval or has grown large.
    pub fn tick<S: Storage>(
        &mut self,
        now_ms: u64,
        log: &mut DurableLog<S>,
        sealed: &mut Vec<Sealed>,
    ) -> Result<(), StorageError> {
        for class in Class::ALL {
            let i = class.index();
            let due = self.opened_at[i].is_some_and(|opened| {
                now_ms.saturating_sub(opened) >= self.cfg.seal_ms[i] || self.approx_bytes[i] >= self.cfg.max_block_bytes
            });
            if due {
                sealed.extend(self.seal(class, now_ms, log)?);
            }
        }
        Ok(())
    }

    /// Seal every open block now. Call before a clean stop.
    pub fn flush<S: Storage>(
        &mut self,
        now_ms: u64,
        log: &mut DurableLog<S>,
        sealed: &mut Vec<Sealed>,
    ) -> Result<(), StorageError> {
        for class in Class::ALL {
            sealed.extend(self.seal(class, now_ms, log)?);
        }
        Ok(())
    }

    fn seal<S: Storage>(
        &mut self,
        class: Class,
        now_ms: u64,
        log: &mut DurableLog<S>,
    ) -> Result<Option<Sealed>, StorageError> {
        let i = class.index();
        if self.open[i].is_empty() {
            return Ok(None);
        }
        let block = core::mem::replace(&mut self.open[i], Block::new(self.boot_id, self.cfg.table_version));
        self.opened_at[i] = None;
        self.approx_bytes[i] = 0;

        let mut encoded = Vec::new();
        block.encode(&mut encoded);
        let hash = block_hash(&encoded);
        let count = block.record_count();
        let raw_len = encoded.len();
        // A compressor that is missing or fails must not cost the block: store it as it is.
        // Each frame records its own compression.
        let (compression, payload) = match compress(self.cfg.compression, &encoded) {
            Ok(payload) => (self.cfg.compression, payload),
            Err(_) => (Compression::None, encoded),
        };

        // A block that could never fit must not empty the log on its way to being dropped.
        let fits_at_all = raw_len <= MAX_BLOCK_BYTES
            && payload.len() <= MAX_BLOCK_BYTES
            && (HEADER_LEN + payload.len()) as u64 <= log.storage().capacity();
        if fits_at_all {
            loop {
                match log.append(class, compression as u8, hash, count, &payload) {
                    Ok(first_seq) => {
                        for def in &block.defines {
                            self.defined[i].insert(def.local_id, Some(first_seq));
                        }
                        return Ok(Some(Sealed {
                            class,
                            first_seq,
                            count,
                            hash,
                        }));
                    }
                    Err(StorageError::Full) => {
                        if !self.make_room(class, now_ms, log)? {
                            break;
                        }
                    }
                    Err(StorageError::TooLarge) => break,
                    Err(e) => {
                        // The write failed part-way. The block is lost all the same, and
                        // has to be accounted for like any other dropped block.
                        let _ = self.drop_block(class, now_ms, &block, count, log);
                        return Err(e);
                    }
                }
            }
        }
        self.drop_block(class, now_ms, &block, count, log)?;
        Ok(None)
    }

    /// Account for a block that will never be in the log. Its sequence numbers are skipped,
    /// never reused, so the gap names a range that nothing else occupies; its definitions
    /// will be written again.
    fn drop_block<S: Storage>(
        &mut self,
        class: Class,
        now_ms: u64,
        block: &Block,
        count: u32,
        log: &mut DurableLog<S>,
    ) -> Result<(), StorageError> {
        let i = class.index();
        for def in &block.defines {
            self.defined[i].remove(&def.local_id);
        }
        let first_seq = log.next_seq(class);
        let skipped = log.skip(class, count);
        self.note_lost(class, now_ms, first_seq, u64::from(count));
        skipped.map(|_| ())
    }

    /// Evict one frame, lowest priority first, never from a class above `class`.
    fn make_room<S: Storage>(
        &mut self,
        class: Class,
        now_ms: u64,
        log: &mut DurableLog<S>,
    ) -> Result<bool, StorageError> {
        for victim in Class::ALL.into_iter().rev() {
            if victim.index() < class.index() {
                break;
            }
            if let Some(lost) = log.evict_oldest(victim)? {
                self.forget_definitions(lost);
                self.note_lost(victim, now_ms, lost.first_seq, lost.count);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Definitions carried by an evicted block never reached the server: write them again.
    fn forget_definitions(&mut self, lost: LostRange) {
        let range = lost.first_seq..lost.first_seq.saturating_add(lost.count);
        self.defined[lost.class.index()].retain(|_, at| !at.is_some_and(|seq| range.contains(&seq)));
    }

    /// Report records lost from `class`. The report goes into P0, the class evicted last,
    /// so that it outlives the data it describes. Consecutive losses are merged.
    fn note_lost(&mut self, class: Class, now_ms: u64, lost_first_seq: u64, lost_records: u64) {
        let lost_class = class as u8;
        if let Some(last) = self.open[Class::P0.index()].gaps.last_mut()
            && last.reason == GapReason::BufferEvicted
            && last.lost_class == lost_class
            && last.lost_first_seq + last.lost_records == lost_first_seq
        {
            last.lost_records += lost_records;
            last.to_mono_ms = now_ms;
            return;
        }
        self.gap(
            Class::P0,
            Gap {
                reason: GapReason::BufferEvicted,
                lost_class,
                from_boot: self.boot_id,
                from_mono_ms: now_ms,
                to_mono_ms: now_ms,
                lost_first_seq,
                lost_records,
            },
        );
    }
}
