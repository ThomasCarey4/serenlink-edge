use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::vec;
use alloc::vec::Vec;

use sl_proto::block::{Block, MAX_BLOCK_BYTES, block_hash};
use sl_proto::compress::{Compression, compress, decompress};
use sl_proto::ids::Class;
use sl_proto::record::{Define, Gap, GapReason, TimeAnchor};
use sl_proto::value::Value;

use crate::frame::HEADER_LEN;
use crate::log::{DECLARATION_RESERVE, DurableLog, FrameRef, LostRange, Recovery};
use crate::storage::{Storage, StorageError};

/// Most gaps a declaration block holds before each class collapses to one.
pub const MAX_DECLARED_GAPS: usize = 8;

/// Largest frame a declaration can make: a header, the block's fixed fields, and
/// `MAX_DECLARED_GAPS` gaps of at most 47 bytes each.
pub const DECLARATION_MAX: u64 = (HEADER_LEN + 16 + MAX_DECLARED_GAPS * 47) as u64;

// Collapsing leaves at most one gap per class, so `MAX_DECLARED_GAPS` bounds every
// declaration, and the reserve holds the largest.
const _: () = assert!(MAX_DECLARED_GAPS >= 3 && DECLARATION_MAX <= DECLARATION_RESERVE);

/// Frames to evict, oldest first, per victim class.
type EvictionPlan = Vec<(Class, Vec<FrameRef>)>;

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
    /// Gaps whose declaration could not be written, as when a flash write failed. They go
    /// out with the next declaration.
    owed: Vec<Gap>,
    /// Every loss declared since this boot, merged and bounded like a declaration. When a P0
    /// frame rots, the gaps it carried cannot be read, so these are declared again.
    declared: Vec<Gap>,
}

impl Recorder {
    pub fn new(cfg: RecorderConfig, boot_id: u32) -> Self {
        let block = || Block::new(boot_id, cfg.table_version);
        Self {
            open: [block(), block(), block()],
            opened_at: [None; 3],
            approx_bytes: [0; 3],
            defined: [BTreeMap::new(), BTreeMap::new(), BTreeMap::new()],
            owed: Vec::new(),
            declared: Vec::new(),
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

    /// Declare what `DurableLog::open` found missing, so that the server learns of records
    /// lost to corruption. Call once after opening the log, before the first `tick`. If it
    /// fails, the log still holds the losses as undeclared, and the next `tick` declares them.
    pub fn report_recovery<S: Storage>(
        &mut self,
        recovery: &Recovery,
        now_ms: u64,
        log: &mut DurableLog<S>,
        sealed: &mut Vec<Sealed>,
    ) -> Result<(), StorageError> {
        self.declare_corrupt(&recovery.corrupt, now_ms, log, sealed)
    }

    /// Seal every block that has been open for its interval or has grown large.
    pub fn tick<S: Storage>(
        &mut self,
        now_ms: u64,
        log: &mut DurableLog<S>,
        sealed: &mut Vec<Sealed>,
    ) -> Result<(), StorageError> {
        self.declare_undeclared(now_ms, log, sealed)?;
        for class in Class::ALL {
            let i = class.index();
            let due = self.opened_at[i].is_some_and(|opened| {
                now_ms.saturating_sub(opened) >= self.cfg.seal_ms[i] || self.approx_bytes[i] >= self.cfg.max_block_bytes
            });
            if due {
                self.seal(class, now_ms, log, sealed)?;
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
        self.declare_undeclared(now_ms, log, sealed)?;
        for class in Class::ALL {
            self.seal(class, now_ms, log, sealed)?;
        }
        Ok(())
    }

    /// Declare the losses the log found by reading, and any declaration still owed, then let
    /// the log trim past them.
    fn declare_undeclared<S: Storage>(
        &mut self,
        now_ms: u64,
        log: &mut DurableLog<S>,
        sealed: &mut Vec<Sealed>,
    ) -> Result<(), StorageError> {
        let pending = log.undeclared();
        self.declare_corrupt(&pending, now_ms, log, sealed)
    }

    fn declare_corrupt<S: Storage>(
        &mut self,
        lost: &[LostRange],
        now_ms: u64,
        log: &mut DurableLog<S>,
        sealed: &mut Vec<Sealed>,
    ) -> Result<(), StorageError> {
        let mut gaps: Vec<Gap> = lost
            .iter()
            .map(|lost| self.loss(GapReason::Corrupt, lost.class, now_ms, lost.first_seq, lost.count))
            .collect();
        // A rotted P0 frame may have been a declaration: declare again what this boot has.
        if lost.iter().any(|lost| lost.class == Class::P0) {
            gaps.extend(self.declared.iter().copied());
        }
        // Until a declaration is durable, the log keeps what it names.
        if let Some(declaration) = self.declare(gaps, log)? {
            sealed.push(declaration);
            for lost in lost {
                log.release(*lost);
            }
        }
        Ok(())
    }

    fn seal<S: Storage>(
        &mut self,
        class: Class,
        now_ms: u64,
        log: &mut DurableLog<S>,
        sealed: &mut Vec<Sealed>,
    ) -> Result<(), StorageError> {
        let i = class.index();
        if self.open[i].is_empty() {
            return Ok(());
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
        let usable = log.storage().capacity().saturating_sub(DECLARATION_RESERVE);
        let frame_len = (HEADER_LEN + payload.len()) as u64;
        let fits_at_all = raw_len <= MAX_BLOCK_BYTES && payload.len() <= MAX_BLOCK_BYTES && frame_len <= usable;
        if fits_at_all {
            loop {
                match log.append(class, compression as u8, hash, count, &payload) {
                    Ok(first_seq) => {
                        for def in &block.defines {
                            self.defined[i].insert(def.local_id, Some(first_seq));
                        }
                        sealed.push(Sealed {
                            class,
                            first_seq,
                            count,
                            hash,
                        });
                        return Ok(());
                    }
                    Err(StorageError::Full) => {
                        if !self.make_room(class, frame_len, now_ms, log, sealed)? {
                            break;
                        }
                    }
                    Err(StorageError::TooLarge) => break,
                    Err(e) => {
                        // The write failed part-way. The block is lost all the same, and
                        // has to be accounted for like any other dropped block.
                        let _ = self.drop_block(class, now_ms, &block, count, log, sealed);
                        return Err(e);
                    }
                }
            }
        }
        self.drop_block(class, now_ms, &block, count, log, sealed)
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
        sealed: &mut Vec<Sealed>,
    ) -> Result<(), StorageError> {
        let i = class.index();
        for def in &block.defines {
            self.defined[i].remove(&def.local_id);
        }
        // `skip` uses the numbers up even when writing the metadata fails, so the gap is
        // right either way; if it cannot be written now, it is owed.
        let first_seq = log.next_seq(class);
        let skipped = log.skip(class, count);
        let gap = self.loss(GapReason::BufferEvicted, class, now_ms, first_seq, u64::from(count));
        let declared = self.declare(vec![gap], log);
        skipped?;
        sealed.extend(declared?);
        Ok(())
    }

    /// Make room for a frame of `frame_len` bytes in `class` by evicting whole frames, lowest
    /// priority first, never from a class above `class`. The loss is declared in a durable
    /// block before anything is removed. Returns `false`, having removed nothing, when
    /// evicting everything eligible would still not be enough.
    fn make_room<S: Storage>(
        &mut self,
        class: Class,
        frame_len: u64,
        now_ms: u64,
        log: &mut DurableLog<S>,
        sealed: &mut Vec<Sealed>,
    ) -> Result<bool, StorageError> {
        // Room for the frame once the declaration, too, is written.
        let capacity = log.storage().capacity();
        let shortfall = (log.used() + frame_len + DECLARATION_RESERVE).saturating_sub(capacity);
        let mut target = shortfall.max(1);
        let (plan, declaration) = loop {
            let (plan, freed) = self.plan_eviction(class, target, log)?;
            if freed < target {
                return Ok(false);
            }
            let gaps = self.eviction_gaps(&plan, now_ms, log)?;
            let declaration = self.declaration(gaps);
            let need = shortfall
                + declaration
                    .as_ref()
                    .map_or(0, |(encoded, _)| (HEADER_LEN + encoded.len()) as u64);
            if freed >= need {
                break (plan, declaration);
            }
            // The declaration grew with the frames it names: plan for it and try again.
            target = need;
        };
        if let Some((encoded, count)) = declaration {
            match self.write_declaration(&encoded, count, log) {
                Ok(declared) => sealed.push(declared),
                // No room even for the declaration: nothing may be evicted undeclared.
                Err(StorageError::Full) => return Ok(false),
                Err(e) => return Err(e),
            }
        }
        for (victim, frames) in &plan {
            let lost = log.evict_through(*victim, frames[frames.len() - 1].next_offset)?;
            self.forget_definitions(lost);
        }
        Ok(true)
    }

    /// The oldest frames to evict, per class, until together they free `target` bytes or
    /// nothing eligible is left; and how many bytes they free.
    fn plan_eviction<S: Storage>(
        &self,
        class: Class,
        target: u64,
        log: &DurableLog<S>,
    ) -> Result<(EvictionPlan, u64), StorageError> {
        let mut plan = Vec::new();
        let mut freed = 0;
        for victim in Class::ALL.into_iter().rev() {
            if victim.index() < class.index() || freed >= target {
                break;
            }
            let start = log.storage().start(victim);
            let frames = log.front_frames(victim, target - freed)?;
            if let Some(last) = frames.last() {
                freed += last.next_offset - start;
                plan.push((victim, frames));
            }
        }
        Ok((plan, freed))
    }

    /// What evicting `plan` loses: each class's range, and the losses that evicted P0 frames
    /// declared, which would otherwise go with them.
    fn eviction_gaps<S: Storage>(
        &self,
        plan: &[(Class, Vec<FrameRef>)],
        now_ms: u64,
        log: &DurableLog<S>,
    ) -> Result<Vec<Gap>, StorageError> {
        let mut gaps = Vec::new();
        for (victim, frames) in plan {
            // From the front of the class, so a rotted frame before the first one found is
            // declared too.
            let first = log.front_seq(*victim).min(frames[0].first_seq);
            let end = frames[frames.len() - 1].end_seq();
            gaps.push(self.loss(GapReason::BufferEvicted, *victim, now_ms, first, end - first));
            if *victim != Class::P0 {
                continue;
            }
            for frame in frames {
                match carried_gaps(log, frame)? {
                    Some(carried) => gaps.extend(carried),
                    // Unreadable: whatever it declared is lost with it.
                    None => gaps.push(self.loss(
                        GapReason::Corrupt,
                        Class::P0,
                        now_ms,
                        frame.first_seq,
                        u64::from(frame.count),
                    )),
                }
            }
        }
        Ok(gaps)
    }

    /// Seal `gaps` into P0 as a block of their own, using the declaration reserve if it must,
    /// so that they are durable before the records they name are removed.
    /// Gaps still owed from an earlier failure go out with these. If the write fails, they
    /// are all owed; when it fails only for want of room, that is not an error, and `None`
    /// says nothing was declared.
    fn declare<S: Storage>(&mut self, gaps: Vec<Gap>, log: &mut DurableLog<S>) -> Result<Option<Sealed>, StorageError> {
        let mut gaps = merge_gaps(gaps);
        gaps.append(&mut self.owed);
        let Some((encoded, count)) = self.declaration(gaps.clone()) else {
            return Ok(None);
        };
        match self.write_declaration(&encoded, count, log) {
            Ok(sealed) => Ok(Some(sealed)),
            Err(e) => {
                self.owed = merge_gaps(gaps);
                if e == StorageError::Full { Ok(None) } else { Err(e) }
            }
        }
    }

    /// The encoded block that declares `gaps`, merged, and its record count; `None` if no gap
    /// names a lost record. Never compressed, so it never depends on a compressor.
    fn declaration(&self, gaps: Vec<Gap>) -> Option<(Vec<u8>, u32)> {
        let gaps = merge_gaps(gaps);
        if gaps.is_empty() {
            return None;
        }
        let mut block = Block::new(self.boot_id, self.cfg.table_version);
        block.gaps = gaps;
        let mut encoded = Vec::new();
        block.encode(&mut encoded);
        Some((encoded, block.record_count()))
    }

    fn write_declaration<S: Storage>(
        &mut self,
        encoded: &[u8],
        count: u32,
        log: &mut DurableLog<S>,
    ) -> Result<Sealed, StorageError> {
        let hash = block_hash(encoded);
        let first_seq = log.append_declaration(Compression::None as u8, hash, count, encoded)?;
        if let Ok(block) = Block::decode(encoded) {
            let mut declared = core::mem::take(&mut self.declared);
            declared.extend(block.gaps);
            self.declared = merge_gaps(declared);
        }
        Ok(Sealed {
            class: Class::P0,
            first_seq,
            count,
            hash,
        })
    }

    /// A gap naming `count` records of `class` from `first_seq`, lost now.
    fn loss(&self, reason: GapReason, class: Class, now_ms: u64, first_seq: u64, count: u64) -> Gap {
        Gap {
            reason,
            lost_class: class as u8,
            from_boot: self.boot_id,
            from_mono_ms: now_ms,
            to_mono_ms: now_ms,
            lost_first_seq: first_seq,
            lost_records: count,
        }
    }

    /// Definitions carried by an evicted block never reached the server: write them again.
    fn forget_definitions(&mut self, lost: LostRange) {
        let range = lost.first_seq..lost.first_seq.saturating_add(lost.count);
        self.defined[lost.class.index()].retain(|_, at| !at.is_some_and(|seq| range.contains(&seq)));
    }
}

/// The gaps naming lost records that a P0 frame carries, or `None` if it cannot be read.
fn carried_gaps<S: Storage>(log: &DurableLog<S>, frame: &FrameRef) -> Result<Option<Vec<Gap>>, StorageError> {
    let Some(payload) = log.read_payload(Class::P0, frame)? else {
        return Ok(None);
    };
    let block = Compression::from_u8(frame.compression)
        .and_then(|compression| decompress(compression, &payload, MAX_BLOCK_BYTES).ok())
        .and_then(|raw| Block::decode(&raw).ok());
    Ok(block.map(|block| block.gaps.into_iter().filter(|gap| gap.lost_records > 0).collect()))
}

/// Merge gaps of the same class and reason whose ranges touch or overlap. If more than
/// `MAX_DECLARED_GAPS` remain, each class collapses to one gap over everything it lost,
/// which may name records that were not lost: over-reporting is allowed, a missing gap is not.
fn merge_gaps(mut gaps: Vec<Gap>) -> Vec<Gap> {
    gaps.retain(|gap| gap.lost_records > 0);
    gaps.sort_by_key(|gap| (gap.lost_class, gap.reason as u8, gap.lost_first_seq));
    let mut merged: Vec<Gap> = Vec::new();
    for gap in gaps {
        if let Some(last) = merged.last_mut()
            && last.lost_class == gap.lost_class
            && last.reason == gap.reason
            && gap.lost_first_seq <= last.lost_first_seq.saturating_add(last.lost_records)
        {
            absorb(last, &gap);
            continue;
        }
        merged.push(gap);
    }
    if merged.len() <= MAX_DECLARED_GAPS {
        return merged;
    }
    let mut collapsed: Vec<Gap> = Vec::new();
    for gap in merged {
        match collapsed.iter_mut().find(|c| c.lost_class == gap.lost_class) {
            Some(c) => absorb(c, &gap),
            None => collapsed.push(Gap {
                reason: GapReason::BufferEvicted,
                ..gap
            }),
        }
    }
    collapsed
}

/// Widen `into` to cover `gap` as well.
fn absorb(into: &mut Gap, gap: &Gap) {
    let end = (into.lost_first_seq.saturating_add(into.lost_records))
        .max(gap.lost_first_seq.saturating_add(gap.lost_records));
    into.lost_first_seq = into.lost_first_seq.min(gap.lost_first_seq);
    into.lost_records = end - into.lost_first_seq;
    into.from_mono_ms = into.from_mono_ms.min(gap.from_mono_ms);
    into.to_mono_ms = into.to_mono_ms.max(gap.to_mono_ms);
}
