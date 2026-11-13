use alloc::vec;
use alloc::vec::Vec;

use sl_proto::block::chain_hash;
use sl_proto::ids::Class;

use crate::frame::{FORMAT_V1, FrameHeader, HEADER_LEN, MAGIC, MAX_PAYLOAD, body_crc, build_frame};
use crate::meta::Meta;
use crate::storage::{Storage, StorageError};

/// While frames remain in a class, its metadata is rewritten once per this many trims.
const PERSIST_EVERY: u32 = 64;

/// Bytes of capacity that only `append_declaration` may use, so that a loss can always be
/// declared before anything is destroyed, even when the store is full.
pub const DECLARATION_RESERVE: u64 = 512;

/// Sequence numbers that were in the log and no longer are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LostRange {
    pub class: Class,
    pub first_seq: u64,
    pub count: u64,
}

impl LostRange {
    /// One past the last lost sequence number.
    pub fn end_seq(&self) -> u64 {
        self.first_seq.saturating_add(self.count)
    }

    fn overlaps(&self, other: &LostRange) -> bool {
        self.class == other.class && self.first_seq < other.end_seq() && other.first_seq < self.end_seq()
    }
}

/// What `DurableLog::open` had to repair.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Bytes of torn write removed from the end of each class.
    pub truncated_bytes: [u64; 3],
    /// Sequence ranges lost to corruption: frames that rotted, wherever they are, and
    /// stretches of bytes that are no longer a frame. Rotted frames stay on disk until the
    /// loss is declared and the normal trim removes them.
    pub corrupt: Vec<LostRange>,
}

/// Where a frame sits and what it covers, from its header alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameRef {
    pub offset: u64,
    pub next_offset: u64,
    pub first_seq: u64,
    pub count: u32,
    pub compression: u8,
}

impl FrameRef {
    /// One past the last sequence number the frame covers.
    pub fn end_seq(&self) -> u64 {
        self.first_seq.saturating_add(u64::from(self.count))
    }
}

/// How the server's record of a class compares with this log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lineage {
    /// The log holds the frame ending at the server's mark and the chains agree.
    Matches,
    /// Nothing at or below the server's mark is held any more, so nothing can be said.
    Unknown,
    /// The server holds something this log did not send.
    Diverged,
}

/// One frame read from the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub class: Class,
    pub offset: u64,
    pub header: FrameHeader,
    pub payload: Vec<u8>,
    pub next_offset: u64,
}

impl Outgoing {
    /// One past the last sequence number the frame covers.
    pub fn end_seq(&self) -> u64 {
        self.header.end_seq()
    }
}

/// Where a frame sits, from its header alone.
#[derive(Clone, Copy)]
struct Found {
    offset: u64,
    header: FrameHeader,
    next_offset: u64,
}

impl Found {
    fn lost(&self, class: Class) -> LostRange {
        LostRange {
            class,
            first_seq: self.header.first_seq,
            count: u64::from(self.header.count),
        }
    }

    fn frame_ref(&self) -> FrameRef {
        FrameRef {
            offset: self.offset,
            next_offset: self.next_offset,
            first_seq: self.header.first_seq,
            count: self.header.count,
            compression: self.header.compression,
        }
    }
}

/// The frame whose header starts exactly at `offset`, if those bytes are a valid header
/// and the frame it describes lies inside the log. The payload is not read.
fn header_at<S: Storage>(storage: &S, class: Class, offset: u64) -> Result<Option<Found>, StorageError> {
    let end = storage.end(class);
    if offset + HEADER_LEN as u64 > end {
        return Ok(None);
    }
    let mut raw = [0u8; HEADER_LEN];
    storage.read(class, offset, &mut raw)?;
    Ok(FrameHeader::parse(&raw).and_then(|header| placed(header, offset, end)))
}

/// A parsed header at `offset`, if the frame it describes lies inside the log.
fn placed(header: FrameHeader, offset: u64, end: u64) -> Option<Found> {
    let next_offset = offset + HEADER_LEN as u64 + u64::from(header.ext_len) + u64::from(header.len);
    if header.len as usize > MAX_PAYLOAD || next_offset > end {
        return None;
    }
    Some(Found {
        offset,
        header,
        next_offset,
    })
}

/// The header at `offset` with one bit of rot undone, if exactly that makes it a header whose
/// frame lies inside the log and continues the sequence from `floor`.
///
/// A torn append cannot look like this: it writes a prefix of its frame, and any prefix
/// holding the whole header holds it intact. So a header that one flipped bit away from
/// sound is a frame that was written whole and then rotted.
fn repaired_header_at<S: Storage>(
    storage: &S,
    class: Class,
    offset: u64,
    floor: u64,
) -> Result<Option<Found>, StorageError> {
    let end = storage.end(class);
    if offset + HEADER_LEN as u64 > end {
        return Ok(None);
    }
    let mut raw = [0u8; HEADER_LEN];
    storage.read(class, offset, &mut raw)?;
    for bit in 0..HEADER_LEN * 8 {
        raw[bit / 8] ^= 1 << (bit % 8);
        let found = FrameHeader::parse(&raw).and_then(|header| placed(header, offset, end));
        raw[bit / 8] ^= 1 << (bit % 8);
        if let Some(found) = found
            && found.header.first_seq >= floor
        {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// The payload of a frame, or `None` when it does not match the header's checksum.
fn payload_of<S: Storage>(storage: &S, class: Class, found: &Found) -> Result<Option<Vec<u8>>, StorageError> {
    let ext_len = usize::from(found.header.ext_len);
    let mut body = vec![0u8; ext_len + found.header.len as usize];
    storage.read(class, found.offset + HEADER_LEN as u64, &mut body)?;
    let (ext, payload) = body.split_at(ext_len);
    if body_crc(ext, payload) != found.header.body_crc {
        return Ok(None);
    }
    body.drain(..ext_len);
    Ok(Some(body))
}

/// Walks the frames of one class from an offset. Bytes that are not a frame are skipped,
/// and so is any frame whose sequence numbers lie below those already passed: sequences
/// only ever grow along the log, so such a frame is a leftover, not data.
///
/// What it steps past is recorded in `lost`: a frame whose payload fails its checksum, and
/// the sequence numbers hidden by bytes that are no longer a frame. A jump in sequence with
/// nothing skipped is not recorded: only `DurableLog::skip` makes one, and it is declared.
struct Scan<'a, S: Storage> {
    storage: &'a S,
    class: Class,
    offset: u64,
    /// One past the highest sequence passed so far.
    floor: u64,
    /// Where a loss before the first frame found is taken to start: below it, the server
    /// holds the data already.
    reference: u64,
    /// Whether any frame has been found yet.
    passed: bool,
    /// Whether bytes were skipped since the last frame found, and from where.
    skipped: bool,
    skipped_from: u64,
    lost: Vec<LostRange>,
}

impl<'a, S: Storage> Scan<'a, S> {
    fn new(storage: &'a S, class: Class, from: u64, floor: u64) -> Self {
        Self {
            storage,
            class,
            offset: from.max(storage.start(class)),
            floor,
            reference: floor,
            passed: false,
            skipped: false,
            skipped_from: 0,
            lost: Vec::new(),
        }
    }

    /// Losses before the first frame found are reported from `reference` at the earliest.
    fn reporting_from(mut self, reference: u64) -> Self {
        self.reference = self.reference.max(reference);
        self
    }

    /// The next frame by header alone. Cheap: the payload is neither read nor checked.
    fn next_header(&mut self) -> Result<Option<Found>, StorageError> {
        let end = self.storage.end(self.class);
        let mut chunk = [0u8; 256];
        while self.offset < end {
            if let Some(found) = header_at(self.storage, self.class, self.offset)?
                && found.header.first_seq >= self.floor
            {
                let from = if self.passed { self.floor } else { self.reference };
                if self.skipped && found.header.first_seq > from {
                    self.lost.push(LostRange {
                        class: self.class,
                        first_seq: from,
                        count: found.header.first_seq - from,
                    });
                }
                self.passed = true;
                self.skipped = false;
                self.offset = found.next_offset;
                self.floor = found.header.end_seq();
                return Ok(Some(found));
            }
            if !self.skipped {
                self.skipped = true;
                self.skipped_from = self.offset;
            }
            self.offset += 1;
            while self.offset < end {
                let n = ((end - self.offset) as usize).min(chunk.len());
                self.storage.read(self.class, self.offset, &mut chunk[..n])?;
                match chunk[..n].iter().position(|b| *b == MAGIC) {
                    Some(i) => {
                        self.offset += i as u64;
                        break;
                    }
                    None => self.offset += n as u64,
                }
            }
        }
        Ok(None)
    }

    /// The next frame whose payload is intact.
    fn next_frame(&mut self) -> Result<Option<Outgoing>, StorageError> {
        loop {
            let Some(found) = self.next_header()? else {
                return Ok(None);
            };
            if let Some(payload) = payload_of(self.storage, self.class, &found)? {
                return Ok(Some(Outgoing {
                    class: self.class,
                    offset: found.offset,
                    header: found.header,
                    payload,
                    next_offset: found.next_offset,
                }));
            }
            // A sound header over a damaged payload. The header has its own checksum, so its
            // lengths hold: the frame is lost, and the next one starts where it ends.
            self.lost.push(found.lost(self.class));
        }
    }
}

/// The device's queue of sealed blocks: append at the back, upload from a cursor, trim the
/// front once the server says the data is backed up.
pub struct DurableLog<S: Storage> {
    storage: S,
    meta: Meta,
    next_seq: [u64; 3],
    /// Chain value of the newest frame of each class.
    chain: [[u8; 16]; 3],
    send_offset: [u64; 3],
    /// One past the highest sequence before `send_offset`, per class.
    send_floor: [u64; 3],
    /// Trims since the metadata was last written.
    unsaved_trims: u32,
    /// Losses found by reading, and whether a durable gap declares them yet. Kept in RAM:
    /// after a restart the rot is still on disk and `open` finds it again.
    rot: Vec<(LostRange, bool)>,
    /// One past the highest sequence trimmed from the front of each class, as far as this
    /// boot knows: the backup mark the metadata held at open, then each trim.
    front_seq: [u64; 3],
}

impl<S: Storage> DurableLog<S> {
    /// Scan the storage, remove a torn tail, and report anything lost to corruption.
    pub fn open(mut storage: S) -> Result<(Self, Recovery), StorageError> {
        let meta = Meta::load(&storage)?;
        let mut recovery = Recovery::default();
        let mut next_seq = meta.next_seq;
        let mut chain = meta.chain;

        for class in Class::ALL {
            let i = class.index();
            let start = storage.start(class);
            let mut valid_end = start;
            let mut newest: Option<(u64, [u8; 16])> = None;
            // Before the first frame the only reference is the backup mark: frames wholly
            // below it are trimmed, so bytes skipped at the very start were above it.
            let mut scan = Scan::new(&storage, class, start, 0).reporting_from(meta.backed_up_next[i]);
            while let Some(found) = scan.next_header()? {
                // A whole frame whose payload rotted is kept, and declared lost.
                if payload_of(&storage, class, &found)?.is_none() {
                    scan.lost.push(found.lost(class));
                }
                newest = Some((found.header.end_seq(), found.header.chain));
                valid_end = found.next_offset;
            }
            recovery.corrupt.append(&mut scan.lost);
            // After the last sound frame: a frame whose header rotted, or a torn write.
            let floor = newest.map_or(meta.backed_up_next[i], |(seq, _)| seq);
            if let Some(found) = repaired_header_at(&storage, class, valid_end, floor)? {
                recovery.corrupt.push(found.lost(class));
                newest = Some((found.header.end_seq(), found.header.chain));
                valid_end = found.next_offset;
            }
            let end = storage.end(class);
            if valid_end < end {
                recovery.truncated_bytes[i] = end - valid_end;
                storage.truncate(class, valid_end)?;
            }
            // The metadata's sequence and chain were written together. When it is ahead of
            // the newest frame still readable, that frame is not the newest ever written,
            // and its chain value is not the one the next frame continues from.
            if let Some((seq, frame_chain)) = newest
                && seq >= next_seq[i]
            {
                next_seq[i] = seq;
                chain[i] = frame_chain;
            }
        }

        let send_offset = Class::ALL.map(|class| storage.start(class));
        let front_seq = meta.backed_up_next;
        Ok((
            Self {
                storage,
                meta,
                next_seq,
                chain,
                send_offset,
                send_floor: [0; 3],
                unsaved_trims: 0,
                rot: recovery.corrupt.iter().map(|lost| (*lost, false)).collect(),
                front_seq,
            },
            recovery,
        ))
    }

    /// Append one sealed block and return its first sequence number. Returns `Full` when
    /// the frame would cut into the declaration reserve.
    pub fn append(
        &mut self,
        class: Class,
        compression: u8,
        hash: [u8; 16],
        count: u32,
        payload: &[u8],
    ) -> Result<u64, StorageError> {
        let frame_len = (HEADER_LEN + payload.len()) as u64;
        if payload.len() <= MAX_PAYLOAD && self.used() + frame_len + DECLARATION_RESERVE > self.storage.capacity() {
            return Err(StorageError::Full);
        }
        self.append_frame(class, compression, hash, count, payload)
    }

    /// Append a block that declares losses, into P0. It may use the declaration reserve.
    pub fn append_declaration(
        &mut self,
        compression: u8,
        hash: [u8; 16],
        count: u32,
        payload: &[u8],
    ) -> Result<u64, StorageError> {
        self.append_frame(Class::P0, compression, hash, count, payload)
    }

    /// Bytes held across the three classes.
    pub fn used(&self) -> u64 {
        Class::ALL
            .iter()
            .map(|&class| self.storage.end(class) - self.storage.start(class))
            .sum()
    }

    fn append_frame(
        &mut self,
        class: Class,
        compression: u8,
        hash: [u8; 16],
        count: u32,
        payload: &[u8],
    ) -> Result<u64, StorageError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(StorageError::TooLarge);
        }
        let i = class.index();
        let first_seq = self.next_seq[i];
        let end_seq = first_seq.checked_add(u64::from(count)).ok_or(StorageError::Io)?;
        let chain = chain_hash(&self.chain[i], first_seq, count, &hash);
        let frame = build_frame(FORMAT_V1, compression, first_seq, count, hash, chain, payload);
        self.storage.append(class, &frame)?;
        self.next_seq[i] = end_seq;
        self.chain[i] = chain;
        Ok(first_seq)
    }

    /// Use up `count` sequence numbers without storing anything, for a block that had to
    /// be dropped. Returns the first skipped number. They are never handed out again, even
    /// when writing the metadata fails.
    pub fn skip(&mut self, class: Class, count: u32) -> Result<u64, StorageError> {
        let i = class.index();
        let first_seq = self.next_seq[i];
        self.next_seq[i] = first_seq.saturating_add(u64::from(count));
        self.persist()?;
        Ok(first_seq)
    }

    /// Compare the server's position and chain for a class with what this log holds.
    pub fn lineage(&self, class: Class, committed_next: u64, chain: &[u8; 16]) -> Result<Lineage, StorageError> {
        let i = class.index();
        if committed_next > self.next_seq[i] {
            return Ok(Lineage::Diverged);
        }
        let verdict = |ours: &[u8; 16]| {
            if ours == chain {
                Lineage::Matches
            } else {
                Lineage::Diverged
            }
        };
        let mut scan = Scan::new(&self.storage, class, self.storage.start(class), 0);
        let mut holds_older = false;
        while let Some(frame) = scan.next_header()? {
            if frame.header.end_seq() == committed_next {
                return Ok(verdict(&frame.header.chain));
            }
            if frame.header.end_seq() > committed_next {
                // The mark falls inside a held frame, or in a hole between held frames. A
                // server only ever commits whole frames this log sent, in order, so neither
                // can be this log's history unless nothing older is held to say otherwise.
                let inside = frame.header.first_seq < committed_next;
                return Ok(if inside || holds_older {
                    Lineage::Diverged
                } else {
                    Lineage::Unknown
                });
            }
            holds_older = true;
        }
        // Past every held frame. A mark at the very end of the log points at the newest
        // frame ever written, whose chain value is still known.
        if committed_next == self.next_seq[i] {
            return Ok(verdict(&self.chain[i]));
        }
        Ok(if holds_older {
            Lineage::Diverged
        } else {
            Lineage::Unknown
        })
    }

    /// The next frame to upload, without moving the cursor. Frames it has to step past,
    /// because they rotted, are noted as undeclared losses: `ack` keeps them until
    /// `release` says a durable gap declares them.
    pub fn peek_unsent(&mut self, class: Class) -> Result<Option<Outgoing>, StorageError> {
        let i = class.index();
        let mut scan = Scan::new(&self.storage, class, self.send_offset[i], self.send_floor[i])
            .reporting_from(self.meta.backed_up_next[i]);
        let frame = scan.next_frame()?;
        // Bytes after the last frame are, at run time, a frame whose header rotted: a torn
        // write leaves the storage dead, and `open` removes it.
        if frame.is_none()
            && scan.skipped
            && let Some(found) = repaired_header_at(&self.storage, class, scan.skipped_from, scan.floor)?
        {
            scan.lost.push(found.lost(class));
        }
        for lost in scan.lost {
            if !self.rot.iter().any(|(known, _)| known.overlaps(&lost)) {
                self.rot.push((lost, false));
            }
        }
        Ok(frame)
    }

    /// Losses found by reading that no durable gap declares yet, oldest first per class.
    pub fn undeclared(&self) -> Vec<LostRange> {
        self.rot
            .iter()
            .filter(|(_, declared)| !declared)
            .map(|(lost, _)| *lost)
            .collect()
    }

    /// Say that a durable gap now declares `lost`, so `ack` may trim past it.
    pub fn release(&mut self, lost: LostRange) {
        for (known, declared) in &mut self.rot {
            if *known == lost {
                *declared = true;
            }
        }
    }

    /// Move the upload cursor past a frame returned by `peek_unsent`.
    pub fn mark_sent(&mut self, frame: &Outgoing) {
        let i = frame.class.index();
        self.send_offset[i] = frame.next_offset;
        self.send_floor[i] = frame.end_seq();
    }

    /// Record the server's marks and trim every frame wholly below `backed_up_next`.
    ///
    /// The marks are bounded by what this log has written (`backed_up_next` ≤
    /// `committed_next` ≤ next sequence), so no claim by a server can reach records that
    /// do not exist yet. The caller checks them against what was actually sent.
    pub fn ack(&mut self, class: Class, committed_next: u64, backed_up_next: u64) -> Result<(), StorageError> {
        let i = class.index();
        let committed_next = committed_next.min(self.next_seq[i]);
        let backed_up_next = backed_up_next.min(committed_next);
        self.meta.committed_next[i] = committed_next;
        self.meta.backed_up_next[i] = self.meta.backed_up_next[i].max(backed_up_next);
        // Nothing from an undeclared loss onwards goes until a durable gap declares it.
        let undeclared = self
            .rot
            .iter()
            .filter(|(lost, declared)| lost.class == class && !declared)
            .map(|(lost, _)| lost.first_seq)
            .min();
        let limit = undeclared.map_or(self.meta.backed_up_next[i], |seq| seq.min(self.meta.backed_up_next[i]));

        // Bytes after the last frame are kept: at run time they can only be a frame whose
        // header rotted, and nothing declares it yet.
        let mut scan = Scan::new(&self.storage, class, self.storage.start(class), 0);
        let mut floor = 0;
        // Bytes between the last frame trimmed and the next are kept as well: they are a
        // frame that rotted, and the upload scan has to pass them to declare it.
        let mut keep_from = self.storage.start(class);
        while let Some(frame) = scan.next_header()? {
            if frame.header.end_seq() > limit {
                break;
            }
            floor = frame.header.end_seq();
            keep_from = frame.next_offset;
        }
        self.trim(class, keep_from, floor)
    }

    /// Point the upload cursor at the frame that contains `from_seq`, or the first one after.
    pub fn rewind(&mut self, class: Class, from_seq: u64) -> Result<(), StorageError> {
        let i = class.index();
        // The cursor stops at the end of the last frame passed, not at the next header, so
        // that the upload scan still steps over, and reports, whatever rotted in between.
        let mut scan = Scan::new(&self.storage, class, self.storage.start(class), 0);
        let mut floor = 0;
        let mut offset = self.storage.start(class);
        while let Some(frame) = scan.next_header()? {
            if frame.header.end_seq() > from_seq {
                break;
            }
            floor = frame.header.end_seq();
            offset = frame.next_offset;
        }
        self.send_offset[i] = offset;
        self.send_floor[i] = floor;
        Ok(())
    }

    /// Adopt an epoch issued by the server: forget the old marks and upload everything
    /// still held again.
    pub fn set_epoch(&mut self, epoch: [u8; 16]) -> Result<(), StorageError> {
        self.meta.epoch = Some(epoch);
        self.meta.committed_next = [0; 3];
        self.meta.backed_up_next = [0; 3];
        self.send_offset = Class::ALL.map(|class| self.storage.start(class));
        self.send_floor = [0; 3];
        self.persist()
    }

    /// The oldest frames of a class, by header, until together with the bytes before them
    /// they span at least `bytes`, or the class runs out. Nothing is removed.
    pub fn front_frames(&self, class: Class, bytes: u64) -> Result<Vec<FrameRef>, StorageError> {
        let start = self.storage.start(class);
        let mut scan = Scan::new(&self.storage, class, start, 0);
        let mut frames = Vec::new();
        while let Some(found) = scan.next_header()? {
            frames.push(found.frame_ref());
            if found.next_offset - start >= bytes {
                break;
            }
        }
        Ok(frames)
    }

    /// Where the records of a class begin, as far as is known: at most the first sequence of
    /// its oldest frame. A frame before that one whose header rotted lies in between.
    pub fn front_seq(&self, class: Class) -> u64 {
        self.front_seq[class.index()]
    }

    /// The payload of a frame found by `front_frames`, or `None` if it fails its checksum.
    pub fn read_payload(&self, class: Class, frame: &FrameRef) -> Result<Option<Vec<u8>>, StorageError> {
        match header_at(&self.storage, class, frame.offset)? {
            Some(found) if found.next_offset == frame.next_offset => payload_of(&self.storage, class, &found),
            _ => Ok(None),
        }
    }

    /// Remove every byte of a class before `next_offset`, the end of a frame returned by
    /// `front_frames`, and say which sequence numbers went. The caller has declared them.
    pub fn evict_through(&mut self, class: Class, next_offset: u64) -> Result<LostRange, StorageError> {
        let start = self.storage.start(class);
        let mut scan = Scan::new(&self.storage, class, start, 0);
        let mut first = None;
        let mut floor = 0;
        while let Some(found) = scan.next_header()? {
            if found.next_offset > next_offset {
                break;
            }
            first.get_or_insert(found.header.first_seq);
            floor = found.header.end_seq();
        }
        let first_seq = first.unwrap_or(floor);
        self.trim(class, next_offset, floor)?;
        Ok(LostRange {
            class,
            first_seq,
            count: floor - first_seq,
        })
    }

    /// Every intact frame held for a class, oldest first. For tests and diagnostics.
    pub fn read_all(&self, class: Class) -> Result<Vec<Outgoing>, StorageError> {
        let mut frames = Vec::new();
        let mut scan = Scan::new(&self.storage, class, self.storage.start(class), 0);
        while let Some(frame) = scan.next_frame()? {
            frames.push(frame);
        }
        Ok(frames)
    }

    /// Sequence of the oldest record held, or the next sequence when the class is empty.
    pub fn first_retained_seq(&self, class: Class) -> Result<u64, StorageError> {
        let first = Scan::new(&self.storage, class, self.storage.start(class), 0).next_header()?;
        Ok(first.map_or(self.next_seq[class.index()], |frame| frame.header.first_seq))
    }

    pub fn epoch(&self) -> Option<[u8; 16]> {
        self.meta.epoch
    }

    pub fn next_seq(&self, class: Class) -> u64 {
        self.next_seq[class.index()]
    }

    pub fn committed_next(&self, class: Class) -> u64 {
        self.meta.committed_next[class.index()]
    }

    pub fn backed_up_next(&self, class: Class) -> u64 {
        self.meta.backed_up_next[class.index()]
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    pub fn into_storage(self) -> S {
        self.storage
    }

    /// Called before the front of a class is trimmed. While a frame remains, the sequence
    /// and chain to continue from can be read back from it, and the marks come again with
    /// the next Welcome, so the metadata is written only now and then: storage wears with
    /// every write. Once the class is empty only the metadata remembers them, and it is
    /// written at once.
    fn persist_for_trim(&mut self, emptied: bool) -> Result<(), StorageError> {
        if emptied || self.unsaved_trims >= PERSIST_EVERY {
            return self.persist();
        }
        self.unsaved_trims += 1;
        Ok(())
    }

    /// Remove every byte of a class before `keep_from`. `floor` is one past the highest
    /// sequence removed.
    fn trim(&mut self, class: Class, keep_from: u64, floor: u64) -> Result<(), StorageError> {
        let i = class.index();
        if keep_from <= self.storage.start(class) {
            return Ok(());
        }
        self.persist_for_trim(keep_from >= self.storage.end(class))?;
        self.storage.trim_front(class, keep_from)?;
        if self.send_offset[i] < keep_from {
            self.send_offset[i] = keep_from;
            self.send_floor[i] = self.send_floor[i].max(floor);
        }
        self.front_seq[i] = self.front_seq[i].max(floor);
        // A loss wholly removed is no longer anything to declare or to wait for.
        self.rot
            .retain(|(lost, _)| lost.class != class || lost.end_seq() > floor);
        Ok(())
    }

    fn persist(&mut self) -> Result<(), StorageError> {
        self.unsaved_trims = 0;
        self.meta.next_seq = self.next_seq;
        self.meta.chain = self.chain;
        self.meta.store(&mut self.storage)
    }
}
