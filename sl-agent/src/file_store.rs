//! `Storage` over files (architecture spec 7.4: "Agent: files with fsync in a size-capped
//! directory"). Each class is a run of segment files named by the logical offset they start at;
//! the exact start of what is held is in a small `start` file per class. Every append is
//! `fdatasync`ed before it returns; a new segment, a trim and a meta write also sync the
//! directory. Meta slots are whole files replaced by rename.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use sl_core::storage::{META_SLOTS, Storage, StorageError};
use sl_proto::ids::Class;

pub const SEGMENT_BYTES: u64 = 8 * 1024 * 1024;

struct Lane {
    dir: PathBuf,
    start: u64,
    end: u64,
    /// Start offsets of the segment files, ascending; each runs to the next, the last to `end`.
    segments: Vec<u64>,
    tail: Option<File>,
}

pub struct FileStore {
    dir: PathBuf,
    capacity: u64,
    segment_bytes: u64,
    lanes: [Lane; 3],
}

fn seg_name(offset: u64) -> String {
    format!("{offset:020}.seg")
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Write `data` to `path` by a synced temporary file and a rename, then sync the directory.
fn replace(dir: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, dir.join(name))?;
    sync_dir(dir)
}

fn io_err(_: io::Error) -> StorageError {
    StorageError::Io
}

impl Lane {
    fn open(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        let mut segments = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|x| x == "seg") {
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                let offset = stem
                    .parse::<u64>()
                    .map_err(|_| io::Error::other(format!("{}: not a segment name", path.display())))?;
                segments.push(offset);
            }
        }
        segments.sort_unstable();
        let recorded = match fs::read(dir.join("start")) {
            Ok(b) if b.len() == 8 => Some(u64::from_le_bytes(b.try_into().unwrap())),
            Ok(_) => return Err(io::Error::other(format!("{}: start file damaged", dir.display()))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let mut end = recorded.unwrap_or(0);
        for (i, &off) in segments.iter().enumerate() {
            let len = fs::metadata(dir.join(seg_name(off)))?.len();
            if let Some(&next) = segments.get(i + 1)
                && off + len != next
            {
                return Err(io::Error::other(format!(
                    "{}: segments not contiguous at {off}",
                    dir.display()
                )));
            }
            end = off + len;
        }
        let first = segments.first().copied();
        let start = match (recorded, first) {
            (Some(r), _) => r,
            (None, Some(f)) => f,
            (None, None) => 0,
        };
        if first.is_some_and(|f| f > start) {
            return Err(io::Error::other(format!(
                "{}: the first segment starts after the start",
                dir.display()
            )));
        }
        let mut lane = Lane {
            dir,
            start: start.min(end),
            end,
            segments,
            tail: None,
        };
        // A crash between writing `start` and deleting segments leaves some wholly below it.
        lane.drop_below(lane.start)?;
        Ok(lane)
    }

    fn drop_below(&mut self, start: u64) -> io::Result<()> {
        while self.segments.len() > 1 && self.segments[1] <= start {
            let off = self.segments.remove(0);
            fs::remove_file(self.dir.join(seg_name(off)))?;
        }
        if self.segments.len() == 1 && self.end <= start && self.end > self.segments[0] {
            let off = self.segments.remove(0);
            self.tail = None;
            fs::remove_file(self.dir.join(seg_name(off)))?;
        }
        Ok(())
    }

    fn seg_len(&self, i: usize) -> u64 {
        self.segments.get(i + 1).copied().unwrap_or(self.end) - self.segments[i]
    }
}

impl FileStore {
    pub fn open(dir: &Path, capacity: u64) -> io::Result<Self> {
        Self::open_with_segment(dir, capacity, SEGMENT_BYTES)
    }

    pub fn open_with_segment(dir: &Path, capacity: u64, segment_bytes: u64) -> io::Result<Self> {
        fs::create_dir_all(dir.join("meta"))?;
        let lane = |c: &str| Lane::open(dir.join(c));
        Ok(Self {
            dir: dir.to_path_buf(),
            capacity,
            segment_bytes: segment_bytes.max(1),
            lanes: [lane("p0")?, lane("p1")?, lane("p2")?],
        })
    }

    fn used(&self) -> u64 {
        self.lanes.iter().map(|l| l.end - l.start).sum()
    }

    fn append_inner(&mut self, class: Class, data: &[u8]) -> io::Result<()> {
        let seg_bytes = self.segment_bytes;
        let lane = &mut self.lanes[class.index()];
        let mut rest = data;
        while !rest.is_empty() {
            let need_new = match lane.segments.last() {
                None => true,
                Some(&last) => lane.end - last >= seg_bytes || lane.end < last,
            };
            if need_new {
                let off = lane.end;
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(lane.dir.join(seg_name(off)))?;
                sync_dir(&lane.dir)?;
                lane.segments.push(off);
                lane.tail = Some(f);
            }
            if lane.tail.is_none() {
                let last = *lane.segments.last().unwrap();
                lane.tail = Some(OpenOptions::new().append(true).open(lane.dir.join(seg_name(last)))?);
            }
            let last = *lane.segments.last().unwrap();
            let room = (seg_bytes - (lane.end - last)) as usize;
            let n = room.min(rest.len());
            let f = lane.tail.as_mut().unwrap();
            if let Err(e) = f.write_all(&rest[..n]).and_then(|_| f.sync_data()) {
                // What reached the file is now the end; the log's checksums find the tear.
                if let Ok(m) = fs::metadata(lane.dir.join(seg_name(last))) {
                    lane.end = last + m.len();
                }
                lane.tail = None;
                return Err(e);
            }
            lane.end += n as u64;
            rest = &rest[n..];
        }
        Ok(())
    }
}

impl Storage for FileStore {
    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn start(&self, class: Class) -> u64 {
        self.lanes[class.index()].start
    }

    fn end(&self, class: Class) -> u64 {
        self.lanes[class.index()].end
    }

    fn append(&mut self, class: Class, data: &[u8]) -> Result<(), StorageError> {
        if self.used() + data.len() as u64 > self.capacity {
            return Err(StorageError::Full);
        }
        self.append_inner(class, data).map_err(io_err)
    }

    fn read(&self, class: Class, offset: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        let lane = &self.lanes[class.index()];
        let want_end = offset.checked_add(buf.len() as u64).ok_or(StorageError::Io)?;
        if offset < lane.start || want_end > lane.end {
            return Err(StorageError::Io);
        }
        let mut done = 0usize;
        while done < buf.len() {
            let at = offset + done as u64;
            let i = lane.segments.partition_point(|&s| s <= at) - 1;
            let seg = lane.segments[i];
            let n = ((lane.seg_len(i) - (at - seg)) as usize).min(buf.len() - done);
            let f = File::open(lane.dir.join(seg_name(seg))).map_err(io_err)?;
            f.read_exact_at(&mut buf[done..done + n], at - seg).map_err(io_err)?;
            done += n;
        }
        Ok(())
    }

    fn trim_front(&mut self, class: Class, new_start: u64) -> Result<(), StorageError> {
        let lane = &mut self.lanes[class.index()];
        let new_start = new_start.clamp(lane.start, lane.end);
        if new_start == lane.start {
            return Ok(());
        }
        replace(&lane.dir, "start", &new_start.to_le_bytes()).map_err(io_err)?;
        lane.start = new_start;
        lane.drop_below(new_start).map_err(io_err)?;
        sync_dir(&lane.dir).map_err(io_err)
    }

    fn truncate(&mut self, class: Class, new_end: u64) -> Result<(), StorageError> {
        let lane = &mut self.lanes[class.index()];
        let new_end = new_end.clamp(lane.start, lane.end);
        if new_end == lane.end {
            return Ok(());
        }
        lane.tail = None;
        while let Some(&last) = lane.segments.last() {
            if last >= new_end && lane.segments.len() > 1 {
                fs::remove_file(lane.dir.join(seg_name(last))).map_err(io_err)?;
                lane.segments.pop();
            } else {
                break;
            }
        }
        if let Some(&last) = lane.segments.last() {
            let f = OpenOptions::new()
                .write(true)
                .open(lane.dir.join(seg_name(last)))
                .map_err(io_err)?;
            f.set_len(new_end.saturating_sub(last)).map_err(io_err)?;
            f.sync_all().map_err(io_err)?;
        }
        sync_dir(&lane.dir).map_err(io_err)?;
        lane.end = new_end;
        Ok(())
    }

    fn read_meta(&self, slot: usize) -> Result<Option<Vec<u8>>, StorageError> {
        assert!(slot < META_SLOTS);
        match fs::read(self.dir.join("meta").join(slot.to_string())) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(StorageError::Io),
        }
    }

    fn write_meta(&mut self, slot: usize, data: &[u8]) -> Result<(), StorageError> {
        assert!(slot < META_SLOTS);
        replace(&self.dir.join("meta"), &slot.to_string(), data).map_err(io_err)
    }
}
