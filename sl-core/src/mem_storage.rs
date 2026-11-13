use alloc::vec::Vec;

use sl_proto::ids::Class;

use crate::storage::{Storage, StorageError};

/// In-memory `Storage` for tests and the simulator, with power-cut and corruption injection.
#[derive(Clone, Debug)]
pub struct MemStorage {
    data: [Vec<u8>; 3],
    start: [u64; 3],
    meta: [Option<Vec<u8>>; 2],
    capacity: u64,
    cut_after: Option<u64>,
    dead: bool,
}

impl MemStorage {
    /// `capacity` bounds the bytes held across the three logs; metadata is separate.
    pub fn new(capacity: u64) -> Self {
        Self {
            data: [Vec::new(), Vec::new(), Vec::new()],
            start: [0; 3],
            meta: [None, None],
            capacity,
            cut_after: None,
            dead: false,
        }
    }

    /// Lose power once `bytes` more bytes have been written. The write that crosses the
    /// limit is applied only up to it, and every write after that fails until `power_on`.
    pub fn cut_power_after(&mut self, bytes: u64) {
        self.cut_after = Some(bytes);
    }

    pub fn power_on(&mut self) {
        self.cut_after = None;
        self.dead = false;
    }

    pub fn is_dead(&self) -> bool {
        self.dead
    }

    /// Flip one bit of the byte at a logical offset.
    pub fn corrupt(&mut self, class: Class, offset: u64) {
        let i = class.index();
        let at = (offset - self.start[i]) as usize;
        self.data[i][at] ^= 0x40;
    }

    pub fn used(&self) -> u64 {
        self.data.iter().map(|d| d.len() as u64).sum()
    }

    /// How many of `want` bytes the pending power cut still allows.
    fn allowed(&mut self, want: usize) -> usize {
        match self.cut_after {
            None => want,
            Some(left) if left >= want as u64 => {
                self.cut_after = Some(left - want as u64);
                want
            }
            Some(left) => {
                self.cut_after = Some(0);
                self.dead = true;
                left as usize
            }
        }
    }
}

impl Storage for MemStorage {
    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn start(&self, class: Class) -> u64 {
        self.start[class.index()]
    }

    fn end(&self, class: Class) -> u64 {
        let i = class.index();
        self.start[i] + self.data[i].len() as u64
    }

    fn append(&mut self, class: Class, data: &[u8]) -> Result<(), StorageError> {
        if self.dead {
            return Err(StorageError::Io);
        }
        if self.used() + data.len() as u64 > self.capacity {
            return Err(StorageError::Full);
        }
        let n = self.allowed(data.len());
        self.data[class.index()].extend_from_slice(&data[..n]);
        if n < data.len() { Err(StorageError::Io) } else { Ok(()) }
    }

    fn read(&self, class: Class, offset: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        let i = class.index();
        if offset < self.start[i] || offset + buf.len() as u64 > self.end(class) {
            return Err(StorageError::Io);
        }
        let at = (offset - self.start[i]) as usize;
        buf.copy_from_slice(&self.data[i][at..at + buf.len()]);
        Ok(())
    }

    fn trim_front(&mut self, class: Class, new_start: u64) -> Result<(), StorageError> {
        if self.dead {
            return Err(StorageError::Io);
        }
        let i = class.index();
        let new_start = new_start.clamp(self.start[i], self.end(class));
        self.data[i].drain(..(new_start - self.start[i]) as usize);
        self.start[i] = new_start;
        Ok(())
    }

    fn truncate(&mut self, class: Class, new_end: u64) -> Result<(), StorageError> {
        if self.dead {
            return Err(StorageError::Io);
        }
        let i = class.index();
        let new_end = new_end.clamp(self.start[i], self.end(class));
        self.data[i].truncate((new_end - self.start[i]) as usize);
        Ok(())
    }

    fn read_meta(&self, slot: usize) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.meta[slot].clone())
    }

    fn write_meta(&mut self, slot: usize, data: &[u8]) -> Result<(), StorageError> {
        if self.dead {
            return Err(StorageError::Io);
        }
        let n = self.allowed(data.len());
        self.meta[slot] = Some(data[..n].to_vec());
        if n < data.len() { Err(StorageError::Io) } else { Ok(()) }
    }
}
