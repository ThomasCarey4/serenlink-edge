use alloc::vec::Vec;

use crate::error::DecodeError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Compression {
    None = 0,
    /// zstd level 1. The level adds little; the columnar layout does the work.
    Zstd = 1,
}

impl Compression {
    pub fn from_u8(v: u8) -> Option<Compression> {
        match v {
            0 => Some(Compression::None),
            1 => Some(Compression::Zstd),
            _ => None,
        }
    }
}

pub fn compress(compression: Compression, data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    match compression {
        Compression::None => Ok(data.to_vec()),
        Compression::Zstd => zstd_compress(data),
    }
}

/// Decompress, refusing to produce more than `max_len` bytes.
pub fn decompress(compression: Compression, data: &[u8], max_len: usize) -> Result<Vec<u8>, DecodeError> {
    match compression {
        Compression::None if data.len() > max_len => Err(DecodeError::BadLength),
        Compression::None => Ok(data.to_vec()),
        Compression::Zstd => zstd_decompress(data, max_len),
    }
}

#[cfg(feature = "zstd")]
fn zstd_compress(data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    zstd::bulk::compress(data, 1).map_err(|_| DecodeError::Unsupported)
}

#[cfg(feature = "zstd")]
fn zstd_decompress(data: &[u8], max_len: usize) -> Result<Vec<u8>, DecodeError> {
    zstd::bulk::decompress(data, max_len).map_err(|_| DecodeError::BadLength)
}

#[cfg(not(feature = "zstd"))]
fn zstd_compress(_data: &[u8]) -> Result<Vec<u8>, DecodeError> {
    Err(DecodeError::Unsupported)
}

#[cfg(not(feature = "zstd"))]
fn zstd_decompress(_data: &[u8], _max_len: usize) -> Result<Vec<u8>, DecodeError> {
    Err(DecodeError::Unsupported)
}
