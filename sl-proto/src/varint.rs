use alloc::vec::Vec;

use crate::error::DecodeError;

/// Append `v` as an unsigned LEB128 varint.
pub fn put_u64(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Read an unsigned LEB128 varint at `*pos`, advancing `*pos`.
pub fn get_u64(buf: &[u8], pos: &mut usize) -> Result<u64, DecodeError> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos).ok_or(DecodeError::Truncated)?;
        *pos += 1;
        // The tenth byte holds only the top bit of a u64.
        if shift >= 64 || (shift == 63 && b & 0x7e != 0) {
            return Err(DecodeError::Overflow);
        }
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(v);
        }
        shift += 7;
    }
}

/// Append `v` zigzag-encoded, so small magnitudes of either sign stay short.
pub fn put_i64(out: &mut Vec<u8>, v: i64) {
    put_u64(out, ((v << 1) ^ (v >> 63)) as u64);
}

pub fn get_i64(buf: &[u8], pos: &mut usize) -> Result<i64, DecodeError> {
    let u = get_u64(buf, pos)?;
    Ok(((u >> 1) as i64) ^ -((u & 1) as i64))
}
