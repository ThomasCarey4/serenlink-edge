use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::error::DecodeError;
use crate::record::{AnchorSource, Define, Gap, GapReason, Kind, TimeAnchor};
use crate::value::{Value, ValueType};
use crate::varint::{get_i64, get_u64, put_i64, put_u64};

pub const BLOCK_VERSION: u8 = 1;
/// Largest encoded block, before and after compression. A device never seals a larger one
/// and a server never decodes one.
pub const MAX_BLOCK_BYTES: usize = 1 << 20;

/// Consecutive samples of one signal that share a value type.
#[derive(Clone, Debug, PartialEq)]
pub struct Column {
    local_id: u32,
    value_type: ValueType,
    samples: Vec<(u64, Value)>,
}

impl Column {
    pub fn local_id(&self) -> u32 {
        self.local_id
    }

    pub fn value_type(&self) -> ValueType {
        self.value_type
    }

    /// `(mono_ms, value)` pairs. Every value has type `value_type`: columns are built only
    /// by `Block::push_sample` and `Block::decode`, which keep that true.
    pub fn samples(&self) -> &[(u64, Value)] {
        &self.samples
    }
}

/// The unit that is sealed into the log, uploaded and acknowledged as a whole.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Block {
    pub boot_id: u32,
    pub table_version: u32,
    pub defines: Vec<Define>,
    pub anchors: Vec<TimeAnchor>,
    pub gaps: Vec<Gap>,
    pub columns: Vec<Column>,
}

impl Block {
    pub fn new(boot_id: u32, table_version: u32) -> Self {
        Self {
            boot_id,
            table_version,
            ..Self::default()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.record_count() == 0
    }

    /// Number of records, which is the number of sequence numbers the block covers.
    pub fn record_count(&self) -> u32 {
        let samples: usize = self.columns.iter().map(|c| c.samples.len()).sum();
        (self.defines.len() + self.anchors.len() + self.gaps.len() + samples) as u32
    }

    pub fn push_sample(&mut self, local_id: u32, mono_ms: u64, value: Value) {
        let value_type = value.value_type();
        let last = self.columns.iter().rposition(|c| c.local_id == local_id);
        match last {
            Some(i) if self.columns[i].value_type == value_type => {
                self.columns[i].samples.push((mono_ms, value));
            }
            _ => self.columns.push(Column {
                local_id,
                value_type,
                samples: vec![(mono_ms, value)],
            }),
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(BLOCK_VERSION);
        put_u64(out, u64::from(self.boot_id));
        put_u64(out, u64::from(self.table_version));

        put_u64(out, self.defines.len() as u64);
        for d in &self.defines {
            put_u64(out, u64::from(d.local_id));
            put_u64(out, d.stable_key);
            put_str(out, &d.path);
            put_u64(out, d.source);
            out.push(d.value_type as u8);
            put_str(out, &d.unit);
            out.push(d.kind as u8);
        }

        put_u64(out, self.anchors.len() as u64);
        for a in &self.anchors {
            put_u64(out, a.mono_ms);
            put_u64(out, a.utc_ms);
            out.push(a.source as u8);
            out.push(a.quality);
        }

        put_u64(out, self.gaps.len() as u64);
        for g in &self.gaps {
            out.push(g.reason as u8);
            out.push(g.lost_class);
            put_u64(out, u64::from(g.from_boot));
            put_u64(out, g.from_mono_ms);
            put_u64(out, g.to_mono_ms);
            put_u64(out, g.lost_first_seq);
            put_u64(out, g.lost_records);
        }

        put_u64(out, self.columns.len() as u64);
        for c in &self.columns {
            put_u64(out, u64::from(c.local_id));
            out.push(c.value_type as u8);
            put_u64(out, c.samples.len() as u64);
            let mut prev = 0u64;
            for (t, _) in &c.samples {
                put_i64(out, t.wrapping_sub(prev) as i64);
                prev = *t;
            }
            encode_values(out, c);
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Block, DecodeError> {
        let mut r = Reader { buf, pos: 0 };
        let version = r.u8()?;
        if version != BLOCK_VERSION {
            return Err(DecodeError::BadTag(version));
        }
        let mut block = Block::new(r.u32()?, r.u32()?);

        for _ in 0..r.count()? {
            let local_id = r.u32()?;
            let stable_key = r.u64()?;
            let path = r.string()?;
            let source = r.u64()?;
            let value_type = r.value_type()?;
            let unit = r.string()?;
            let kind = r.u8()?;
            let kind = Kind::from_u8(kind).ok_or(DecodeError::BadTag(kind))?;
            block.defines.push(Define {
                local_id,
                stable_key,
                path,
                source,
                value_type,
                unit,
                kind,
            });
        }

        for _ in 0..r.count()? {
            let mono_ms = r.u64()?;
            let utc_ms = r.u64()?;
            let source = r.u8()?;
            let source = AnchorSource::from_u8(source).ok_or(DecodeError::BadTag(source))?;
            let quality = r.u8()?;
            block.anchors.push(TimeAnchor {
                mono_ms,
                utc_ms,
                source,
                quality,
            });
        }

        for _ in 0..r.count()? {
            let reason = r.u8()?;
            let reason = GapReason::from_u8(reason).ok_or(DecodeError::BadTag(reason))?;
            block.gaps.push(Gap {
                reason,
                lost_class: r.u8()?,
                from_boot: r.u32()?,
                from_mono_ms: r.u64()?,
                to_mono_ms: r.u64()?,
                lost_first_seq: r.u64()?,
                lost_records: r.u64()?,
            });
        }

        for _ in 0..r.count()? {
            let local_id = r.u32()?;
            let value_type = r.value_type()?;
            let n = r.count()?;
            let mut times = Vec::with_capacity(n);
            let mut prev = 0u64;
            for _ in 0..n {
                prev = prev.wrapping_add(r.i64()? as u64);
                times.push(prev);
            }
            let values = decode_values(&mut r, value_type, n)?;
            let samples = times.into_iter().zip(values).collect();
            block.columns.push(Column {
                local_id,
                value_type,
                samples,
            });
        }

        if r.pos != buf.len() {
            return Err(DecodeError::Trailing);
        }
        Ok(block)
    }
}

/// First 16 bytes of SHA-256 over the encoded, uncompressed block.
pub fn block_hash(encoded: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(encoded);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&digest[..16]);
    hash
}

/// Extend a class's running hash by one frame. Two logs with the same chain value at a
/// sequence number hold the same frames up to it; the first frame chains from all zeros.
pub fn chain_hash(prev: &[u8; 16], first_seq: u64, count: u32, hash: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(first_seq.to_le_bytes());
    hasher.update(count.to_le_bytes());
    hasher.update(hash);
    let mut chain = [0u8; 16];
    chain.copy_from_slice(&hasher.finalize()[..16]);
    chain
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u64(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn encode_values(out: &mut Vec<u8>, c: &Column) {
    match c.value_type {
        ValueType::F32 => {
            let mut prev = 0u32;
            for (_, v) in &c.samples {
                let bits = match v {
                    Value::F32(x) => x.to_bits(),
                    _ => 0,
                };
                out.extend_from_slice(&(bits ^ prev).to_le_bytes());
                prev = bits;
            }
        }
        ValueType::F64 => {
            let mut prev = 0u64;
            for (_, v) in &c.samples {
                let bits = match v {
                    Value::F64(x) => x.to_bits(),
                    _ => 0,
                };
                out.extend_from_slice(&(bits ^ prev).to_le_bytes());
                prev = bits;
            }
        }
        ValueType::I64 => {
            let mut prev = 0i64;
            for (_, v) in &c.samples {
                let x = match v {
                    Value::I64(x) => *x,
                    _ => 0,
                };
                put_i64(out, x.wrapping_sub(prev));
                prev = x;
            }
        }
        ValueType::Bool => {
            for (_, v) in &c.samples {
                out.push(u8::from(matches!(v, Value::Bool(true))));
            }
        }
        ValueType::Enum => {
            for (_, v) in &c.samples {
                let x = match v {
                    Value::Enum(x) => *x,
                    _ => 0,
                };
                put_u64(out, u64::from(x));
            }
        }
        ValueType::Position => {
            let (mut prev_lat, mut prev_lon) = (0i32, 0i32);
            for (_, v) in &c.samples {
                let (lat, lon) = match v {
                    Value::Position { lat_e7, lon_e7 } => (*lat_e7, *lon_e7),
                    _ => (0, 0),
                };
                put_i64(out, i64::from(lat.wrapping_sub(prev_lat)));
                put_i64(out, i64::from(lon.wrapping_sub(prev_lon)));
                prev_lat = lat;
                prev_lon = lon;
            }
        }
        ValueType::Blob => {
            for (_, v) in &c.samples {
                let bytes: &[u8] = match v {
                    Value::Blob(b) => b,
                    _ => &[],
                };
                put_u64(out, bytes.len() as u64);
                out.extend_from_slice(bytes);
            }
        }
    }
}

fn decode_values(r: &mut Reader<'_>, value_type: ValueType, n: usize) -> Result<Vec<Value>, DecodeError> {
    let mut values = Vec::with_capacity(n);
    match value_type {
        ValueType::F32 => {
            let mut prev = 0u32;
            for _ in 0..n {
                let mut raw = [0u8; 4];
                raw.copy_from_slice(r.bytes(4)?);
                prev ^= u32::from_le_bytes(raw);
                values.push(Value::F32(f32::from_bits(prev)));
            }
        }
        ValueType::F64 => {
            let mut prev = 0u64;
            for _ in 0..n {
                let mut raw = [0u8; 8];
                raw.copy_from_slice(r.bytes(8)?);
                prev ^= u64::from_le_bytes(raw);
                values.push(Value::F64(f64::from_bits(prev)));
            }
        }
        ValueType::I64 => {
            let mut prev = 0i64;
            for _ in 0..n {
                prev = prev.wrapping_add(r.i64()?);
                values.push(Value::I64(prev));
            }
        }
        ValueType::Bool => {
            for _ in 0..n {
                values.push(Value::Bool(match r.u8()? {
                    0 => false,
                    1 => true,
                    other => return Err(DecodeError::BadTag(other)),
                }));
            }
        }
        ValueType::Enum => {
            for _ in 0..n {
                values.push(Value::Enum(r.u32()?));
            }
        }
        ValueType::Position => {
            let (mut lat, mut lon) = (0i32, 0i32);
            for _ in 0..n {
                lat = lat.wrapping_add(r.i32()?);
                lon = lon.wrapping_add(r.i32()?);
                values.push(Value::Position {
                    lat_e7: lat,
                    lon_e7: lon,
                });
            }
        }
        ValueType::Blob => {
            for _ in 0..n {
                let len = r.count()?;
                values.push(Value::Blob(r.bytes(len)?.to_vec()));
            }
        }
    }
    Ok(values)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        let b = *self.buf.get(self.pos).ok_or(DecodeError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        get_u64(self.buf, &mut self.pos)
    }

    fn i64(&mut self) -> Result<i64, DecodeError> {
        get_i64(self.buf, &mut self.pos)
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        u32::try_from(self.u64()?).map_err(|_| DecodeError::Overflow)
    }

    fn i32(&mut self) -> Result<i32, DecodeError> {
        i32::try_from(self.i64()?).map_err(|_| DecodeError::Overflow)
    }

    /// A count or length. Every counted item takes at least one byte, so a count larger than
    /// the remaining input is impossible and is rejected before anything is allocated.
    fn count(&mut self) -> Result<usize, DecodeError> {
        let n = self.u64()?;
        if n > self.remaining() as u64 {
            return Err(DecodeError::BadLength);
        }
        Ok(n as usize)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return Err(DecodeError::Truncated);
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        let n = self.count()?;
        let bytes = self.bytes(n)?;
        core::str::from_utf8(bytes)
            .map(String::from)
            .map_err(|_| DecodeError::BadUtf8)
    }

    fn value_type(&mut self) -> Result<ValueType, DecodeError> {
        let tag = self.u8()?;
        ValueType::from_u8(tag).ok_or(DecodeError::BadTag(tag))
    }
}
