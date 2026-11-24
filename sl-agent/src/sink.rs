//! The agent's `ArtifactSink` (agent spec 3.7): NixOS owns the binary and the configuration, so
//! nothing but a trust store is ever made active. A trust store is applied by `Control` through
//! the trust anchor and never reaches `apply`. Other kinds download into RAM and fail at apply,
//! which `Control` reports `failed{apply}`.
use std::collections::BTreeMap;

use sl_core::sink::{ApplyResult, ArtifactSink, SinkError};
use sl_proto::artifact::{ArtifactKind, Manifest};

pub const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024;

#[derive(Default)]
pub struct AgentSink {
    partial: BTreeMap<usize, (u32, Vec<u8>)>,
}

impl ArtifactSink for AgentSink {
    fn progress(&self, kind: ArtifactKind) -> Option<(u32, u64)> {
        self.partial.get(&kind.index()).map(|(v, b)| (*v, b.len() as u64))
    }

    fn begin(&mut self, m: &Manifest) -> Result<(), SinkError> {
        let kind = m.kind().ok_or(SinkError::Io)?;
        if m.size > MAX_ARTIFACT_BYTES {
            return Err(SinkError::Full);
        }
        self.partial.insert(kind.index(), (m.version, Vec::new()));
        Ok(())
    }

    fn write(&mut self, kind: ArtifactKind, offset: u64, bytes: &[u8]) -> Result<(), SinkError> {
        let (_, body) = self.partial.get_mut(&kind.index()).ok_or(SinkError::Io)?;
        let at = usize::try_from(offset).map_err(|_| SinkError::Io)?;
        if at > body.len() || (at + bytes.len()) as u64 > MAX_ARTIFACT_BYTES {
            return Err(SinkError::Io);
        }
        let end = at + bytes.len();
        if end > body.len() {
            body.resize(end, 0);
        }
        body[at..end].copy_from_slice(bytes);
        Ok(())
    }

    fn read(&self, kind: ArtifactKind, offset: u64, buf: &mut [u8]) -> Result<usize, SinkError> {
        let (_, body) = self.partial.get(&kind.index()).ok_or(SinkError::Io)?;
        let at = usize::try_from(offset).map_err(|_| SinkError::Io)?;
        let Some(rest) = body.get(at..) else { return Ok(0) };
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        Ok(n)
    }

    fn apply(&mut self, m: &Manifest) -> ApplyResult {
        if let Some(kind) = m.kind() {
            self.partial.remove(&kind.index());
        }
        ApplyResult::Failed
    }
}
