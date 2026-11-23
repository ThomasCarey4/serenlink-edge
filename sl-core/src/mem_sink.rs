//! An in-memory `ArtifactSink` for tests and the simulator, with injected write and apply
//! failures, power cuts and corruption.
use alloc::vec::Vec;

use sl_proto::artifact::{ArtifactKind, Manifest};

use crate::sink::{ApplyResult, ArtifactSink, SinkError};

#[derive(Clone, Debug, Default)]
pub struct MemSink {
    partial: [Option<(Manifest, Vec<u8>)>; 4],
    applied: Vec<(Manifest, Vec<u8>)>,
    defer: bool,
    fail_write: bool,
    fail_apply: bool,
    /// Partials held in RAM only: a power cut loses them, as on a device without a staging slot.
    lose_on_power_cut: bool,
}

impl MemSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// While set, `apply` answers `Deferred`.
    pub fn set_defer(&mut self, defer: bool) {
        self.defer = defer;
    }

    /// The next `write` answers `Err(Io)`.
    pub fn fail_next_write(&mut self) {
        self.fail_write = true;
    }

    /// The next `apply` answers `Failed`.
    pub fn fail_next_apply(&mut self) {
        self.fail_apply = true;
    }

    pub fn set_lose_on_power_cut(&mut self, lose: bool) {
        self.lose_on_power_cut = lose;
    }

    /// Drops every partial if `set_lose_on_power_cut`; applied artifacts always survive.
    pub fn power_cut(&mut self) {
        if self.lose_on_power_cut {
            self.partial = Default::default();
        }
    }

    /// Flip the low bit of byte `at` of `kind`'s partial, if it holds that byte.
    pub fn corrupt_partial(&mut self, kind: ArtifactKind, at: u64) {
        if let Some((_, body)) = &mut self.partial[kind.index()]
            && let Some(b) = body.get_mut(at as usize)
        {
            *b ^= 1;
        }
    }

    /// Every artifact applied, oldest first.
    pub fn applied(&self) -> &[(Manifest, Vec<u8>)] {
        &self.applied
    }

    /// The last artifact of `kind` applied.
    pub fn running(&self, kind: ArtifactKind) -> Option<&(Manifest, Vec<u8>)> {
        self.applied.iter().rev().find(|(m, _)| m.kind() == Some(kind))
    }

    /// The manifest of the partial (or verified, deferred) download held for `kind`.
    pub fn partial(&self, kind: ArtifactKind) -> Option<&Manifest> {
        self.partial[kind.index()].as_ref().map(|(m, _)| m)
    }

    /// After a `Deferred`: make the partial for `m` active, as the shell does once its gates
    /// open. False if no partial for `m` is held.
    pub fn apply_now(&mut self, m: &Manifest) -> bool {
        let Some(kind) = m.kind() else {
            return false;
        };
        let slot = &mut self.partial[kind.index()];
        if slot.as_ref().is_none_or(|(held, _)| held != m) {
            return false;
        }
        if let Some(done) = slot.take() {
            self.applied.push(done);
        }
        true
    }
}

impl ArtifactSink for MemSink {
    fn progress(&self, kind: ArtifactKind) -> Option<(u32, u64)> {
        self.partial[kind.index()]
            .as_ref()
            .map(|(m, body)| (m.version, body.len() as u64))
    }

    fn begin(&mut self, m: &Manifest) -> Result<(), SinkError> {
        let kind = m.kind().ok_or(SinkError::Io)?;
        self.partial[kind.index()] = Some((m.clone(), Vec::new()));
        Ok(())
    }

    fn write(&mut self, kind: ArtifactKind, offset: u64, bytes: &[u8]) -> Result<(), SinkError> {
        if core::mem::take(&mut self.fail_write) {
            return Err(SinkError::Io);
        }
        let (_, body) = self.partial[kind.index()].as_mut().ok_or(SinkError::Io)?;
        let at = usize::try_from(offset).map_err(|_| SinkError::Io)?;
        // A gap would leave bytes nobody wrote: refuse it, as a real slot would.
        if at > body.len() {
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
        let (_, body) = self.partial[kind.index()].as_ref().ok_or(SinkError::Io)?;
        let at = usize::try_from(offset).map_err(|_| SinkError::Io)?;
        let Some(rest) = body.get(at..) else {
            return Ok(0);
        };
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        Ok(n)
    }

    fn apply(&mut self, m: &Manifest) -> ApplyResult {
        if core::mem::take(&mut self.fail_apply) {
            return ApplyResult::Failed;
        }
        if self.defer {
            return ApplyResult::Deferred;
        }
        if self.apply_now(m) {
            ApplyResult::Applied
        } else {
            ApplyResult::Failed
        }
    }
}
