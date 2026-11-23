//! Where a device keeps an artifact while it downloads, and what makes it active (control lane
//! spec 2.2, 2.3). `Control` decides what to fetch and checks what arrived; the sink only holds
//! bytes, so keeping them across a reboot (an A/B slot for firmware, a file on a Linux device)
//! is the sink's choice and `Control` resumes from whatever `progress` reports.
use sl_proto::artifact::{ArtifactKind, Manifest};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkError {
    /// No room for the body.
    Full,
    Io,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyResult {
    Applied,
    /// Verified and held, but the device's own gates (underway, anchor watch, the user's window)
    /// say not now. The shell calls `Control::finish` once it has applied it, or failed to.
    Deferred,
    Failed,
}

pub trait ArtifactSink {
    /// The partial download held for `kind`: its version and how many bytes from 0.
    fn progress(&self, kind: ArtifactKind) -> Option<(u32, u64)>;
    /// Start a download of `m`, discarding any other partial for its kind.
    fn begin(&mut self, m: &Manifest) -> Result<(), SinkError>;
    /// `bytes` at `offset` of `kind`'s partial; `Control` only writes at the end of what is held,
    /// or over its last byte when resuming a complete partial.
    fn write(&mut self, kind: ArtifactKind, offset: u64, bytes: &[u8]) -> Result<(), SinkError>;
    /// Up to `buf.len()` bytes of `kind`'s partial from `offset`; 0 past its end.
    fn read(&self, kind: ArtifactKind, offset: u64, buf: &mut [u8]) -> Result<usize, SinkError>;
    /// Make the verified download active, or say why not yet.
    fn apply(&mut self, m: &Manifest) -> ApplyResult;
}
