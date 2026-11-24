use sl_agent::sink::{AgentSink, MAX_ARTIFACT_BYTES};
use sl_core::sink::{ApplyResult, ArtifactSink, SinkError};
use sl_proto::artifact::{ArtifactKind, Manifest};

fn manifest(kind: ArtifactKind, size: u64) -> Manifest {
    Manifest {
        kind: kind as u32,
        version: 2,
        size,
        ..Manifest::default()
    }
}

#[test]
fn a_download_is_held_and_its_apply_fails() {
    let mut s = AgentSink::default();
    let m = manifest(ArtifactKind::Configuration, 4);
    s.begin(&m).unwrap();
    s.write(ArtifactKind::Configuration, 0, b"ab").unwrap();
    s.write(ArtifactKind::Configuration, 2, b"cd").unwrap();
    assert_eq!(s.progress(ArtifactKind::Configuration), Some((2, 4)));
    let mut buf = [0u8; 8];
    assert_eq!(s.read(ArtifactKind::Configuration, 1, &mut buf).unwrap(), 3);
    assert_eq!(&buf[..3], b"bcd");
    assert_eq!(s.apply(&m), ApplyResult::Failed);
}

#[test]
fn an_artifact_too_big_to_hold_is_refused_at_begin() {
    let mut s = AgentSink::default();
    assert_eq!(
        s.begin(&manifest(ArtifactKind::Firmware, MAX_ARTIFACT_BYTES + 1)),
        Err(SinkError::Full)
    );
}

#[test]
fn a_write_past_what_is_held_is_refused() {
    let mut s = AgentSink::default();
    s.begin(&manifest(ArtifactKind::Tables, 10)).unwrap();
    assert_eq!(s.write(ArtifactKind::Tables, 3, b"x"), Err(SinkError::Io));
}
