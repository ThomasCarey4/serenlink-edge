use prost::Message;
use sl_proto::artifact::{
    ArtifactKind, Manifest, ManifestError, Outcome, Reason, Signer, body_matches, verify_manifest,
};
use sl_proto::identity::{IdentityCert, ServerIdentity, SignedIdentityCert};
use sl_proto::lp::signed_message;
use sl_proto::trust::{ReleaseKey, TrustStore};
use sl_proto::wire::{Body, Chunk, Envelope, Fetch, Offer, Report};

const RELEASE: [u8; 32] = [0x52; 32];
const ID: [u8; 32] = [0x22; 32];
const DEVICE: [u8; 16] = [7; 16];
const SERIAL: u64 = 5;

fn public(seed: &[u8; 32]) -> Vec<u8> {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
        .to_vec()
}

fn store(revoked: &[u64]) -> TrustStore {
    TrustStore {
        version: 1,
        release_keys: vec![ReleaseKey {
            id: 1,
            pubkey: public(&RELEASE),
        }],
        min_serial: 0,
        revoked_serials: revoked.to_vec(),
        tls_roots: vec![],
    }
}

fn identity() -> ServerIdentity {
    let cert = IdentityCert {
        identity_pubkey: public(&ID),
        serial: SERIAL,
        hostnames: vec!["ingest.test".into()],
    };
    ServerIdentity::new(ID, SignedIdentityCert::sign(&cert, 1, &RELEASE).to_bytes()).unwrap()
}

fn release(kind: ArtifactKind) -> Manifest {
    Manifest::sign_release(kind, 3, b"the body", 1, &RELEASE)
}

fn config() -> Manifest {
    Manifest::sign_config(&DEVICE, 3, b"the body", &identity())
}

#[test]
fn a_release_manifest_verifies() {
    for kind in [ArtifactKind::Tables, ArtifactKind::Firmware, ArtifactKind::Trust] {
        assert_eq!(verify_manifest(&release(kind), &store(&[]), &DEVICE), Ok(kind));
    }
    assert_eq!(
        verify_manifest(&config(), &store(&[]), &DEVICE),
        Ok(ArtifactKind::Configuration)
    );
}

#[test]
fn every_signed_field_is_covered() {
    let s = store(&[]);
    let flip = |m: &mut Manifest, field: &str| match field {
        "kind" => m.kind = if m.kind == 2 { 3 } else { 2 },
        "version" => m.version += 1,
        "size" => m.size += 1,
        "sha256" => m.sha256[0] ^= 1,
        "device_id" => m.device_id[0] ^= 1,
        _ => unreachable!(),
    };
    for field in ["kind", "version", "size", "sha256"] {
        let mut m = release(ArtifactKind::Tables);
        flip(&mut m, field);
        assert_eq!(
            verify_manifest(&m, &s, &DEVICE),
            Err(ManifestError::Signature),
            "{field}"
        );
    }
    let mut m = config();
    flip(&mut m, "device_id");
    assert_eq!(verify_manifest(&m, &s, &DEVICE), Err(ManifestError::Signature));
    let mut m = release(ArtifactKind::Tables);
    m.key_id = 9;
    assert_eq!(verify_manifest(&m, &s, &DEVICE), Err(ManifestError::Signature));
}

#[test]
fn a_configuration_must_be_identity_signed() {
    // A release-signed manifest of kind configuration, and the identity cert on a release kind.
    let mut m = Manifest::sign_release(ArtifactKind::Configuration, 3, b"x", 1, &RELEASE);
    assert_eq!(m.signer, Signer::Release as u32);
    assert_eq!(verify_manifest(&m, &store(&[]), &DEVICE), Err(ManifestError::Signature));
    m = config();
    m.signer = Signer::Release as u32;
    assert_eq!(verify_manifest(&m, &store(&[]), &DEVICE), Err(ManifestError::Signature));
}

#[test]
fn a_release_kind_must_be_release_signed() {
    let mut m = release(ArtifactKind::Firmware);
    m.signer = Signer::Identity as u32;
    m.cert = identity().cert().to_vec();
    assert_eq!(verify_manifest(&m, &store(&[]), &DEVICE), Err(ManifestError::Signature));
}

#[test]
fn a_configuration_for_another_device_is_refused() {
    assert_eq!(
        verify_manifest(&config(), &store(&[]), &[8; 16]),
        Err(ManifestError::WrongDevice)
    );
    assert_eq!(ManifestError::WrongDevice.reason(), Reason::WrongDevice);
}

#[test]
fn a_revoked_identity_cannot_sign_configuration() {
    assert_eq!(
        verify_manifest(&config(), &store(&[SERIAL]), &DEVICE),
        Err(ManifestError::Signature)
    );
}

#[test]
fn size_limits() {
    let s = store(&[]);
    let zero = Manifest::sign_release(ArtifactKind::Tables, 1, b"", 1, &RELEASE);
    assert_eq!(verify_manifest(&zero, &s, &DEVICE), Err(ManifestError::Malformed));

    let max = ArtifactKind::Tables.max_size() as usize;
    let at = Manifest::sign_release(ArtifactKind::Tables, 1, &vec![0u8; max], 1, &RELEASE);
    assert_eq!(verify_manifest(&at, &s, &DEVICE), Ok(ArtifactKind::Tables));
    let over = Manifest::sign_release(ArtifactKind::Tables, 1, &vec![0u8; max + 1], 1, &RELEASE);
    assert_eq!(verify_manifest(&over, &s, &DEVICE), Err(ManifestError::TooBig));
    assert_eq!(ManifestError::TooBig.reason(), Reason::TooBig);
    assert_eq!(ManifestError::Malformed.reason(), Reason::Signature);
}

#[test]
fn body_matches_checks_length_and_hash() {
    let m = release(ArtifactKind::Tables);
    assert!(body_matches(&m, b"the body"));
    assert!(!body_matches(&m, b"the bodz"));
    assert!(!body_matches(&m, b"the bod"));
    assert!(!body_matches(&m, b"the body!"));
}

#[test]
fn messages_round_trip() {
    let bodies = [
        Body::Offer(Offer {
            manifests: vec![release(ArtifactKind::Firmware), config()],
        }),
        Body::Fetch(Fetch {
            kind: 3,
            version: 4,
            offset: 16384,
        }),
        Body::Chunk(Chunk {
            kind: 3,
            version: 4,
            offset: 16384,
            bytes: vec![1, 2, 3],
        }),
        Body::Report(Report {
            kind: 3,
            version: 4,
            outcome: Outcome::Failed as u32,
            reason: Reason::Hash as u32,
        }),
    ];
    for body in bodies {
        let env = Envelope::of(body);
        assert_eq!(Envelope::decode(env.encode_to_vec().as_slice()).unwrap(), env);
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct OldEnvelope {
    #[prost(oneof = "OldBody", tags = "1")]
    body: Option<OldBody>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
enum OldBody {
    #[prost(message, tag = "1")]
    Hello(sl_proto::wire::Hello),
}

#[test]
fn an_old_peer_skips_the_new_bodies() {
    let bytes = Envelope::of(Body::Offer(Offer {
        manifests: vec![release(ArtifactKind::Tables)],
    }))
    .encode_to_vec();
    assert_eq!(OldEnvelope::decode(bytes.as_slice()).unwrap().body, None);
}

#[test]
fn malformed_manifests_are_refused() {
    let s = store(&[]);
    let mut m = release(ArtifactKind::Tables);
    m.kind = 9;
    assert_eq!(verify_manifest(&m, &s, &DEVICE), Err(ManifestError::Malformed));
    for len in [0, 31, 33] {
        let mut m = release(ArtifactKind::Tables);
        m.sha256 = vec![0; len];
        assert_eq!(verify_manifest(&m, &s, &DEVICE), Err(ManifestError::Malformed), "{len}");
    }
    // Correctly signed, but a release kind has no device: the signature is made by hand over
    // the same layout `Manifest::sign_release` uses, with a device id in it.
    let mut m = release(ArtifactKind::Tables);
    m.device_id = DEVICE.to_vec();
    let message = signed_message(
        b"serenlink-artifact-v1",
        &[
            &m.kind.to_le_bytes(),
            &m.version.to_le_bytes(),
            &m.size.to_le_bytes(),
            &m.sha256,
            &m.device_id,
        ],
    );
    m.sig = ed25519_dalek::Signer::sign(&ed25519_dalek::SigningKey::from_bytes(&RELEASE), &message)
        .to_bytes()
        .to_vec();
    assert_eq!(verify_manifest(&m, &s, &DEVICE), Err(ManifestError::Malformed));
}
