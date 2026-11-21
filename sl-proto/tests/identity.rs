use sl_proto::identity::{
    IdentityCert, IdentityError, ServerIdentity, SignedIdentityCert, server_message, verify_cert_signature,
};

const RELEASE: [u8; 32] = [0x11; 32];
const IDENTITY: [u8; 32] = [0x22; 32];

fn public(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

fn cert(serial: u64) -> IdentityCert {
    IdentityCert {
        identity_pubkey: public(&IDENTITY).to_vec(),
        serial,
        hostnames: vec!["ingest.test".into()],
    }
}

#[test]
fn a_signed_cert_round_trips_and_verifies_under_its_release_key() {
    let signed = SignedIdentityCert::sign(&cert(7), 1, &RELEASE);
    let back = SignedIdentityCert::from_bytes(&signed.to_bytes()).unwrap();
    assert_eq!(back, signed);
    let body = verify_cert_signature(&back, &public(&RELEASE)).unwrap();
    assert_eq!(body.serial, 7);
}

#[test]
fn a_cert_does_not_verify_under_another_key() {
    let signed = SignedIdentityCert::sign(&cert(7), 1, &RELEASE);
    assert_eq!(
        verify_cert_signature(&signed, &public(&[0x33; 32])),
        Err(IdentityError::BadSignature)
    );
}

#[test]
fn a_cert_with_a_changed_body_does_not_verify() {
    let mut signed = SignedIdentityCert::sign(&cert(7), 1, &RELEASE);
    let last = signed.body.len() - 1;
    signed.body[last] ^= 1;
    assert!(verify_cert_signature(&signed, &public(&RELEASE)).is_err());
}

#[test]
fn bounds_are_enforced() {
    let mut c = cert(1);
    c.hostnames = (0..9).map(|i| format!("h{i}.test")).collect();
    let signed = SignedIdentityCert::sign(&c, 1, &RELEASE);
    assert_eq!(
        verify_cert_signature(&signed, &public(&RELEASE)),
        Err(IdentityError::Bounds)
    );
    let mut c = cert(1);
    c.hostnames = vec!["a".repeat(254)];
    let signed = SignedIdentityCert::sign(&c, 1, &RELEASE);
    assert_eq!(
        verify_cert_signature(&signed, &public(&RELEASE)),
        Err(IdentityError::Bounds)
    );
    let mut c = cert(1);
    c.serial = 0;
    let signed = SignedIdentityCert::sign(&c, 1, &RELEASE);
    assert_eq!(
        verify_cert_signature(&signed, &public(&RELEASE)),
        Err(IdentityError::Bounds)
    );
    assert_eq!(SignedIdentityCert::from_bytes(&[0u8; 1025]), Err(IdentityError::Bounds));
}

#[test]
fn a_server_identity_refuses_a_cert_for_another_key() {
    let signed = SignedIdentityCert::sign(&cert(1), 1, &RELEASE);
    assert_eq!(
        ServerIdentity::new([0x44; 32], signed.to_bytes()).unwrap_err(),
        IdentityError::KeyMismatch
    );
}

#[test]
fn the_server_signature_covers_every_field() {
    let signed = SignedIdentityCert::sign(&cert(1), 1, &RELEASE);
    let id = ServerIdentity::new(IDENTITY, signed.to_bytes()).unwrap();
    assert_eq!(id.serial(), 1);
    let sig = id.sign_challenge(&[1; 32], &[2; 32], &[3; 16], "ingest.test");
    let ok = server_message(&[1; 32], &[2; 32], &[3; 16], "ingest.test");
    assert!(sl_proto::auth::verify(&id.public_key(), &ok, &sig));
    for other in [
        server_message(&[9; 32], &[2; 32], &[3; 16], "ingest.test"),
        server_message(&[1; 32], &[9; 32], &[3; 16], "ingest.test"),
        server_message(&[1; 32], &[2; 32], &[9; 16], "ingest.test"),
        server_message(&[1; 32], &[2; 32], &[3; 16], "other.test"),
    ] {
        assert!(!sl_proto::auth::verify(&id.public_key(), &other, &sig));
    }
}

#[test]
fn server_message_is_fixed() {
    // context, then each field length-prefixed: a change here is a protocol change.
    let m = server_message(&[1; 32], &[2; 32], &[3; 16], "h");
    let mut want = b"serenlink-server-v1".to_vec();
    for f in [&[1u8; 32][..], &[2u8; 32][..], &[3u8; 16][..], b"h"] {
        want.extend_from_slice(&(f.len() as u32).to_le_bytes());
        want.extend_from_slice(f);
    }
    assert_eq!(m, want);
}
