use sl_proto::identity::{IdentityCert, IdentityError, ServerIdentity, SignedIdentityCert, verify_identity};
use sl_proto::trust::{ReleaseKey, SignedTrustStore, TrustError, TrustStore};

const K1: [u8; 32] = [0x11; 32];
const K2: [u8; 32] = [0x12; 32];
const ID: [u8; 32] = [0x22; 32];
const HOST: &str = "ingest.test";

fn public(seed: &[u8; 32]) -> Vec<u8> {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
        .to_vec()
}

fn store(version: u32, keys: &[(u32, [u8; 32])], min_serial: u64, revoked: &[u64]) -> TrustStore {
    TrustStore {
        version,
        release_keys: keys
            .iter()
            .map(|(id, s)| ReleaseKey {
                id: *id,
                pubkey: public(s),
            })
            .collect(),
        min_serial,
        revoked_serials: revoked.to_vec(),
        tls_roots: vec![],
    }
}

fn identity(serial: u64, host: &str, key_id: u32, release: &[u8; 32]) -> ServerIdentity {
    let cert = IdentityCert {
        identity_pubkey: public(&ID),
        serial,
        hostnames: vec![host.into()],
    };
    ServerIdentity::new(ID, SignedIdentityCert::sign(&cert, key_id, release).to_bytes()).unwrap()
}

fn check(store: &TrustStore, id: &ServerIdentity, binding: [u8; 32], host: &str) -> Result<(), IdentityError> {
    let nonce = [5; 32];
    let device = [6; 16];
    let sig = id.sign_challenge(&binding, &nonce, &device, host);
    verify_identity(store, id.cert(), &sig, &[1; 32], &nonce, &device, host)
}

#[test]
fn an_honest_challenge_verifies() {
    let s = store(1, &[(1, K1)], 1, &[]);
    assert_eq!(check(&s, &identity(1, HOST, 1, &K1), [1; 32], HOST), Ok(()));
}

#[test]
fn a_challenge_signed_over_another_channel_is_refused() {
    let s = store(1, &[(1, K1)], 1, &[]);
    assert_eq!(
        check(&s, &identity(1, HOST, 1, &K1), [2; 32], HOST),
        Err(IdentityError::BadSignature)
    );
}

#[test]
fn an_unknown_release_key_is_refused() {
    let s = store(1, &[(1, K1)], 1, &[]);
    assert_eq!(
        check(&s, &identity(1, HOST, 2, &K2), [1; 32], HOST),
        Err(IdentityError::UnknownReleaseKey)
    );
    // The right id with the wrong key is a bad signature, not an unknown key.
    assert_eq!(
        check(&s, &identity(1, HOST, 1, &K2), [1; 32], HOST),
        Err(IdentityError::BadSignature)
    );
}

#[test]
fn low_and_revoked_serials_are_refused() {
    let s = store(1, &[(1, K1)], 5, &[7]);
    assert_eq!(
        check(&s, &identity(4, HOST, 1, &K1), [1; 32], HOST),
        Err(IdentityError::Revoked)
    );
    assert_eq!(
        check(&s, &identity(7, HOST, 1, &K1), [1; 32], HOST),
        Err(IdentityError::Revoked)
    );
    assert_eq!(check(&s, &identity(6, HOST, 1, &K1), [1; 32], HOST), Ok(()));
}

#[test]
fn another_host_is_refused() {
    let s = store(1, &[(1, K1)], 1, &[]);
    assert_eq!(
        check(&s, &identity(1, "other.test", 1, &K1), [1; 32], HOST),
        Err(IdentityError::WrongHost)
    );
}

#[test]
fn a_store_signature_is_not_a_cert_signature() {
    // Same key, same bytes signed under the other context, must not verify.
    let s = store(1, &[(1, K1)], 1, &[]);
    let signed = SignedTrustStore::sign(&s, 1, &K1);
    let as_cert = SignedIdentityCert {
        body: signed.body.clone(),
        release_key_id: 1,
        sig: signed.sig.clone(),
    };
    let key: [u8; 32] = public(&K1).try_into().unwrap();
    assert_eq!(
        sl_proto::identity::verify_cert_signature(&as_cert, &key),
        Err(IdentityError::BadSignature)
    );
}

#[test]
fn a_successor_must_be_newer_and_signed_by_a_current_key() {
    let v1 = store(1, &[(1, K1)], 1, &[]);
    let v2 = store(2, &[(1, K1), (2, K2)], 1, &[]);
    let v3 = store(3, &[(2, K2)], 1, &[]);
    let v2s = SignedTrustStore::sign(&v2, 1, &K1);
    let got2 = v1.accept_successor(&v2s).unwrap();
    assert_eq!(got2, v2);
    // v3 is signed by K2, which only v2 introduced.
    let v3s = SignedTrustStore::sign(&v3, 2, &K2);
    assert_eq!(v1.accept_successor(&v3s), Err(TrustError::UnknownReleaseKey));
    assert_eq!(got2.accept_successor(&v3s).unwrap(), v3);
    // Not newer.
    assert_eq!(v3.accept_successor(&v2s), Err(TrustError::NotNewer));
    assert_eq!(v2.accept_successor(&v2s), Err(TrustError::NotNewer));
}

#[test]
fn a_store_without_keys_or_with_duplicate_ids_is_refused() {
    let v1 = store(1, &[(1, K1)], 1, &[]);
    let empty = SignedTrustStore::sign(&store(2, &[], 1, &[]), 1, &K1);
    assert_eq!(v1.accept_successor(&empty), Err(TrustError::Bounds));
    let dup = SignedTrustStore::sign(&store(2, &[(1, K1), (1, K2)], 1, &[]), 1, &K1);
    assert_eq!(v1.accept_successor(&dup), Err(TrustError::Bounds));
    let four = SignedTrustStore::sign(&store(2, &[(1, K1), (2, K2), (3, K2), (4, K2)], 1, &[]), 1, &K1);
    assert_eq!(v1.accept_successor(&four), Err(TrustError::Bounds));
    let revoked: Vec<u64> = (0..65).collect();
    let many = SignedTrustStore::sign(&store(2, &[(1, K1)], 1, &revoked), 1, &K1);
    assert_eq!(v1.accept_successor(&many), Err(TrustError::Bounds));
}

#[test]
fn a_baseline_must_verify_under_itself() {
    let v1 = store(1, &[(1, K1)], 1, &[]);
    assert_eq!(SignedTrustStore::sign(&v1, 1, &K1).open_baseline().unwrap(), v1);
    assert!(SignedTrustStore::sign(&v1, 1, &K2).open_baseline().is_err());
    let bytes = SignedTrustStore::sign(&v1, 1, &K1).to_bytes();
    assert_eq!(
        SignedTrustStore::from_bytes(&bytes).unwrap().open_baseline().unwrap(),
        v1
    );
}
