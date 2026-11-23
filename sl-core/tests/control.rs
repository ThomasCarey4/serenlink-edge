use std::collections::BTreeMap;

use sl_core::control::{Control, Event};
use sl_core::mem_sink::MemSink;
use sl_core::mem_storage::MemStorage;
use sl_core::sink::ArtifactSink;
use sl_core::trust::TrustAnchor;
use sl_proto::artifact::{ArtifactKind, MAX_CHUNK, Manifest, Outcome, Reason};
use sl_proto::identity::{IdentityCert, ServerIdentity, SignedIdentityCert};
use sl_proto::trust::{ReleaseKey, SignedTrustStore, TrustStore};
use sl_proto::wire::{Body, Chunk, Envelope, Fetch, Offer, Report};

const RELEASE: [u8; 32] = [0x52; 32];
const OTHER: [u8; 32] = [0x53; 32];
const ID: [u8; 32] = [0x22; 32];
const DEVICE: [u8; 16] = [7; 16];

use ArtifactKind::{Configuration, Firmware, Tables, Trust};

fn public(seed: &[u8; 32]) -> Vec<u8> {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
        .to_vec()
}

fn store(version: u32) -> TrustStore {
    TrustStore {
        version,
        release_keys: vec![ReleaseKey {
            id: 1,
            pubkey: public(&RELEASE),
        }],
        min_serial: 0,
        revoked_serials: vec![],
        tls_roots: vec![],
    }
}

fn identity() -> ServerIdentity {
    let cert = IdentityCert {
        identity_pubkey: public(&ID),
        serial: 5,
        hostnames: vec!["ingest.test".into()],
    };
    ServerIdentity::new(ID, SignedIdentityCert::sign(&cert, 1, &RELEASE).to_bytes()).unwrap()
}

/// A device running version 1 of everything, trusting store v1.
struct Rig {
    control: Control,
    sink: MemSink,
    anchor: TrustAnchor,
    storage: MemStorage,
    bodies: BTreeMap<(u32, u32), Vec<u8>>,
}

fn body(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

impl Rig {
    fn new() -> Self {
        let storage = MemStorage::new(1 << 16);
        let anchor = TrustAnchor::open(&storage, &SignedTrustStore::sign(&store(1), 1, &RELEASE)).unwrap();
        Self {
            control: Control::new(DEVICE, [1, 1, 1, 0]),
            sink: MemSink::new(),
            anchor,
            storage,
            bodies: BTreeMap::new(),
        }
    }

    /// A release manifest for `body`, whose bytes the server side of `pump` will serve.
    fn release(&mut self, kind: ArtifactKind, version: u32, body: Vec<u8>) -> Manifest {
        let m = Manifest::sign_release(kind, version, &body, 1, &RELEASE);
        self.bodies.insert((kind as u32, version), body);
        m
    }

    fn config(&mut self, version: u32, body: Vec<u8>) -> Manifest {
        let m = Manifest::sign_config(&DEVICE, version, &body, &identity());
        self.bodies.insert((Configuration as u32, version), body);
        m
    }

    fn offer(&mut self, manifests: Vec<Manifest>) {
        let trust = self.anchor.active().clone();
        self.control.on_offer(Offer { manifests }, &trust);
    }

    fn poll(&mut self) -> Vec<Envelope> {
        self.control.poll(&mut self.sink)
    }

    fn chunk(&mut self, chunk: Chunk) -> Event {
        self.control
            .on_chunk(chunk, &mut self.sink, &mut self.anchor, &mut self.storage)
    }

    /// The server's answer to `f`.
    fn answer(&self, f: &Fetch) -> Chunk {
        let body = &self.bodies[&(f.kind, f.version)];
        let at = f.offset as usize;
        let end = (at + MAX_CHUNK).min(body.len());
        Chunk {
            kind: f.kind,
            version: f.version,
            offset: f.offset,
            bytes: body[at..end].to_vec(),
        }
    }

    /// Answer every `Fetch` until `poll` emits nothing; everything polled, in order.
    fn pump(&mut self) -> Vec<Envelope> {
        let mut seen = Vec::new();
        for _ in 0..10_000 {
            let out = self.poll();
            if out.is_empty() {
                return seen;
            }
            for e in &out {
                if let Some(Body::Fetch(f)) = &e.body {
                    let c = self.answer(f);
                    self.chunk(c);
                }
            }
            seen.extend(out);
        }
        panic!("pump did not settle");
    }
}

fn fetches(out: &[Envelope]) -> Vec<Fetch> {
    out.iter()
        .filter_map(|e| match &e.body {
            Some(Body::Fetch(f)) => Some(f.clone()),
            _ => None,
        })
        .collect()
}

fn reports(out: &[Envelope]) -> Vec<Report> {
    out.iter()
        .filter_map(|e| match &e.body {
            Some(Body::Report(r)) => Some(r.clone()),
            _ => None,
        })
        .collect()
}

fn rep(kind: ArtifactKind, version: u32, outcome: Outcome, reason: Reason) -> Report {
    Report {
        kind: kind as u32,
        version,
        outcome: outcome as u32,
        reason: reason as u32,
    }
}

#[test]
fn an_offer_of_what_runs_is_ignored() {
    let mut r = Rig::new();
    let t = r.release(Tables, 1, body(100, 0));
    let s = r.release(Trust, 1, SignedTrustStore::sign(&store(1), 1, &RELEASE).to_bytes());
    r.offer(vec![t, s]);
    assert!(r.poll().is_empty());
}

#[test]
fn an_older_version_is_refused_once() {
    let mut r = Rig::new();
    r.control = Control::new(DEVICE, [1, 5, 1, 0]);
    let m = r.release(Tables, 4, body(100, 0));
    r.offer(vec![m.clone()]);
    assert_eq!(
        reports(&r.poll()),
        vec![rep(Tables, 4, Outcome::Refused, Reason::NotNewer)]
    );
    r.offer(vec![m]);
    assert!(r.poll().is_empty());
}

#[test]
fn a_forged_manifest_is_refused_and_never_fetched() {
    let mut r = Rig::new();
    let b = body(100, 0);
    let forged = Manifest::sign_release(Tables, 2, &b, 1, &OTHER);
    r.bodies.insert((Tables as u32, 2), b);
    r.offer(vec![forged.clone()]);
    let out = r.pump();
    assert_eq!(reports(&out), vec![rep(Tables, 2, Outcome::Refused, Reason::Signature)]);
    assert!(fetches(&out).is_empty());
    r.offer(vec![forged]);
    assert!(r.poll().is_empty());
}

#[test]
fn downloads_follow_the_fetch_order() {
    let mut r = Rig::new();
    let f = r.release(Firmware, 2, body(100, 1));
    let t = r.release(Tables, 2, body(100, 2));
    let c = r.config(2, body(100, 3));
    let s = r.release(Trust, 2, SignedTrustStore::sign(&store(2), 1, &RELEASE).to_bytes());
    r.offer(vec![f, t, c, s]);
    let kinds: Vec<u32> = fetches(&r.pump()).iter().map(|f| f.kind).collect();
    assert_eq!(kinds.first(), Some(&(Trust as u32)));
    let mut order = kinds.clone();
    order.dedup();
    assert_eq!(
        order,
        vec![Trust as u32, Configuration as u32, Tables as u32, Firmware as u32]
    );
}

#[test]
fn one_fetch_in_flight() {
    let mut r = Rig::new();
    let t = r.release(Tables, 2, body(100, 0));
    r.offer(vec![t]);
    assert_eq!(fetches(&r.poll()).len(), 1);
    assert!(r.poll().is_empty());
}

#[test]
fn a_download_completes_and_is_applied() {
    let mut r = Rig::new();
    let b = body(40 * 1024, 9);
    let t = r.release(Tables, 2, b.clone());
    r.offer(vec![t.clone()]);
    let out = r.pump();
    let offsets: Vec<u64> = fetches(&out).iter().map(|f| f.offset).collect();
    assert_eq!(offsets, vec![0, 16384, 32768]);
    assert_eq!(r.sink.applied(), &[(t, b)]);
    assert_eq!(reports(&out), vec![rep(Tables, 2, Outcome::Applied, Reason::None)]);
}

#[test]
fn a_download_resumes_from_the_sink_after_a_disconnect() {
    let mut r = Rig::new();
    let t = r.release(Tables, 2, body(40 * 1024, 9));
    r.offer(vec![t.clone()]);
    let f = fetches(&r.poll()).remove(0);
    let c = r.answer(&f);
    r.chunk(c);
    r.control.on_disconnected();
    assert_eq!(r.sink.progress(Tables), Some((2, 16384)));

    r.offer(vec![t]);
    let f = fetches(&r.poll()).remove(0);
    assert_eq!(f.offset, 16384);
    let c = r.answer(&f);
    r.chunk(c);
    let out = r.pump();
    assert_eq!(reports(&out), vec![rep(Tables, 2, Outcome::Applied, Reason::None)]);
}

#[test]
fn a_complete_partial_resumes_at_its_last_byte() {
    let mut r = Rig::new();
    let b = body(1000, 4);
    let t = r.release(Tables, 2, b.clone());
    r.sink.begin(&t).unwrap();
    r.sink.write(Tables, 0, &b).unwrap();
    r.offer(vec![t.clone()]);
    let out = r.pump();
    let offsets: Vec<u64> = fetches(&out).iter().map(|f| f.offset).collect();
    assert_eq!(offsets, vec![999]);
    assert_eq!(r.sink.applied(), &[(t, b)]);
}

#[test]
fn a_misplaced_or_overlong_chunk_is_dropped_and_fetched_again() {
    let mut r = Rig::new();
    let t = r.release(Tables, 2, body(40 * 1024, 9));
    r.offer(vec![t]);
    let f = fetches(&r.poll()).remove(0);
    let mut c = r.answer(&f);
    c.offset = 5;
    r.chunk(c);
    assert_eq!(fetches(&r.poll()), vec![f.clone()]);

    // More than one chunk's worth, though within the size.
    let mut c = r.answer(&f);
    c.bytes = vec![0; MAX_CHUNK + 1];
    r.chunk(c);
    assert_eq!(fetches(&r.poll()), vec![f.clone()]);
    assert_eq!(r.sink.progress(Tables), Some((2, 0)));

    // Bytes past the size.
    let mut c = r.answer(&f);
    c.offset = 0;
    c.bytes = vec![0; 40 * 1024 + 1];
    r.chunk(c);
    assert_eq!(fetches(&r.poll()), vec![f.clone()]);
    assert_eq!(r.sink.progress(Tables), Some((2, 0)));

    let c = r.answer(&f);
    r.chunk(c);
    let out = r.pump();
    assert_eq!(reports(&out), vec![rep(Tables, 2, Outcome::Applied, Reason::None)]);
}

#[test]
fn an_empty_chunk_drops_the_download_until_reoffered() {
    let mut r = Rig::new();
    let t = r.release(Tables, 2, body(100, 0));
    r.offer(vec![t.clone()]);
    let f = fetches(&r.poll()).remove(0);
    r.chunk(Chunk {
        kind: f.kind,
        version: f.version,
        offset: f.offset,
        bytes: vec![],
    });
    assert!(r.poll().is_empty());
    r.offer(vec![t]);
    let out = r.pump();
    assert_eq!(fetches(&out)[0].offset, 0);
    assert_eq!(reports(&out), vec![rep(Tables, 2, Outcome::Applied, Reason::None)]);
}

#[test]
fn a_hash_mismatch_restarts_once_then_fails() {
    let mut r = Rig::new();
    let t = r.release(Tables, 2, body(40 * 1024, 9));
    r.offer(vec![t]);
    for round in 0..2 {
        // Every chunk but the last, then a bit rots in the sink before the last one lands.
        for expect in [0, 16384] {
            let f = fetches(&r.poll()).remove(0);
            assert_eq!(f.offset, expect, "round {round}");
            let c = r.answer(&f);
            r.chunk(c);
        }
        let f = fetches(&r.poll()).remove(0);
        assert_eq!(f.offset, 32768);
        r.sink.corrupt_partial(Tables, 7);
        let c = r.answer(&f);
        r.chunk(c);
    }
    let out = r.poll();
    assert_eq!(reports(&out), vec![rep(Tables, 2, Outcome::Failed, Reason::Hash)]);
    assert!(fetches(&out).is_empty());
    assert!(r.poll().is_empty());
    assert!(r.sink.applied().is_empty());
}

#[test]
fn a_sink_write_error_reports_storage() {
    let mut r = Rig::new();
    let t = r.release(Tables, 2, body(100, 0));
    r.offer(vec![t.clone()]);
    r.sink.fail_next_write();
    let out = r.pump();
    assert_eq!(fetches(&out).len(), 1);
    assert_eq!(reports(&out), vec![rep(Tables, 2, Outcome::Failed, Reason::Storage)]);
    // Failed this session: offered again, it is not fetched.
    r.offer(vec![t]);
    assert!(r.poll().is_empty());
}

#[test]
fn a_withdrawn_offer_stops_the_download() {
    let mut r = Rig::new();
    let t = r.release(Tables, 2, body(40 * 1024, 9));
    r.offer(vec![t]);
    let f = fetches(&r.poll()).remove(0);
    let c = r.answer(&f);
    r.chunk(c);
    let f = fetches(&r.poll()).remove(0);
    r.offer(vec![]);
    // The chunk already on its way is ignored, and nothing more is fetched.
    let c = r.answer(&f);
    r.chunk(c);
    assert!(r.poll().is_empty());
    assert_eq!(r.sink.progress(Tables), Some((2, 16384)));
    assert!(r.sink.applied().is_empty());
}

#[test]
fn a_replacement_offer_waits_for_the_chunk_in_flight() {
    let mut r = Rig::new();
    let v2 = r.release(Tables, 2, body(40 * 1024, 9));
    let v3 = r.release(Tables, 3, body(40 * 1024, 10));
    r.offer(vec![v2]);
    let f = fetches(&r.poll()).remove(0);
    r.offer(vec![v3.clone()]);
    // v2's Fetch is still unanswered: the server allows only one outstanding.
    assert!(r.poll().is_empty());
    let c = r.answer(&f);
    r.chunk(c);
    assert_eq!(r.sink.progress(Tables), Some((2, 0)));
    let out = r.pump();
    let first = &fetches(&out)[0];
    assert_eq!((first.version, first.offset), (3, 0));
    assert_eq!(reports(&out), vec![rep(Tables, 3, Outcome::Applied, Reason::None)]);
    assert_eq!(r.sink.running(Tables).map(|(m, _)| m), Some(&v3));
}

#[test]
fn a_withdrawn_and_reoffered_download_keeps_one_fetch_outstanding() {
    let mut r = Rig::new();
    let t = r.release(Tables, 2, body(40 * 1024, 9));
    r.offer(vec![t.clone()]);
    let f = fetches(&r.poll()).remove(0);
    let c = r.answer(&f);
    r.chunk(c);
    let f = fetches(&r.poll()).remove(0);
    assert_eq!(f.offset, 16384);
    r.offer(vec![]);
    r.offer(vec![t]);
    assert!(r.poll().is_empty());

    // The answer to the withdrawn download's Fetch is not used, but frees the lane.
    let c = r.answer(&f);
    r.chunk(c);
    assert_eq!(r.sink.progress(Tables), Some((2, 16384)));
    let mut outstanding: Option<Fetch> = None;
    let mut seen = Vec::new();
    for _ in 0..100 {
        let out = r.poll();
        let fs = fetches(&out);
        assert!(fs.len() <= 1);
        if let Some(f) = fs.into_iter().next() {
            assert!(outstanding.is_none(), "a second Fetch while one is outstanding");
            outstanding = Some(f);
        }
        seen.extend(out);
        let Some(f) = outstanding.take() else { break };
        // Polling again before answering sends nothing.
        assert!(fetches(&r.poll()).is_empty());
        let c = r.answer(&f);
        r.chunk(c);
    }
    let offsets: Vec<u64> = fetches(&seen).iter().map(|f| f.offset).collect();
    assert_eq!(offsets, vec![16384, 32768]);
    assert_eq!(reports(&seen), vec![rep(Tables, 2, Outcome::Applied, Reason::None)]);
}

#[test]
fn queued_reports_survive_a_disconnect() {
    let mut r = Rig::new();
    r.control = Control::new(DEVICE, [1, 5, 1, 0]);
    let m = r.release(Tables, 4, body(100, 0));
    r.offer(vec![m]);
    r.control.on_disconnected();
    assert_eq!(
        reports(&r.poll()),
        vec![rep(Tables, 4, Outcome::Refused, Reason::NotNewer)]
    );
}

#[test]
fn a_refusal_is_reported_again_in_the_next_session() {
    let mut r = Rig::new();
    r.control = Control::new(DEVICE, [1, 5, 1, 0]);
    let m = r.release(Tables, 4, body(100, 0));
    r.offer(vec![m.clone()]);
    assert_eq!(
        reports(&r.poll()),
        vec![rep(Tables, 4, Outcome::Refused, Reason::NotNewer)]
    );
    r.control.on_disconnected();
    r.offer(vec![m]);
    assert_eq!(
        reports(&r.poll()),
        vec![rep(Tables, 4, Outcome::Refused, Reason::NotNewer)]
    );
}

fn signed_store(s: &TrustStore) -> Vec<u8> {
    SignedTrustStore::sign(s, 1, &RELEASE).to_bytes()
}

#[test]
fn a_trust_store_is_applied_through_the_anchor() {
    let mut r = Rig::new();
    let mut next = store(2);
    next.release_keys.push(ReleaseKey {
        id: 2,
        pubkey: public(&OTHER),
    });
    let t = r.release(Trust, 2, signed_store(&next));
    r.offer(vec![t]);
    let mut events = Vec::new();
    let mut seen = Vec::new();
    for _ in 0..100 {
        let out = r.poll();
        if out.is_empty() {
            break;
        }
        for e in &out {
            if let Some(Body::Fetch(f)) = &e.body {
                let c = r.answer(f);
                events.push(r.chunk(c));
            }
        }
        seen.extend(out);
    }
    assert!(events.contains(&Event::TrustChanged));
    assert_eq!(r.anchor.active().version, 2);
    assert_eq!(reports(&seen), vec![rep(Trust, 2, Outcome::Applied, Reason::None)]);

    // A manifest signed by the new key now verifies and downloads.
    let b = body(100, 3);
    let m = Manifest::sign_release(Tables, 2, &b, 2, &OTHER);
    r.bodies.insert((Tables as u32, 2), b.clone());
    r.offer(vec![m.clone()]);
    let out = r.pump();
    assert_eq!(r.sink.applied().last(), Some(&(m, b)));
    assert_eq!(reports(&out), vec![rep(Tables, 2, Outcome::Applied, Reason::None)]);
}

#[test]
fn a_trust_store_the_anchor_refuses_is_reported() {
    let mut r = Rig::new();
    // The manifest is newer than the active store; the store inside is not.
    let t = r.release(Trust, 2, signed_store(&store(1)));
    r.offer(vec![t]);
    let out = r.pump();
    assert_eq!(reports(&out), vec![rep(Trust, 2, Outcome::Refused, Reason::NotNewer)]);
    assert_eq!(r.anchor.active().version, 1);
}

#[test]
fn a_garbled_trust_store_is_refused_as_a_signature() {
    let mut r = Rig::new();
    let t = r.release(Trust, 2, vec![1, 2, 3]);
    r.offer(vec![t]);
    let out = r.pump();
    assert_eq!(reports(&out), vec![rep(Trust, 2, Outcome::Refused, Reason::Signature)]);
}

#[test]
fn a_deferred_apply_reports_on_finish() {
    let mut r = Rig::new();
    r.sink.set_defer(true);
    let t = r.release(Tables, 2, body(100, 1));
    r.offer(vec![t.clone()]);
    let out = r.pump();
    assert!(reports(&out).is_empty());
    assert_eq!(r.control.running(Tables, r.anchor.active()), 1);
    // Offered again while deferred: not downloaded again.
    r.offer(vec![t.clone()]);
    assert!(r.poll().is_empty());

    r.sink.apply_now(&t);
    r.control.finish(Tables, 2, Outcome::Applied, Reason::None);
    assert_eq!(r.control.running(Tables, r.anchor.active()), 2);
    assert_eq!(reports(&r.poll()), vec![rep(Tables, 2, Outcome::Applied, Reason::None)]);
    // Only once.
    r.control.finish(Tables, 2, Outcome::Applied, Reason::None);
    assert!(r.poll().is_empty());
}

#[test]
fn finish_ignores_what_is_not_deferred() {
    let mut r = Rig::new();
    r.control.finish(Tables, 9, Outcome::Applied, Reason::None);
    assert!(r.poll().is_empty());
    assert_eq!(r.control.running(Tables, r.anchor.active()), 1);
}

#[test]
fn a_deferred_apply_survives_a_disconnect() {
    let mut r = Rig::new();
    r.sink.set_defer(true);
    let t = r.release(Tables, 2, body(100, 1));
    r.offer(vec![t.clone()]);
    r.pump();
    r.control.on_disconnected();
    r.sink.apply_now(&t);
    r.control.finish(Tables, 2, Outcome::Applied, Reason::None);
    r.control.on_disconnected();
    assert_eq!(reports(&r.poll()), vec![rep(Tables, 2, Outcome::Applied, Reason::None)]);
}

#[test]
fn a_failed_apply_is_reported() {
    let mut r = Rig::new();
    r.sink.fail_next_apply();
    let t = r.release(Tables, 2, body(100, 1));
    r.offer(vec![t]);
    let out = r.pump();
    assert_eq!(reports(&out), vec![rep(Tables, 2, Outcome::Failed, Reason::Apply)]);
    assert_eq!(r.control.running(Tables, r.anchor.active()), 1);
}
