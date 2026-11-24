//! The device's half of the control lane (spec 2): which offered artifacts to take, fetching
//! them one chunk at a time, checking what arrived, and the reports the server is owed.
//!
//! `Control` sits beside `Session`, not inside it: the shell routes `Offer` and `Chunk` here
//! while the session is `Active` and sends what `poll` returns after `Session::poll`, so data
//! batches go first in each round and one `Fetch` in flight bounds what the lane costs them.
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use sl_proto::artifact::{ArtifactKind, MAX_CHUNK, Manifest, Outcome, Reason, verify_manifest};
use sl_proto::trust::{MAX_TRUST_STORE_BYTES, SignedTrustStore, TrustError, TrustStore};
use sl_proto::wire::{Body, Chunk, Envelope, Fetch, Offer, Report};

use crate::sink::{ApplyResult, ArtifactSink};
use crate::storage::Storage;
use crate::trust::{OfferError, TrustAnchor};

/// What a `Chunk` changed that the shell must act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    None,
    /// The trust anchor took a new store: the shell hands it to the session.
    TrustChanged,
    /// `kind` now runs `version`.
    Applied(ArtifactKind, u32),
}

/// The most (kind, version) refusals remembered in a session. Past it a refusal is neither
/// reported nor remembered, though the manifest is still not fetched: a byzantine server can
/// offer endlessly many bad manifests, and the device's memory must not grow with them.
pub const MAX_REFUSED: usize = 32;

/// The download under way: one at a time, across all kinds.
struct Download {
    m: Manifest,
    kind: ArtifactKind,
    /// The offset the next `Fetch` asks for; every byte below it is in the sink.
    next: u64,
    /// The body already failed its hash once and was fetched again from 0.
    mismatched: bool,
}

pub struct Control {
    device_id: [u8; 16],
    /// By `ArtifactKind::index`; Trust's entry is unused (the trust store knows its version).
    running: [u32; 4],
    /// The last `Offer` as it arrived, and the trust store it was last judged against: judged
    /// again when the store changes, or when a trust store it holds fails.
    offer: Option<Offer>,
    store: Option<TrustStore>,
    /// The current offer, by kind, with every manifest already verified.
    offered: [Option<Manifest>; 4],
    current: Option<Download>,
    /// The (kind, version) of the `Fetch` not yet answered. It outlives a withdrawn download:
    /// the server allows one `Fetch` outstanding, so nothing is fetched until its `Chunk`
    /// arrives, even when that `Chunk` is no longer wanted.
    in_flight: Option<(u32, u32)>,
    /// (kind, version) already reported refused this session, so each is reported once; at
    /// most `MAX_REFUSED` of them.
    refused: BTreeSet<(u32, u32)>,
    /// Failed this session: not fetched again until the next one.
    failed: BTreeSet<(ArtifactKind, u32)>,
    /// The server answered an empty `Chunk`: no longer offered, until the next `Offer` says.
    gone: BTreeSet<(ArtifactKind, u32)>,
    /// Verified and held by the sink, waiting on the device's own gates for `finish`. Kept
    /// across sessions: the shell may apply one long after the link dropped.
    deferred: Vec<Manifest>,
    reports: Vec<Report>,
}

fn report(kind: u32, version: u32, outcome: Outcome, reason: Reason) -> Report {
    Report {
        kind,
        version,
        outcome: outcome as u32,
        reason: reason as u32,
    }
}

impl Control {
    /// `running[k.index()]` for Configuration, Tables, Firmware; Trust's entry is ignored
    /// (the trust store's own version is used).
    pub fn new(device_id: [u8; 16], running: [u32; 4]) -> Self {
        Self {
            device_id,
            running,
            offer: None,
            store: None,
            offered: Default::default(),
            current: None,
            in_flight: None,
            refused: BTreeSet::new(),
            failed: BTreeSet::new(),
            gone: BTreeSet::new(),
            deferred: Vec::new(),
            reports: Vec::new(),
        }
    }

    pub fn running(&self, kind: ArtifactKind, trust: &TrustStore) -> u32 {
        match kind {
            ArtifactKind::Trust => trust.version,
            k => self.running[k.index()],
        }
    }

    /// The session ended. The sink keeps its partial, so the next session resumes it; what was
    /// refused or failed is tried afresh, and queued reports wait for the next `poll`.
    pub fn on_disconnected(&mut self) {
        self.offer = None;
        self.store = None;
        self.offered = Default::default();
        self.current = None;
        self.in_flight = None;
        self.refused.clear();
        self.failed.clear();
        self.gone.clear();
    }

    /// Replace what is offered (spec 2.1). A manifest is believed only once it verifies; a
    /// refusal is reported once per (kind, version) per session, so a server that keeps
    /// offering the same bad manifest hears about it once.
    pub fn on_offer(&mut self, offer: Offer, trust: &TrustStore) {
        self.gone.clear();
        self.offer = Some(offer);
        self.store = Some(trust.clone());
        self.judge();
    }

    /// A newer trust store this offer holds, that verifies and has not failed this session:
    /// it may carry the key that signs the rest (amended in the final review).
    fn pending_trust(&self, offer: &Offer, trust: &TrustStore) -> bool {
        offer.manifests.iter().any(|m| {
            m.kind == ArtifactKind::Trust as u32
                && m.version > trust.version
                && !self.failed.contains(&(ArtifactKind::Trust, m.version))
                && verify_manifest(m, trust, &self.device_id).is_ok()
        })
    }

    /// Judge the kept offer against the kept store. While it holds a pending trust store, a
    /// manifest of another kind whose signature does not verify is neither refused nor
    /// fetched: it is judged again once that store is applied, refused or failed. A manifest
    /// of a kind this device does not know is skipped without a report, for a newer server's
    /// sake. Deferred applies the store no longer verifies are dropped and refused.
    fn judge(&mut self) {
        let (Some(offer), Some(trust)) = (self.offer.take(), self.store.take()) else {
            return;
        };
        let pending = self.pending_trust(&offer, &trust);
        let mut offered: [Option<Manifest>; 4] = Default::default();
        for m in &offer.manifests {
            // An unknown kind is skipped, and so is the version the device runs, before its
            // signature: the store may since have dropped the key that signed it, and nothing
            // is fetched either way.
            let Some(known) = ArtifactKind::from_u32(m.kind) else {
                continue;
            };
            if m.version == self.running(known, &trust) {
                continue;
            }
            let kind = match verify_manifest(m, &trust, &self.device_id) {
                Ok(kind) => kind,
                Err(e) => {
                    let held_back = pending && e.reason() == Reason::Signature && m.kind != ArtifactKind::Trust as u32;
                    if !held_back {
                        self.refuse(m.kind, m.version, e.reason());
                    }
                    continue;
                }
            };
            let running = self.running(kind, &trust);
            if self.failed.contains(&(kind, m.version))
                || self
                    .deferred
                    .iter()
                    .any(|d| d.kind() == Some(kind) && d.version == m.version)
            {
                continue;
            }
            if m.version < running {
                self.refuse(m.kind, m.version, Reason::NotNewer);
                continue;
            }
            // Two of one kind in one offer: the newer is the one worth having.
            let slot = &mut offered[kind.index()];
            if slot.as_ref().is_none_or(|held| held.version < m.version) {
                *slot = Some(m.clone());
            }
        }
        // A deferred apply is believed only while the store still verifies it.
        let mut kept = Vec::new();
        for d in core::mem::take(&mut self.deferred) {
            match verify_manifest(&d, &trust, &self.device_id) {
                Ok(_) => kept.push(d),
                Err(e) => self.refuse(d.kind, d.version, e.reason()),
            }
        }
        self.deferred = kept;
        self.offered = offered;
        if let Some(d) = &self.current
            // The whole manifest, not just (kind, version): one re-signed at the same version
            // restarts the download, as the sink's partial may be of different bytes.
            && (self.offered[d.kind.index()].as_ref() != Some(&d.m)
                // A pending trust store goes first, so what it revokes is never applied; the
                // sink keeps the partial, and the download resumes from it afterwards.
                || (pending && d.kind != ArtifactKind::Trust))
        {
            // Withdrawn: its Fetch stays in flight, and the Chunk answering it is ignored,
            // being no longer current.
            self.drop_download();
        }
        self.offer = Some(offer);
        self.store = Some(trust);
    }

    /// The trust store changed or a trust download ended without one: judge the kept offer
    /// again, against `trust`.
    fn rejudge(&mut self, trust: Option<&TrustStore>) {
        if let Some(trust) = trust {
            self.store = Some(trust.clone());
        }
        self.judge();
    }

    fn refuse(&mut self, kind: u32, version: u32, reason: Reason) {
        if self.refused.len() >= MAX_REFUSED || self.refused.contains(&(kind, version)) {
            return;
        }
        self.refused.insert((kind, version));
        self.reports.push(report(kind, version, Outcome::Refused, reason));
    }

    /// Queue a `Failed` report and stop fetching (kind, version) this session. A trust store
    /// that fails frees what waited on it.
    fn fail(&mut self, kind: ArtifactKind, version: u32, reason: Reason) {
        self.failed.insert((kind, version));
        self.reports.push(report(kind as u32, version, Outcome::Failed, reason));
        if kind == ArtifactKind::Trust {
            self.rejudge(None);
        }
    }

    /// End the current download; the `failed` and `gone` sets, or the offer, say whether it
    /// starts again. A `Fetch` in flight stays so until answered.
    fn drop_download(&mut self) {
        self.current = None;
    }

    /// Queued reports, then at most one `Fetch` (spec 2.2): nothing is fetched while one is
    /// unanswered, and the next download is the first offered kind in `FETCH_ORDER`.
    pub fn poll<K: ArtifactSink>(&mut self, sink: &mut K) -> Vec<Envelope> {
        let mut out: Vec<Envelope> = self.reports.drain(..).map(|r| Envelope::of(Body::Report(r))).collect();
        if self.in_flight.is_some() {
            return out;
        }
        if self.current.is_none() {
            self.start(sink);
        }
        // `start` may have queued a storage failure.
        out.extend(self.reports.drain(..).map(|r| Envelope::of(Body::Report(r))));
        if let Some(d) = &self.current {
            out.push(Envelope::of(Body::Fetch(Fetch {
                kind: d.kind as u32,
                version: d.m.version,
                offset: d.next,
            })));
            self.in_flight = Some((d.kind as u32, d.m.version));
        }
        out
    }

    /// Start the first download the offer allows, resuming the sink's partial when it is of
    /// the same version. A partial already whole resumes at its last byte: `Fetch.offset` is
    /// always below the size, and that byte arriving completes it and runs the check.
    fn start<K: ArtifactSink>(&mut self, sink: &mut K) {
        for kind in ArtifactKind::FETCH_ORDER {
            let Some(m) = self.offered[kind.index()].clone() else {
                continue;
            };
            // A deferred apply owns the sink's slot for its kind until `finish`: beginning
            // another download would discard its body.
            if self.deferred.iter().any(|d| d.kind() == Some(kind)) {
                continue;
            }
            if self.gone.contains(&(kind, m.version)) || self.failed.contains(&(kind, m.version)) {
                continue;
            }
            let next = match sink.progress(kind) {
                Some((version, held)) if version == m.version && held <= m.size => held.min(m.size - 1),
                _ => {
                    if sink.begin(&m).is_err() {
                        self.fail(kind, m.version, Reason::Storage);
                        continue;
                    }
                    0
                }
            };
            self.current = Some(Download {
                m,
                kind,
                next,
                mismatched: false,
            });
            return;
        }
    }

    /// The answer to the `Fetch` in flight (spec 2.2, 2.3). Any chunk of the (kind, version)
    /// in flight answers it; only one of the current download is used. A chunk at the wrong
    /// offset, longer than `MAX_CHUNK` or past the size is dropped and the next `poll` asks
    /// again; the body is believed only once all of it has been read back from the sink and its
    /// hash matches the manifest.
    pub fn on_chunk<K: ArtifactSink, S: Storage>(
        &mut self,
        chunk: Chunk,
        sink: &mut K,
        anchor: &mut TrustAnchor,
        storage: &mut S,
    ) -> Event {
        if self.in_flight != Some((chunk.kind, chunk.version)) {
            return Event::None;
        }
        self.in_flight = None;
        // In flight implies current or withdrawn: `poll` starts a download only with nothing
        // in flight, so a current download is always the one fetched.
        let Some(d) = &mut self.current else {
            return Event::None;
        };
        let (kind, version) = (d.kind, d.m.version);
        if chunk.bytes.is_empty() {
            self.gone.insert((kind, version));
            self.drop_download();
            return Event::None;
        }
        let len = chunk.bytes.len() as u64;
        if chunk.offset != d.next
            || chunk.bytes.len() > MAX_CHUNK
            || chunk.offset.checked_add(len).is_none_or(|end| end > d.m.size)
        {
            return Event::None;
        }
        if sink.write(kind, chunk.offset, &chunk.bytes).is_err() {
            self.drop_download();
            self.fail(kind, version, Reason::Storage);
            return Event::None;
        }
        d.next += len;
        if d.next < d.m.size {
            return Event::None;
        }
        match body_hash(sink, kind, d.m.size) {
            None => {
                self.drop_download();
                self.fail(kind, version, Reason::Storage);
                Event::None
            }
            Some(sha) if Some(sha) == d.m.sha() => {
                let m = d.m.clone();
                // The download is over whatever `complete` decides; the offer no longer holds it.
                self.drop_download();
                self.offered[kind.index()] = None;
                self.complete(&m, kind, sink, anchor, storage)
            }
            Some(_) if !d.mismatched => {
                d.mismatched = true;
                d.next = 0;
                if sink.begin(&d.m).is_err() {
                    self.drop_download();
                    self.fail(kind, version, Reason::Storage);
                }
                Event::None
            }
            Some(_) => {
                self.drop_download();
                self.fail(kind, version, Reason::Hash);
                Event::None
            }
        }
    }

    /// The shell's word on a deferred apply of (`kind`, `version`): `Applied` once it is
    /// running, or `Failed`. Anything that is not a deferred apply is ignored, and `false`
    /// comes back: the shell must make nothing active then. The report waits for the next
    /// `poll`, which may be in a later session. No `Event` comes back: after an `Applied` the
    /// shell must also call `Session::set_running`.
    pub fn finish(&mut self, kind: ArtifactKind, version: u32, outcome: Outcome, reason: Reason) -> bool {
        let Some(at) = self
            .deferred
            .iter()
            .position(|m| m.kind() == Some(kind) && m.version == version)
        else {
            return false;
        };
        self.deferred.remove(at);
        match outcome {
            Outcome::Applied => self.raise(kind, version),
            _ => {
                self.failed.insert((kind, version));
            }
        }
        self.reports.push(report(kind as u32, version, outcome, reason));
        true
    }

    /// Whether (`kind`, `version`) is a deferred apply waiting on `finish`.
    pub fn is_deferred(&self, kind: ArtifactKind, version: u32) -> bool {
        self.deferred
            .iter()
            .any(|m| m.kind() == Some(kind) && m.version == version)
    }

    /// An artifact the shell applied outside a live deferral, such as firmware that passed its
    /// probation after a reboot (`deferred` is RAM only, so `finish` cannot know it). Raises
    /// what runs and queues the `Applied` report for the next `poll`. The shell must also call
    /// `Session::set_running`.
    pub fn report_applied(&mut self, kind: ArtifactKind, version: u32) {
        self.raise(kind, version);
        self.reports
            .push(report(kind as u32, version, Outcome::Applied, Reason::None));
    }

    /// The failing twin of `report_applied`: an artifact the shell tried outside a live
    /// deferral and gave up on, such as firmware that failed its probation after a reboot and
    /// was rolled back (amended in the final review). Queues `Report{failed, reason}` for the
    /// next `poll`, and (kind, version) is not fetched again this session.
    pub fn report_failed(&mut self, kind: ArtifactKind, version: u32, reason: Reason) {
        self.fail(kind, version, reason);
    }

    /// What runs never goes down.
    fn raise(&mut self, kind: ArtifactKind, version: u32) {
        if kind != ArtifactKind::Trust {
            let r = &mut self.running[kind.index()];
            *r = (*r).max(version);
        }
    }

    /// A verified body: make it active (spec 2.3).
    fn complete<K: ArtifactSink, S: Storage>(
        &mut self,
        m: &Manifest,
        kind: ArtifactKind,
        sink: &mut K,
        anchor: &mut TrustAnchor,
        storage: &mut S,
    ) -> Event {
        if kind == ArtifactKind::Trust {
            return self.complete_trust(m, sink, anchor, storage);
        }
        match sink.apply(m) {
            ApplyResult::Applied => {
                self.raise(kind, m.version);
                self.reports
                    .push(report(kind as u32, m.version, Outcome::Applied, Reason::None));
                Event::Applied(kind, m.version)
            }
            ApplyResult::Deferred => {
                self.deferred.push(m.clone());
                Event::None
            }
            ApplyResult::Failed => {
                self.fail(kind, m.version, Reason::Apply);
                Event::None
            }
        }
    }

    fn complete_trust<K: ArtifactSink, S: Storage>(
        &mut self,
        m: &Manifest,
        sink: &K,
        anchor: &mut TrustAnchor,
        storage: &mut S,
    ) -> Event {
        let v = m.version;
        // Refusals go straight to `reports`, not through `refused`: the `failed` set below is
        // what stops the same store being fetched again.
        let refuse = |c: &mut Self, reason| {
            // Not fetched again this session: the same bytes would be refused again.
            c.failed.insert((ArtifactKind::Trust, v));
            c.reports
                .push(report(ArtifactKind::Trust as u32, v, Outcome::Refused, reason));
            // What waited on this store is judged without it.
            c.rejudge(None);
            Event::None
        };
        let size = m.size as usize;
        // A backstop: `verify_manifest` already caps a Trust manifest's size.
        if size > MAX_TRUST_STORE_BYTES {
            return refuse(self, Reason::TooBig);
        }
        let mut bytes = alloc::vec![0u8; size];
        let mut at = 0;
        while at < size {
            match sink.read(ArtifactKind::Trust, at as u64, &mut bytes[at..]) {
                Ok(n) if n > 0 => at += n,
                _ => {
                    self.fail(ArtifactKind::Trust, v, Reason::Storage);
                    return Event::None;
                }
            }
        }
        let Ok(signed) = SignedTrustStore::from_bytes(&bytes) else {
            return refuse(self, Reason::Signature);
        };
        // The store must be the version its manifest names, or the version the device reports
        // and the server records are not the store it holds (amended in the final review).
        // Only the version is read before the anchor checks the signature.
        if signed.open_unverified().map(|s| s.version) != Ok(v) {
            return refuse(self, Reason::Signature);
        }
        match anchor.offer(storage, &signed) {
            Ok(()) => {
                self.reports
                    .push(report(ArtifactKind::Trust as u32, v, Outcome::Applied, Reason::None));
                // Judge what is offered again under the new store: what it revokes is dropped,
                // what its new keys sign is taken.
                self.rejudge(Some(anchor.active()));
                Event::TrustChanged
            }
            Err(OfferError::Refused(TrustError::NotNewer)) => refuse(self, Reason::NotNewer),
            Err(OfferError::Refused(_)) => refuse(self, Reason::Signature),
            Err(OfferError::Storage(_)) => {
                self.fail(ArtifactKind::Trust, v, Reason::Storage);
                Event::None
            }
        }
    }
}

/// The sha256 of the first `size` bytes of `kind`'s partial, read back 1 KiB at a time so the
/// check is of what the sink holds, not of what arrived; `None` if the sink cannot give them.
fn body_hash<K: ArtifactSink>(sink: &K, kind: ArtifactKind, size: u64) -> Option<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024];
    let mut at = 0u64;
    while at < size {
        let want = (size - at).min(buf.len() as u64) as usize;
        let n = sink.read(kind, at, &mut buf[..want]).ok()?;
        if n == 0 {
            return None;
        }
        hasher.update(&buf[..n]);
        at += n as u64;
    }
    Some(hasher.finalize().into())
}
