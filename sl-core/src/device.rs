//! The device half that every shell shares: the durable log, the recorder, the upload session,
//! the control lane and the trust anchor, and the routing between them. A shell (the simulator's
//! boat, the hunt's device, the Linux agent, firmware) owns one and adds only its I/O: where
//! samples come from, the transport, and what a reboot means for its storage and sink.
use alloc::string::String;
use alloc::vec::Vec;

use sl_proto::artifact::{ArtifactKind, Outcome, Reason};
use sl_proto::auth::{KeySigner, Signer};
use sl_proto::ids::Class;
use sl_proto::record::{Define, TimeAnchor};
use sl_proto::trust::{SignedTrustStore, TrustStore};
use sl_proto::value::Value;
use sl_proto::wire::{Body, DeviceState, Envelope};

use crate::control::{Control, Event};
use crate::log::{DurableLog, Recovery};
use crate::recorder::{Recorder, RecorderConfig, Sealed};
use crate::session::{Phase, Session, SessionConfig, SessionError};
use crate::sink::ArtifactSink;
use crate::storage::{Storage, StorageError};
use crate::trust::{OfferError, OpenError, TrustAnchor};

#[derive(Clone, Debug)]
pub struct DeviceConfig {
    pub device_id: [u8; 16],
    /// The Ed25519 seed of the device key.
    pub seed: [u8; 32],
    /// The server name the device connects to and its Auth signs.
    pub hostname: String,
    /// This boot's id: a new one after every power cycle or process start.
    pub boot_id: u32,
    /// What the device runs of each kind, by `ArtifactKind::index`; Trust's entry is unused.
    pub running: [u32; 4],
    pub recorder: RecorderConfig,
    pub max_batches_per_poll: usize,
    /// Whether Offers and Chunks of an active session reach the control lane, and its
    /// reports and Fetches go out. Off, they go to the session, as before the control lane.
    pub control_lane: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenDeviceError {
    Storage(StorageError),
    Trust(OpenError),
}

pub struct Device<S: Storage, K: ArtifactSink> {
    cfg: DeviceConfig,
    log: DurableLog<S>,
    recorder: Recorder,
    session: Session<KeySigner>,
    anchor: TrustAnchor,
    control: Control,
    sink: K,
    server_anchors: u64,
    storage_fault: Option<StorageError>,
}

impl<S: Storage, K: ArtifactSink> Device<S, K> {
    /// Open the log on `storage` and the trust anchor over its slots, with `baseline` as the
    /// compiled-in store. The `Recovery` is the log's; hand it to `report_recovery` before the
    /// first `tick` unless the storage is known clean.
    pub fn open(
        cfg: DeviceConfig,
        storage: S,
        sink: K,
        baseline: &SignedTrustStore,
    ) -> Result<(Self, Recovery), OpenDeviceError> {
        let (log, recovery) = DurableLog::open(storage).map_err(OpenDeviceError::Storage)?;
        let anchor = TrustAnchor::open(log.storage(), baseline).map_err(OpenDeviceError::Trust)?;
        let session_cfg = SessionConfig {
            device_id: cfg.device_id,
            hostname: cfg.hostname.clone(),
            firmware_version: cfg.running[ArtifactKind::Firmware.index()],
            config_version: cfg.running[ArtifactKind::Configuration.index()],
            table_version: cfg.running[ArtifactKind::Tables.index()],
            max_batches_per_poll: cfg.max_batches_per_poll,
        };
        let session = Session::new(session_cfg, KeySigner::from_seed(cfg.seed), anchor.active().clone());
        let recorder = Recorder::new(cfg.recorder.clone(), cfg.boot_id);
        let control = Control::new(cfg.device_id, cfg.running);
        let device = Self {
            cfg,
            log,
            recorder,
            session,
            anchor,
            control,
            sink,
            server_anchors: 0,
            storage_fault: None,
        };
        Ok((device, recovery))
    }

    pub fn report_recovery(
        &mut self,
        recovery: &Recovery,
        now_ms: u64,
        sealed: &mut Vec<Sealed>,
    ) -> Result<(), StorageError> {
        self.recorder.report_recovery(recovery, now_ms, &mut self.log, sealed)
    }

    pub fn sample(&mut self, class: Class, def: &Define, mono_ms: u64, value: Value) {
        self.recorder.sample(class, def, mono_ms, value);
    }

    pub fn anchor(&mut self, anchor: TimeAnchor) {
        self.recorder.anchor(anchor);
    }

    pub fn tick(&mut self, now_ms: u64, sealed: &mut Vec<Sealed>) -> Result<(), StorageError> {
        self.recorder.tick(now_ms, &mut self.log, sealed)
    }

    /// Seal every open block, as a clean stop does.
    pub fn flush(&mut self, now_ms: u64, sealed: &mut Vec<Sealed>) -> Result<(), StorageError> {
        self.recorder.flush(now_ms, &mut self.log, sealed)
    }

    pub fn phase(&self) -> Phase {
        self.session.phase()
    }

    pub fn connected(&self) -> bool {
        self.session.phase() != Phase::Disconnected
    }

    /// The state the server reported in its last Welcome.
    pub fn state(&self) -> DeviceState {
        self.session.state()
    }

    /// The transport is up with channel binding `binding`. Returns the Hello to send, or
    /// `None` if the log could not be read.
    pub fn connect(&mut self, binding: [u8; 32], now_ms: u64) -> Option<Envelope> {
        self.session.on_connected(&self.log, binding, now_ms).ok()
    }

    /// The connection is gone, for the session and the control lane alike.
    pub fn disconnect(&mut self) {
        self.session.on_disconnected();
        self.control.on_disconnected();
    }

    /// The shell's routing: with the control lane on and the session active, an Offer or a
    /// Chunk goes to the control lane; everything else to the session. A session error drops
    /// the link (close the transport) and comes back to the shell, which decides whether it was
    /// its storage failing.
    pub fn receive(&mut self, msg: Envelope, now_ms: u64) -> Result<Vec<Envelope>, SessionError> {
        let lane = self.cfg.control_lane && self.session.phase() == Phase::Active;
        let msg = match msg.body {
            Some(Body::Offer(offer)) if lane => {
                self.control.on_offer(offer, self.anchor.active());
                return Ok(Vec::new());
            }
            Some(Body::Chunk(chunk)) if lane => {
                let event = self
                    .control
                    .on_chunk(chunk, &mut self.sink, &mut self.anchor, self.log.storage_mut());
                match event {
                    Event::None => {}
                    Event::TrustChanged => self.session.set_trust(self.anchor.active().clone()),
                    Event::Applied(kind, version) => self.session.set_running(kind, version),
                }
                return Ok(Vec::new());
            }
            body => Envelope { body },
        };
        match self.receive_raw(msg, now_ms) {
            Ok(out) => Ok(out),
            Err(e) => {
                self.disconnect();
                Err(e)
            }
        }
    }

    /// The session's answer to `msg`, with no routing and no disconnect on error. A Welcome's
    /// server time becomes a `Server` anchor at `now_ms`.
    pub fn receive_raw(&mut self, msg: Envelope, now_ms: u64) -> Result<Vec<Envelope>, SessionError> {
        let out = self.session.on_message(msg, &mut self.log)?;
        if let Some(anchor) = self.session.take_anchor(now_ms) {
            self.recorder.anchor(anchor);
            self.server_anchors += 1;
        }
        Ok(out)
    }

    /// Batches first, then, with the control lane on and the session active, its reports and
    /// its one Fetch. A storage error reading batches yields none and is kept for
    /// `take_storage_fault`; the control lane still polls.
    pub fn poll(&mut self) -> Vec<Envelope> {
        let mut out = match self.session.poll(&mut self.log) {
            Ok(out) => out,
            Err(e) => {
                self.storage_fault = Some(e);
                Vec::new()
            }
        };
        if self.cfg.control_lane && self.session.phase() == Phase::Active {
            out.extend(self.control.poll(&mut self.sink));
        }
        out
    }

    pub fn take_storage_fault(&mut self) -> Option<StorageError> {
        self.storage_fault.take()
    }

    /// A newer trust store from outside the protocol (a shell's sideload, a test).
    pub fn offer_trust(&mut self, next: &SignedTrustStore) -> Result<(), OfferError> {
        self.anchor.offer(self.log.storage_mut(), next)?;
        self.session.set_trust(self.anchor.active().clone());
        Ok(())
    }

    /// `Control::finish`: the shell's word on a deferred apply.
    pub fn finish(&mut self, kind: ArtifactKind, version: u32, outcome: Outcome, reason: Reason) -> bool {
        self.control.finish(kind, version, outcome, reason)
    }

    /// What the Hello names for `kind` from now on.
    pub fn set_running(&mut self, kind: ArtifactKind, version: u32) {
        self.session.set_running(kind, version);
    }

    pub fn running(&self, kind: ArtifactKind) -> u32 {
        self.control.running(kind, self.anchor.active())
    }

    pub fn trust(&self) -> &TrustStore {
        self.anchor.active()
    }

    /// How many Server anchors Welcomes gave this device since it opened.
    pub fn server_anchors(&self) -> u64 {
        self.server_anchors
    }

    pub fn config(&self) -> &DeviceConfig {
        &self.cfg
    }

    pub fn public_key(&self) -> [u8; 32] {
        KeySigner::from_seed(self.cfg.seed).public_key()
    }

    pub fn log(&self) -> &DurableLog<S> {
        &self.log
    }

    pub fn log_mut(&mut self) -> &mut DurableLog<S> {
        &mut self.log
    }

    pub fn sink(&self) -> &K {
        &self.sink
    }

    pub fn sink_mut(&mut self) -> &mut K {
        &mut self.sink
    }

    pub fn control(&self) -> &Control {
        &self.control
    }

    /// The storage and the sink, for a reboot: what survives a power cycle.
    pub fn into_parts(self) -> (S, K) {
        (self.log.into_storage(), self.sink)
    }
}
