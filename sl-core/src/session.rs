use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use sl_proto::artifact::ArtifactKind;
use sl_proto::auth::{Signer, auth_message};
use sl_proto::identity::verify_identity;
use sl_proto::ids::Class;
use sl_proto::record::{AnchorSource, TimeAnchor};
use sl_proto::trust::TrustStore;
use sl_proto::wire::{Auth, Batch, Body, Cursor, DeviceState, Envelope, Hello, PROTOCOL_VERSION, Resync};

use crate::log::{DurableLog, Lineage};
use crate::storage::{Storage, StorageError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Disconnected,
    AwaitChallenge,
    AwaitWelcome,
    Active,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// The message does not belong in the current phase. Close the connection.
    Unexpected,
    /// The Challenge did not carry a 32-byte nonce.
    BadChallenge,
    /// The Challenge's server identity did not verify (spec 3.3): nothing was signed. The
    /// session stays in `AwaitChallenge`; the shell must close the transport, since the peer on
    /// this channel is not the server.
    BadIdentity,
    /// The Welcome was malformed, or named a protocol version that was not offered.
    BadWelcome,
    /// An Ack claimed more than this session has sent, or more backed up than committed.
    BadAck,
    /// A Rewind asked for sequences above the upload cursor: it would skip frames not sent.
    BadRewind,
    /// A Welcome, Ack or Rewind did not carry the check over its fields, or carried one that
    /// does not match them: it was damaged on the way, or is malformed. Nothing in it was
    /// acted on.
    BadCheck,
    Storage(StorageError),
}

impl From<StorageError> for SessionError {
    fn from(e: StorageError) -> Self {
        SessionError::Storage(e)
    }
}

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub device_id: [u8; 16],
    /// The server name the device connected to; part of what it signs.
    pub hostname: String,
    pub firmware_version: u32,
    /// The configuration the device runs. A device that has never applied a configuration
    /// from the server runs its factory configuration, version 0, so the server's first
    /// (version 1) is newer.
    pub config_version: u32,
    pub table_version: u32,
    /// Upper bound on batches produced by one `poll`.
    pub max_batches_per_poll: usize,
}

/// The device side of one connection, as a state machine with no I/O of its own. The shell
/// feeds it received messages and sends whatever it returns.
pub struct Session<G: Signer> {
    cfg: SessionConfig,
    signer: G,
    /// The active trust store: what a Challenge's certificate is checked against, and whose
    /// version the Hello names.
    trust: TrustStore,
    phase: Phase,
    state: DeviceState,
    /// The allowance per class as a balance: a frame costs its whole length, and any balance
    /// above zero lets one frame go, so it can fall below zero by less than one frame.
    credit: [i64; 3],
    /// One past the highest sequence the server can hold in this session, per class: its
    /// mark at the Welcome, then the end of each batch sent. An Ack beyond it is a lie.
    /// Everything held between the mark and here has been sent: the cursor starts at the
    /// mark, goes forward one frame at a time, and a Rewind can only take it back.
    sent_next: [u64; 3],
    /// Where the upload cursor of each class stands, as a sequence number: the server's mark
    /// at the Welcome, then the end of each batch sent, or where a Rewind put it back to.
    /// Every batch states it, so the server can tell a sequence jump the device made from a
    /// batch that went missing on the way.
    cursor: [u64; 3],
    /// The RFC 9266 tls-exporter value of the connection the session is on, which its Auth
    /// signs.
    binding: [u8; 32],
    /// The monotonic time the Hello went out, which starts the round trip a server anchor's
    /// quality is measured by.
    hello_at_ms: u64,
    /// The server's wall clock from the Welcome of this authenticated session, until the
    /// shell takes it as an anchor.
    server_time: Option<u64>,
}

/// The uncertainty of a server anchor whose round trip took `rtt_ms`, on a log2 scale:
/// `ceil(log2(rtt_ms + 1))`, so 0 under 1 ms and 10 for about a second (spec 6).
pub fn anchor_quality(rtt_ms: u64) -> u8 {
    (u64::BITS - rtt_ms.leading_zeros()) as u8
}

impl<G: Signer> Session<G> {
    pub fn new(cfg: SessionConfig, signer: G, trust: TrustStore) -> Self {
        Self {
            cfg,
            signer,
            trust,
            phase: Phase::Disconnected,
            state: DeviceState::Unclaimed,
            credit: [0; 3],
            sent_next: [0; 3],
            cursor: [0; 3],
            binding: [0; 32],
            hello_at_ms: 0,
            server_time: None,
        }
    }

    /// After the shell's `TrustAnchor` accepted a new store.
    pub fn set_trust(&mut self, trust: TrustStore) {
        self.trust = trust;
    }

    /// The Hello's version of `kind` from now on. Trust is ignored: it follows `set_trust`.
    pub fn set_running(&mut self, kind: ArtifactKind, version: u32) {
        match kind {
            ArtifactKind::Configuration => self.cfg.config_version = version,
            ArtifactKind::Tables => self.cfg.table_version = version,
            ArtifactKind::Firmware => self.cfg.firmware_version = version,
            ArtifactKind::Trust => {}
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The state the server reported in its Welcome, for display. It does not gate
    /// uploads: the server withholds credit from a device it will not accept data from.
    pub fn state(&self) -> DeviceState {
        self.state
    }

    /// The transport is up. `binding` is the RFC 9266 tls-exporter value of its TLS session,
    /// and `now_ms` the monotonic time the Hello is sent. Returns the Hello to send.
    pub fn on_connected<S: Storage>(
        &mut self,
        log: &DurableLog<S>,
        binding: [u8; 32],
        now_ms: u64,
    ) -> Result<Envelope, StorageError> {
        self.binding = binding;
        self.hello_at_ms = now_ms;
        self.server_time = None;
        self.phase = Phase::AwaitChallenge;
        self.credit = [0; 3];
        let mut cursors = Vec::with_capacity(3);
        for class in Class::ALL {
            cursors.push(Cursor {
                class: class as u32,
                first_retained_seq: log.first_retained_seq(class)?,
                next_seq: log.next_seq(class),
            });
        }
        Ok(Envelope::of(Body::Hello(Hello {
            protocol_versions: vec![PROTOCOL_VERSION],
            device_id: self.cfg.device_id.to_vec(),
            epoch: log.epoch().map(|e| e.to_vec()).unwrap_or_default(),
            cursors,
            firmware_version: self.cfg.firmware_version,
            config_version: self.cfg.config_version,
            table_version: self.cfg.table_version,
            trust_version: self.trust.version,
        })))
    }

    pub fn on_disconnected(&mut self) {
        self.phase = Phase::Disconnected;
        self.credit = [0; 3];
        self.server_time = None;
    }

    /// The server's time from the Welcome of this authenticated session, as an anchor, once.
    /// Call right after `on_message`, with the monotonic time the message arrived (plan
    /// Decision 2); hand the anchor to the recorder.
    pub fn take_anchor(&mut self, now_ms: u64) -> Option<TimeAnchor> {
        let utc_ms = self.server_time.take()?;
        Some(TimeAnchor {
            mono_ms: now_ms,
            utc_ms,
            source: AnchorSource::Server,
            quality: anchor_quality(now_ms.saturating_sub(self.hello_at_ms)),
        })
    }

    pub fn on_message<S: Storage>(
        &mut self,
        msg: Envelope,
        log: &mut DurableLog<S>,
    ) -> Result<Vec<Envelope>, SessionError> {
        let Some(body) = msg.body else {
            // A message kind added after this build. Once the session is up it is ignored,
            // so a newer server can speak to older devices.
            return if self.phase == Phase::Active {
                Ok(Vec::new())
            } else {
                Err(SessionError::Unexpected)
            };
        };
        match (self.phase, body) {
            (Phase::AwaitChallenge, Body::Challenge(challenge)) => {
                // A fixed size, so that this is not a service that signs anything it is sent.
                let nonce: [u8; 32] = challenge
                    .nonce
                    .as_slice()
                    .try_into()
                    .map_err(|_| SessionError::BadChallenge)?;
                // The server proves, for this channel, a key our release keys certified;
                // until it has, this device signs nothing and believes nothing (spec 3.3).
                verify_identity(
                    &self.trust,
                    &challenge.identity_cert,
                    &challenge.identity_sig,
                    &self.binding,
                    &nonce,
                    &self.cfg.device_id,
                    &self.cfg.hostname,
                )
                .map_err(|_| SessionError::BadIdentity)?;
                let message = auth_message(&nonce, &self.cfg.device_id, &self.cfg.hostname, &self.binding);
                let signature = self.signer.sign(&message).to_vec();
                self.phase = Phase::AwaitWelcome;
                Ok(vec![Envelope::of(Body::Auth(Auth { signature }))])
            }
            (Phase::AwaitWelcome, Body::Welcome(welcome)) => {
                // Nothing in a Welcome is believed until its check matches. One flipped bit in
                // a mark can stay inside every bound below and still trim a frame no backup
                // holds, and a flipped epoch would throw away the marks altogether.
                if !welcome.is_intact() {
                    return Err(SessionError::BadCheck);
                }
                if welcome.protocol_version != PROTOCOL_VERSION {
                    return Err(SessionError::BadWelcome);
                }
                let epoch: [u8; 16] = welcome
                    .epoch
                    .as_slice()
                    .try_into()
                    .map_err(|_| SessionError::BadWelcome)?;
                if log.epoch() == Some(epoch) {
                    // Same epoch: the server's marks must describe this log. If they describe
                    // another device's history, skipping to them would discard our own.
                    for mark in &welcome.marks {
                        // A class added after this build: nothing of ours to compare.
                        let Some(class) = Class::from_u32(mark.class) else {
                            continue;
                        };
                        if mark.backed_up_next > mark.committed_next {
                            return Err(SessionError::BadWelcome);
                        }
                        if mark.committed_next == 0 {
                            continue;
                        }
                        // A mark above zero without a chain cannot be checked, and an
                        // unchecked mark must never be trimmed against.
                        let chain =
                            <[u8; 16]>::try_from(mark.chain.as_slice()).map_err(|_| SessionError::BadWelcome)?;
                        if log.lineage(class, mark.committed_next, &chain)? == Lineage::Diverged {
                            return Ok(vec![Envelope::of(Body::Resync(Resync {}))]);
                        }
                    }
                    for class in Class::ALL {
                        let mark = welcome.marks.iter().find(|m| m.class == class as u32);
                        let (committed, backed_up) = mark.map_or((0, 0), |m| (m.committed_next, m.backed_up_next));
                        log.ack(class, committed, backed_up)?;
                        log.rewind(class, committed)?;
                        self.sent_next[class.index()] = committed;
                        self.cursor[class.index()] = committed;
                    }
                } else {
                    log.set_epoch(epoch)?;
                    self.sent_next = [0; 3];
                    self.cursor = [0; 3];
                }
                self.state = welcome.state();
                // Zero is a server with no clock to offer.
                self.server_time = (welcome.server_time_ms != 0).then_some(welcome.server_time_ms);
                self.phase = Phase::Active;
                Ok(Vec::new())
            }
            // Sent by the server alongside a Welcome that was answered with a Resync: its
            // Credits, Acks and Offer. The Offer that follows the next Welcome replaces it.
            // A Chunk answers a Fetch, which no session sends before it is active.
            (Phase::AwaitWelcome, Body::Credit(_) | Body::Ack(_) | Body::Offer(_)) => Ok(Vec::new()),
            // In an active session a message about a class this build does not know is
            // ignored, for the same reason as an unknown message kind.
            (Phase::Active, Body::Ack(ack)) => {
                // Checked before anything else, the class included: the bounds below hold a
                // lying server to what it was sent, but a backup mark raised by one flipped
                // bit can stay inside them and trim a frame no backup holds (ADV-005).
                if !ack.is_intact() {
                    return Err(SessionError::BadCheck);
                }
                let Some(class) = Class::from_u32(ack.class) else {
                    return Ok(Vec::new());
                };
                if ack.backed_up_next > ack.committed_next || ack.committed_next > self.sent_next[class.index()] {
                    return Err(SessionError::BadAck);
                }
                log.ack(class, ack.committed_next, ack.backed_up_next)?;
                Ok(Vec::new())
            }
            (Phase::Active, Body::Rewind(rewind)) => {
                if !rewind.is_intact() {
                    return Err(SessionError::BadCheck);
                }
                let Some(class) = Class::from_u32(rewind.class) else {
                    return Ok(Vec::new());
                };
                // A Rewind only ever asks for something again. One that points above the
                // cursor would step over frames that were never sent: the next batch would
                // raise `sent_next` past them, and an Ack could then trim them unsent.
                let i = class.index();
                if rewind.from_seq > self.cursor[i] {
                    return Err(SessionError::BadRewind);
                }
                log.rewind(class, rewind.from_seq)?;
                self.cursor[i] = rewind.from_seq;
                Ok(Vec::new())
            }
            (Phase::Active, Body::Credit(credit)) => {
                if let Some(class) = Class::from_u32(credit.class) {
                    let i = class.index();
                    self.credit[i] = self.credit[i].saturating_add(i64::try_from(credit.bytes).unwrap_or(i64::MAX));
                }
                Ok(Vec::new())
            }
            // The control lane's: the shell routes these to `Control`.
            (Phase::Active, Body::Offer(_) | Body::Chunk(_)) => Ok(Vec::new()),
            _ => Err(SessionError::Unexpected),
        }
    }

    /// Batches the credit allows, highest class first. Call after every received message and
    /// whenever the recorder has sealed something.
    pub fn poll<S: Storage>(&mut self, log: &mut DurableLog<S>) -> Result<Vec<Envelope>, StorageError> {
        let mut out = Vec::new();
        if self.phase != Phase::Active {
            return Ok(out);
        }
        for class in Class::ALL {
            let i = class.index();
            while let Some(frame) = log.peek_unsent(class)? {
                // A class that still has data blocks every class below it. Any credit at all
                // lets one frame go, however large: a frame bigger than the whole allowance
                // would otherwise never be sent, and would block everything behind it. The
                // frame costs its whole length, as the server counts it, so the balance can
                // go below zero; the server hands the whole length back when it commits.
                if out.len() >= self.cfg.max_batches_per_poll || self.credit[i] <= 0 {
                    return Ok(out);
                }
                let cost = i64::try_from(frame.payload.len()).unwrap_or(i64::MAX);
                self.credit[i] = self.credit[i].saturating_sub(cost);
                self.sent_next[i] = self.sent_next[i].max(frame.end_seq());
                let cursor_seq = self.cursor[i];
                self.cursor[i] = frame.end_seq();
                log.mark_sent(&frame);
                let mut batch = Batch {
                    class: class as u32,
                    first_seq: frame.header.first_seq,
                    count: frame.header.count,
                    format_version: u32::from(frame.header.version),
                    compression: u32::from(frame.header.compression),
                    hash: frame.header.hash.to_vec(),
                    chain: frame.header.chain.to_vec(),
                    block: frame.payload,
                    cursor_seq: Some(cursor_seq),
                    check: Vec::new(),
                };
                batch.check = batch.header_check().to_vec();
                out.push(Envelope::of(Body::Batch(batch)));
            }
        }
        Ok(out)
    }
}
