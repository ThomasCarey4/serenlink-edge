use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use sl_proto::auth::{Signer, auth_message};
use sl_proto::ids::Class;
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
    /// The Welcome was malformed, or named a protocol version that was not offered.
    BadWelcome,
    /// An Ack claimed more than this session has sent, or more backed up than committed.
    BadAck,
    /// A Rewind asked for sequences above the upload cursor: it would skip frames not sent.
    BadRewind,
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
    pub config_version: u32,
    pub table_version: u32,
    pub trust_version: u32,
    /// Upper bound on batches produced by one `poll`.
    pub max_batches_per_poll: usize,
}

/// The device side of one connection, as a state machine with no I/O of its own. The shell
/// feeds it received messages and sends whatever it returns.
pub struct Session<G: Signer> {
    cfg: SessionConfig,
    signer: G,
    phase: Phase,
    state: DeviceState,
    credit: [u64; 3],
    /// One past the highest sequence the server can hold in this session, per class: its
    /// mark at the Welcome, then the end of each batch sent. An Ack beyond it is a lie.
    /// Everything held between the mark and here has been sent: the cursor starts at the
    /// mark, goes forward one frame at a time, and a Rewind can only take it back.
    sent_next: [u64; 3],
    /// Where the upload cursor of each class stands, as a sequence number: the server's mark
    /// at the Welcome, then the end of each batch sent, or where a Rewind put it back to.
    cursor: [u64; 3],
}

impl<G: Signer> Session<G> {
    pub fn new(cfg: SessionConfig, signer: G) -> Self {
        Self {
            cfg,
            signer,
            phase: Phase::Disconnected,
            state: DeviceState::Unclaimed,
            credit: [0; 3],
            sent_next: [0; 3],
            cursor: [0; 3],
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

    /// The transport is up. Returns the Hello to send.
    pub fn on_connected<S: Storage>(&mut self, log: &DurableLog<S>) -> Result<Envelope, StorageError> {
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
            trust_version: self.cfg.trust_version,
        })))
    }

    pub fn on_disconnected(&mut self) {
        self.phase = Phase::Disconnected;
        self.credit = [0; 3];
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
                if challenge.nonce.len() != 32 {
                    return Err(SessionError::BadChallenge);
                }
                let message = auth_message(&challenge.nonce, &self.cfg.device_id, &self.cfg.hostname);
                let signature = self.signer.sign(&message).to_vec();
                self.phase = Phase::AwaitWelcome;
                Ok(vec![Envelope::of(Body::Auth(Auth { signature }))])
            }
            (Phase::AwaitWelcome, Body::Welcome(welcome)) => {
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
                self.phase = Phase::Active;
                Ok(Vec::new())
            }
            // Sent by the server alongside a Welcome that was answered with a Resync.
            (Phase::AwaitWelcome, Body::Credit(_) | Body::Ack(_)) => Ok(Vec::new()),
            // In an active session a message about a class this build does not know is
            // ignored, for the same reason as an unknown message kind.
            (Phase::Active, Body::Ack(ack)) => {
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
                    self.credit[i] = self.credit[i].saturating_add(credit.bytes);
                }
                Ok(Vec::new())
            }
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
                // would otherwise never be sent, and would block everything behind it.
                if out.len() >= self.cfg.max_batches_per_poll || self.credit[i] == 0 {
                    return Ok(out);
                }
                self.credit[i] = self.credit[i].saturating_sub(frame.payload.len() as u64);
                self.sent_next[i] = self.sent_next[i].max(frame.end_seq());
                self.cursor[i] = frame.end_seq();
                log.mark_sent(&frame);
                out.push(Envelope::of(Body::Batch(Batch {
                    class: class as u32,
                    first_seq: frame.header.first_seq,
                    count: frame.header.count,
                    format_version: u32::from(frame.header.version),
                    compression: u32::from(frame.header.compression),
                    hash: frame.header.hash.to_vec(),
                    chain: frame.header.chain.to_vec(),
                    block: frame.payload,
                })));
            }
        }
        Ok(out)
    }
}
