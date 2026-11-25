//! The agent's loop (agent spec 3.8): SignalK into the device, the device's seals on a 200 ms
//! tick, and its session over one WebSocket at a time, until SIGTERM or SIGINT.
//!
//! A storage error is a reboot, as in the simulator's boat: the loop closes the socket and
//! `run` returns an error, so the process exits non-zero and systemd starts a new boot that
//! reopens and recovers the log.
//!
//! Recording never waits on the network or the disk: SignalK is read, and its updates stamped
//! as they arrive, on a thread of its own (started before the log is opened), into a bounded
//! queue that the loop records from; and a gateway connection writes on its own task through a
//! bounded queue (`Link`). A full queue, a send that waits longer than the gateway's idle
//! timeout, or a gateway silent that long drops the session, which the device rewinds on its
//! next Hello.
//!
//! A log that cannot be opened is set aside as `log.broken-<secs>` and a fresh one started,
//! once per process (`open_device`), so a damaged log does not become a restart loop.
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use sl_core::device::{Device, DeviceConfig, OpenDeviceError};
use sl_core::log::Recovery;
use sl_core::recorder::RecorderConfig;
use sl_core::session::SessionError;
use sl_proto::auth::{KeySigner, Signer as _};
use sl_proto::compress::Compression;
use sl_proto::ids::Class;
use sl_proto::trust::SignedTrustStore;
use sl_proto::wire::{Body, Envelope};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior, interval, sleep_until, timeout, timeout_at};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{self, Message};

use crate::clock::Clock;
use crate::defines::{Defines, to_value};
use crate::file_store::{FileStore, create_dir_durable};
use crate::identity::{CLOCK_SET_AFTER, load_or_create_seed, resolve_boot};
use crate::policy::Policy;
use crate::signalk::{Update, names, parse_delta, sources_url};
use crate::sink::AgentSink;
use crate::transport::{Ws, connect, tls_config};

/// What the agent runs of each kind, by `ArtifactKind::index`: as the simulator's boat.
pub const RUNNING: [u32; 4] = [0, 1, 1, 0];
const TICK_MS: u64 = 200;
const NTP_EVERY: Duration = Duration::from_secs(600);
const FILL_EVERY: Duration = Duration::from_secs(86_400);
const STOP_WITHIN: Duration = Duration::from_secs(10);
const SIGNALK_IDLE: Duration = Duration::from_secs(60);
const CONNECT_WITHIN: Duration = Duration::from_secs(15);
const BACKOFF_FIRST: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// A session that lasts this long resets the backoff; one that is welcomed and then lost
/// sooner (a gateway that refuses after the handshake, say) keeps it growing.
const STAYED_UP: Duration = Duration::from_secs(60);
/// The sources document is fetched at most this often.
const NAMES_EVERY: Duration = Duration::from_secs(60);
const INTAKE: usize = 8_192;
/// The gateway's idle timeout (`sl-gateway serve --idle-secs`, default 90; it pings every 30):
/// a gateway heard from for no longer than this is gone, and so is a send that waits this long.
const GATEWAY_IDLE: Duration = Duration::from_secs(90);
/// Messages queued for a connection's writer. The device sends only what the gateway's credit
/// allows, so this fills only when the uplink has stopped; then the session is dropped.
const OUT_QUEUE: usize = 1_024;

#[derive(Parser, Debug, Clone)]
#[command(about = "SerenLink agent: records a SignalK server into the durable log and uploads it")]
pub struct Args {
    /// The gateway's name: TLS checks it and the session signs it.
    #[arg(long)]
    pub hostname: Option<String>,
    /// Where to connect, host:port; default the hostname on 443.
    #[arg(long)]
    pub addr: Option<String>,
    /// The private CA's root, PEM.
    #[arg(long)]
    pub ca: Option<PathBuf>,
    /// The baseline trust store (a signed store file).
    #[arg(long)]
    pub trust_store: Option<PathBuf>,
    /// This device's id, 16 bytes of hex.
    #[arg(long)]
    pub device_id: Option<String>,
    #[arg(long, default_value = "/var/lib/sl-agent")]
    pub state_dir: PathBuf,
    /// Most bytes the log may hold.
    #[arg(long, default_value_t = 4 * 1024 * 1024 * 1024)]
    pub capacity: u64,
    #[arg(long, default_value = "ws://localhost:3000/signalk/v1/stream")]
    pub signalk_url: String,
    /// Make the device key if there is none, print its public key in hex, and exit.
    #[arg(long)]
    pub print_pubkey: bool,
}

fn need<T: Clone>(v: &Option<T>, flag: &str) -> Result<T, String> {
    v.clone().ok_or_else(|| format!("--{flag} is required"))
}

pub fn print_pubkey(args: &Args) -> Result<(), String> {
    create_dir_durable(&args.state_dir).map_err(|e| format!("{}: {e}", args.state_dir.display()))?;
    let seed = load_or_create_seed(&args.state_dir.join("device.seed")).map_err(|e| e.to_string())?;
    println!("{}", hex::encode(KeySigner::from_seed(seed).public_key()));
    Ok(())
}

type Connecting = Pin<Box<dyn Future<Output = Result<(Ws, [u8; 32]), String>>>>;

/// Read SignalK on a thread of its own, so that nothing the loop waits on (opening the log, a
/// rewind, an fsync) delays an update's arrival stamp. The thread ends when the loop drops its
/// receiver.
fn spawn_signalk(url: String, clock: Clock, tx: mpsc::Sender<(Update, u64, u64)>) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("the SignalK runtime: {e}"))?;
    std::thread::Builder::new()
        .name("signalk".into())
        .spawn(move || rt.block_on(signalk(url, clock, tx)))
        .map_err(|e| format!("the SignalK thread: {e}"))?;
    Ok(())
}

/// SignalK into `tx` for ever, reconnecting with backoff. `$source` NAMEs come from the sources
/// document, fetched on a task of its own when a source appears that the last document did
/// not name, at most once a minute; a source that a fetch it started still did not name (one
/// that is not on NMEA 2000, say) starts no other fetch until SignalK reconnects. An update
/// whose source is not named yet goes with NAME 0. An update that finds the channel full is
/// dropped and counted. Each update goes with its NAME and the time it arrived, on the agent's
/// clock.
async fn signalk(url: String, clock: Clock, tx: mpsc::Sender<(Update, u64, u64)>) {
    let mut backoff = Duration::from_secs(1);
    let names_url = sources_url(&url);
    let known: Arc<Mutex<HashMap<String, u64>>> = Arc::default();
    let mut dropped: u64 = 0;
    let mut dropped_logged: Option<Instant> = None;
    loop {
        match tokio_tungstenite::connect_async(url.as_str()).await {
            Ok((mut ws, _)) => {
                eprintln!("SignalK connected: {url}");
                backoff = Duration::from_secs(1);
                // A new connection may fetch the names again for any source.
                let mut fetched_at: Option<Instant> = None;
                let mut asked: HashSet<String> = HashSet::new();
                loop {
                    let msg = match tokio::time::timeout(SIGNALK_IDLE, ws.next()).await {
                        Ok(Some(Ok(m))) => m,
                        Ok(Some(Err(e))) => {
                            eprintln!("SignalK: {e}");
                            break;
                        }
                        Ok(None) => break,
                        Err(_) => {
                            eprintln!("SignalK: nothing for {SIGNALK_IDLE:?}, reconnecting");
                            break;
                        }
                    };
                    let mono = clock.mono_ms();
                    let Message::Text(text) = msg else { continue };
                    for u in parse_delta(text.as_str()) {
                        let name = known.lock().unwrap_or_else(|e| e.into_inner()).get(&u.source).copied();
                        if name.is_none()
                            && !asked.contains(&u.source)
                            && fetched_at.is_none_or(|t| t.elapsed() >= NAMES_EVERY)
                            && let Some(src_url) = &names_url
                        {
                            fetched_at = Some(Instant::now());
                            asked.insert(u.source.clone());
                            tokio::spawn(fetch_names(src_url.clone(), known.clone()));
                        }
                        match tx.try_send((u, name.unwrap_or(0), mono)) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                // The device loop is far behind: dropping is the intake budget.
                                dropped += 1;
                                if dropped_logged.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
                                    dropped_logged = Some(Instant::now());
                                    eprintln!("SignalK intake full: {dropped} updates dropped so far");
                                }
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => return,
                        }
                    }
                }
            }
            Err(e) => eprintln!("SignalK {url}: {e}"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// Fetch the sources document and, if it came, make its NAMEs the known ones.
async fn fetch_names(url: String, known: Arc<Mutex<HashMap<String, u64>>>) {
    let doc = tokio::task::spawn_blocking(move || {
        ureq::get(&url)
            .timeout(Duration::from_secs(5))
            .call()
            .ok()?
            .into_json::<serde_json::Value>()
            .ok()
    })
    .await
    .ok()
    .flatten();
    if let Some(doc) = doc {
        *known.lock().unwrap_or_else(|e| e.into_inner()) = names(&doc);
    }
}

/// `d` lengthened by up to a quarter, by `r` (any value; `r % 1000` is used).
fn jittered(d: Duration, r: u64) -> Duration {
    d + d.mul_f64((r % 1000) as f64 / 4000.0)
}

fn jitter(d: Duration) -> Duration {
    use std::hash::{BuildHasher, Hasher};
    // Each RandomState is freshly keyed: a random u64 with no extra dependency.
    let r = std::collections::hash_map::RandomState::new().build_hasher().finish();
    jittered(d, r)
}

/// What a connection has for the loop.
enum LinkEvent {
    Msg(Option<Result<Message, tungstenite::Error>>),
    /// The writer stopped: a send failed or waited `GATEWAY_IDLE`.
    WriterEnded(String),
    /// Nothing heard from the gateway for `GATEWAY_IDLE`: the connection is half-open.
    Silent,
}

/// One gateway connection: read here, written by its own task through a bounded queue.
struct Link<T> {
    read: SplitStream<WebSocketStream<T>>,
    out: mpsc::Sender<Message>,
    writer: JoinHandle<Result<(), String>>,
    heard: Instant,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Link<T> {
    fn new(ws: WebSocketStream<T>) -> Self {
        let (sink, read) = ws.split();
        let (out, rx) = mpsc::channel(OUT_QUEUE);
        Self {
            read,
            out,
            writer: tokio::spawn(write(sink, rx)),
            heard: Instant::now(),
        }
    }

    /// Queue `out` without waiting. An error means a frame did not go: drop the session, so
    /// the device rewinds to it on the next Hello.
    fn queue(&self, out: Vec<Envelope>) -> Result<(), &'static str> {
        for env in out {
            self.out
                .try_send(Message::Binary(env.encode_to_vec().into()))
                .map_err(|e| match e {
                    mpsc::error::TrySendError::Full(_) => "the send queue is full",
                    mpsc::error::TrySendError::Closed(_) => "the writer has stopped",
                })?;
        }
        Ok(())
    }

    /// The next thing to act on. Cancel-safe: a select may drop it at any await.
    async fn next(&mut self) -> LinkEvent {
        tokio::select! {
            m = self.read.next() => {
                if matches!(m, Some(Ok(_))) {
                    self.heard = Instant::now();
                }
                LinkEvent::Msg(m)
            }
            r = &mut self.writer => LinkEvent::WriterEnded(match r {
                Ok(Ok(())) => "the writer ended".into(),
                Ok(Err(e)) => e,
                Err(e) => format!("the writer failed: {e}"),
            }),
            _ = sleep_until(self.heard + GATEWAY_IDLE) => LinkEvent::Silent,
        }
    }

    /// Drop the connection now, whatever is queued.
    fn abort(self) {
        self.writer.abort();
    }

    /// Send what is queued, then a Close, by `deadline`.
    async fn finish(self, deadline: Instant) {
        let Self { out, mut writer, .. } = self;
        drop(out);
        if timeout_at(deadline, &mut writer).await.is_err() {
            writer.abort();
        }
    }
}

/// A connection's writer: each send bounded by `GATEWAY_IDLE`; when the queue closes, a Close.
async fn write<T: AsyncRead + AsyncWrite + Unpin>(
    mut sink: SplitSink<WebSocketStream<T>, Message>,
    mut rx: mpsc::Receiver<Message>,
) -> Result<(), String> {
    while let Some(m) = rx.recv().await {
        match timeout(GATEWAY_IDLE, sink.send(m)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("sending: {e}")),
            Err(_) => return Err(format!("a send waited {GATEWAY_IDLE:?}")),
        }
    }
    let _ = timeout(Duration::from_secs(1), sink.close()).await;
    Ok(())
}

/// The reconnect schedule: a failed attempt or a lost session waits the backoff (jittered),
/// which doubles to five minutes; a session that stayed up `STAYED_UP` after its Welcome
/// resets it.
struct Retry {
    at: Instant,
    backoff: Duration,
    welcomed_at: Option<Instant>,
}

impl Retry {
    fn new() -> Self {
        Self {
            at: Instant::now(),
            backoff: BACKOFF_FIRST,
            welcomed_at: None,
        }
    }

    fn failed(&mut self) {
        let now = Instant::now();
        if self.welcomed_at.take().is_some_and(|t| now - t >= STAYED_UP) {
            self.backoff = BACKOFF_FIRST;
        }
        self.at = now + jitter(self.backoff);
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
    }

    fn welcomed(&mut self) {
        self.welcomed_at = Some(Instant::now());
    }
}

pub type AgentDevice = Device<FileStore, AgentSink>;

/// Record one SignalK update, if the policy keeps it.
fn record(dev: &mut AgentDevice, policy: &mut Policy, defines: &mut Defines, (u, name, at): (Update, u64, u64)) {
    if let Some(class) = policy.decide(&u.path, &u.value, at)
        && let Some(value) = to_value(&u.path, &u.value)
    {
        let def = defines.get(&u.path, name, value.value_type()).clone();
        dev.sample(class, &def, at, value);
    }
}

/// Why `open_device` failed.
#[derive(Debug)]
pub enum OpenFailure {
    /// The log itself: its files, or what is in them.
    Log(String),
    /// Anything else, which a fresh log would not mend (the baseline trust store).
    Other(String),
}

/// Open the device over the log in `dir`.
pub fn open_log(
    dir: &Path,
    capacity: u64,
    cfg: DeviceConfig,
    baseline: &SignedTrustStore,
) -> Result<(AgentDevice, Recovery), OpenFailure> {
    let store = FileStore::open(dir, capacity).map_err(|e| OpenFailure::Log(format!("{}: {e}", dir.display())))?;
    Device::open(cfg, store, AgentSink::default(), baseline).map_err(|e| match e {
        OpenDeviceError::Storage(e) => OpenFailure::Log(format!("{}: reading the log: {e:?}", dir.display())),
        OpenDeviceError::Trust(e) => OpenFailure::Other(format!("the baseline trust store: {e:?}")),
    })
}

/// Copy the trust store slots of the log at `old` into `fresh`, each only if it holds an intact
/// store newer than `baseline` (as `TrustAnchor::open` would take it). Returns how many went.
/// The old log will not open, so its slot files are read directly.
fn carry_trust(old: &Path, fresh: &mut FileStore, baseline: &SignedTrustStore) -> Result<usize, String> {
    use sl_core::mem_storage::MemStorage;
    use sl_core::storage::Storage as _;
    use sl_core::trust::{TRUST_SLOTS, TrustAnchor};
    let version = |m: &MemStorage| TrustAnchor::open(m, baseline).ok().map(|a| a.active().version);
    let Some(base) = version(&MemStorage::new(0)) else {
        return Ok(0);
    };
    let mut carried = 0;
    for slot in TRUST_SLOTS {
        let Ok(bytes) = std::fs::read(old.join("meta").join(slot.to_string())) else {
            continue;
        };
        let mut probe = MemStorage::new(0);
        if probe.write_meta(slot, &bytes).is_err() || version(&probe).is_none_or(|v| v <= base) {
            continue;
        }
        fresh
            .write_meta(slot, &bytes)
            .map_err(|e| format!("copying trust slot {slot}: {e:?}"))?;
        carried += 1;
    }
    Ok(carried)
}

/// Open the device over `state/log`. A log that will not open is set aside, once: a fresh
/// log is made beside it first (so a full or read-only disk leaves the old log where it is),
/// then the old one is renamed `log.broken-<now_secs>` and the fresh one put in its place.
/// Returns where the broken log went, if it was moved.
pub fn open_device(
    state: &Path,
    capacity: u64,
    cfg: DeviceConfig,
    baseline: &SignedTrustStore,
    now_secs: u64,
) -> Result<(AgentDevice, Recovery, Option<PathBuf>), String> {
    let log = state.join("log");
    let first = match open_log(&log, capacity, cfg.clone(), baseline) {
        Ok((dev, recovery)) => return Ok((dev, recovery, None)),
        Err(OpenFailure::Other(e)) => return Err(e),
        Err(OpenFailure::Log(e)) => e,
    };
    // `<3>`: journald's error priority.
    eprintln!("<3>sl-agent: ERROR: the log will not open: {first}");
    let fresh = state.join(format!("log.new-{now_secs}"));
    if fresh.exists() {
        std::fs::remove_dir_all(&fresh).map_err(|e| format!("{}: {e}", fresh.display()))?;
    }
    let made = FileStore::open(&fresh, capacity)
        .map_err(|e| e.to_string())
        .and_then(|mut store| carry_trust(&log, &mut store, baseline));
    let carried = match made {
        Ok(n) => n,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&fresh);
            return Err(format!(
                "the log will not open ({first}), and a fresh one cannot be made beside it ({e}); left as it is"
            ));
        }
    };
    if carried > 0 {
        eprintln!("sl-agent: carried {carried} trust store slot(s) from the old log into the fresh one");
    }
    let mut broken = state.join(format!("log.broken-{now_secs}"));
    let mut n = 1;
    while broken.exists() {
        broken = state.join(format!("log.broken-{now_secs}-{n}"));
        n += 1;
    }
    let moved = std::fs::rename(&log, &broken)
        .and_then(|()| std::fs::rename(&fresh, &log))
        .and_then(|()| std::fs::File::open(state)?.sync_all());
    if let Err(e) = moved {
        return Err(format!("setting the log aside as {}: {e}", broken.display()));
    }
    eprintln!(
        "<3>sl-agent: ERROR: the log was moved to {} and a fresh log started; what it held that \
         was not yet uploaded is in it, and will not be sent (see ops/sl-agent/ROLLOUT.md)",
        broken.display()
    );
    match open_log(&log, capacity, cfg, baseline) {
        Ok((dev, recovery)) => Ok((dev, recovery, Some(broken))),
        Err(OpenFailure::Log(e) | OpenFailure::Other(e)) => Err(format!("the fresh log will not open either: {e}")),
    }
}

/// The wall clock in seconds, once it is set: waits (blocking) until then, saying so once a
/// minute. Only a damaged or lost boot counter needs it.
fn wait_for_clock() -> u64 {
    let mut said: Option<std::time::Instant> = None;
    loop {
        let now = unix_secs();
        if now >= CLOCK_SET_AFTER {
            return now;
        }
        if said.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
            said = Some(std::time::Instant::now());
            eprintln!(
                "<4>sl-agent: the boot counter must restart from the wall clock, which is not set; \
                 waiting (SignalK is queued meanwhile)"
            );
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// The newest boot id in the log at `dir`: the boot of the newest readable frame of each class.
/// `None` when there is no log or it will not open.
pub fn highest_boot_in_log(dir: &Path) -> Option<u32> {
    use sl_core::log::DurableLog;
    if !dir.is_dir() {
        return None;
    }
    let store = FileStore::open(dir, u64::MAX).ok()?;
    let (mut log, _) = DurableLog::open(store).ok()?;
    let mut best = None;
    for class in Class::ALL {
        let next = log.next_seq(class);
        if next == 0 || log.rewind(class, next - 1).is_err() {
            continue;
        }
        let Ok(Some(frame)) = log.peek_unsent(class) else {
            continue;
        };
        let boot = Compression::from_u8(frame.header.compression)
            .and_then(|c| sl_proto::compress::decompress(c, &frame.payload, 16 << 20).ok())
            .and_then(|raw| sl_proto::block::Block::decode(&raw).ok())
            .map(|b| b.boot_id);
        best = best.max(boot);
    }
    best
}

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// What one turn of the loop decided beyond its own arm.
enum Turn {
    /// Carry on, and let the session send what it may.
    Poll,
    /// Carry on; nothing for the session to send.
    Skip,
    /// The log failed: end the process (a new boot recovers it).
    Fatal(String),
}

pub async fn run(args: Args) -> Result<(), String> {
    let hostname = need(&args.hostname, "hostname")?;
    let addr = args.addr.clone().unwrap_or_else(|| format!("{hostname}:443"));
    let tls = tls_config(&need(&args.ca, "ca")?)?;
    let trust_path = need(&args.trust_store, "trust-store")?;
    let baseline = std::fs::read(&trust_path)
        .map_err(|e| format!("{}: {e}", trust_path.display()))
        .and_then(|b| SignedTrustStore::from_bytes(&b).map_err(|e| format!("{}: {e:?}", trust_path.display())))?;
    let device_id: [u8; 16] = hex::decode(need(&args.device_id, "device-id")?)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("--device-id: 16 bytes of hex")?;
    let state = &args.state_dir;
    create_dir_durable(state).map_err(|e| format!("{}: {e}", state.display()))?;
    let seed = load_or_create_seed(&state.join("device.seed")).map_err(|e| e.to_string())?;
    let clock = Clock::start();
    // SignalK is read from here on, whatever resolving the boot id or opening the log costs:
    // its updates are stamped on this process's timeline and queue until the loop runs.
    let (tx, mut rx) = mpsc::channel::<(Update, u64, u64)>(INTAKE);
    spawn_signalk(args.signalk_url.clone(), clock, tx)?;
    // Blocking here is fine: nothing else runs on this runtime yet, and SignalK has its own.
    let boot = resolve_boot(state, &mut wait_for_clock, &mut || {
        highest_boot_in_log(&state.join("log"))
    })
    .map_err(|e| format!("the boot counter: {e}"))?;
    if let Some(why) = &boot.restarted {
        eprintln!(
            "<3>sl-agent: ERROR: the boot counter: {why}; restarted from the wall clock at {}",
            boot.id
        );
    }
    let boot_id = boot.id;
    let cfg = DeviceConfig {
        device_id,
        seed,
        hostname: hostname.clone(),
        boot_id,
        running: RUNNING,
        recorder: RecorderConfig {
            compression: Compression::Zstd,
            table_version: 1,
            ..RecorderConfig::default()
        },
        max_batches_per_poll: 32,
        control_lane: true,
    };
    let (mut dev, recovery, _) = open_device(state, args.capacity, cfg, &baseline, unix_secs())?;
    let mut sealed = Vec::new();
    if let Err(e) = dev.report_recovery(&recovery, clock.mono_ms(), &mut sealed) {
        eprintln!("declaring the losses found at open failed ({e:?}); the next tick declares them");
    }
    eprintln!(
        "boot {boot_id}; log P0 {} P1 {} P2 {} records; torn bytes {:?}; {} corrupt ranges",
        dev.log().next_seq(Class::P0),
        dev.log().next_seq(Class::P1),
        dev.log().next_seq(Class::P2),
        recovery.truncated_bytes,
        recovery.corrupt.len()
    );
    if let Some(a) = clock.ntp_anchor() {
        dev.anchor(a);
    }

    let mut policy = Policy::new();
    let mut defines = Defines::new();
    let mut tick = interval(Duration::from_millis(TICK_MS));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut ntp = interval(NTP_EVERY);
    ntp.tick().await;
    let mut fill = interval(FILL_EVERY);
    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
    let mut link: Option<Link<Tls>> = None;
    let mut connecting: Option<Connecting> = None;
    let mut retry = Retry::new();
    let mut welcomed = false;

    loop {
        if link.is_none() && connecting.is_none() && Instant::now() >= retry.at {
            let (addr, hostname, tls) = (addr.clone(), hostname.clone(), tls.clone());
            connecting = Some(Box::pin(async move {
                match tokio::time::timeout(CONNECT_WITHIN, connect(&addr, &hostname, tls)).await {
                    Ok(r) => r,
                    Err(_) => Err(format!("no connection within {CONNECT_WITHIN:?}")),
                }
            }));
        }
        let turn = tokio::select! {
            _ = term.recv() => break,
            _ = int.recv() => break,
            r = rx.recv() => match r {
                Some(update) => {
                    record(&mut dev, &mut policy, &mut defines, update);
                    // A sample never makes a frame sendable; the tick polls.
                    Turn::Skip
                }
                None => Turn::Fatal("the SignalK reader stopped".into()),
            },
            _ = tick.tick() => {
                sealed.clear();
                match dev.tick(clock.mono_ms(), &mut sealed) {
                    Ok(()) => Turn::Poll,
                    Err(e) => Turn::Fatal(format!("sealing failed: {e:?}")),
                }
            }
            _ = ntp.tick() => {
                if let Some(a) = clock.ntp_anchor() {
                    dev.anchor(a);
                }
                Turn::Skip
            }
            _ = fill.tick() => {
                let log = dev.log();
                eprintln!(
                    "log fill: {} of {} bytes; P0 {}..{} P1 {}..{} P2 {}..{}",
                    log.used(), args.capacity,
                    log.committed_next(Class::P0), log.next_seq(Class::P0),
                    log.committed_next(Class::P1), log.next_seq(Class::P1),
                    log.committed_next(Class::P2), log.next_seq(Class::P2),
                );
                Turn::Skip
            }
            r = async { connecting.as_mut().unwrap().await }, if connecting.is_some() => {
                connecting = None;
                match r {
                    Ok((socket, binding)) => match dev.connect(binding, clock.mono_ms()) {
                        Some(hello) => {
                            let l = Link::new(socket);
                            if let Err(e) = l.queue(vec![hello]) {
                                l.abort();
                                lose(&mut link, &mut dev, &mut retry, e);
                            } else {
                                link = Some(l);
                                welcomed = false;
                            }
                            Turn::Skip
                        }
                        None => Turn::Fatal("the log could not be read to say Hello".into()),
                    },
                    Err(e) => {
                        eprintln!("gateway {addr}: {e}");
                        retry.failed();
                        Turn::Skip
                    }
                }
            }
            ev = async { link.as_mut().unwrap().next().await }, if link.is_some() => {
                let env = match ev {
                    LinkEvent::Msg(Some(Ok(Message::Binary(b)))) => Ok(Envelope::decode(b.as_ref()).ok()),
                    LinkEvent::Msg(Some(Ok(Message::Close(f)))) => Err(format!("gateway closed: {f:?}")),
                    // Text, Ping, Pong: tungstenite answers pings itself.
                    LinkEvent::Msg(Some(Ok(_))) => Ok(None),
                    LinkEvent::Msg(Some(Err(e))) => Err(format!("gateway: {e}")),
                    LinkEvent::Msg(None) => Err("gateway: connection ended".into()),
                    LinkEvent::WriterEnded(e) => Err(format!("gateway: {e}")),
                    LinkEvent::Silent => Err(format!("gateway: nothing heard for {GATEWAY_IDLE:?}")),
                };
                match env {
                    Ok(None) => Turn::Skip,
                    Err(e) => {
                        lose(&mut link, &mut dev, &mut retry, &e);
                        Turn::Skip
                    }
                    Ok(Some(env)) => {
                        let is_welcome = matches!(env.body, Some(Body::Welcome(_)));
                        match dev.receive(env, clock.mono_ms()) {
                            Ok(out) => {
                                if is_welcome && !welcomed {
                                    welcomed = true;
                                    retry.welcomed();
                                    eprintln!("Welcome received: device {:?}", dev.state());
                                }
                                if let Err(e) = link.as_ref().unwrap().queue(out) {
                                    lose(&mut link, &mut dev, &mut retry, e);
                                    Turn::Skip
                                } else {
                                    Turn::Poll
                                }
                            }
                            Err(SessionError::Storage(e)) => Turn::Fatal(format!("the log failed in the session: {e:?}")),
                            Err(e) => {
                                lose(&mut link, &mut dev, &mut retry, &format!("session ended: {e:?}"));
                                Turn::Skip
                            }
                        }
                    }
                }
            }
        };
        let fault = match turn {
            Turn::Fatal(e) => Some(e),
            Turn::Skip => None,
            // Whatever the session may send now: batches the credit allows, reports, a Fetch.
            Turn::Poll => match link.as_ref() {
                Some(l) if dev.connected() => {
                    let out = dev.poll();
                    if let Some(e) = dev.take_storage_fault() {
                        Some(format!("reading the log failed: {e:?}"))
                    } else {
                        if let Err(e) = l.queue(out) {
                            lose(&mut link, &mut dev, &mut retry, e);
                        }
                        None
                    }
                }
                _ => None,
            },
        };
        if let Some(e) = fault {
            eprintln!("{e}; ending this boot so the next one starts afresh");
            if let Some(l) = link.take() {
                l.abort();
            }
            dev.disconnect();
            return Err(e);
        }
    }

    // A second signal during the stop exits at once.
    tokio::spawn(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        eprintln!("second signal: exiting now");
        std::process::exit(1);
    });

    // Clean stop: record what SignalK has already sent, seal, send what the credit allows, close.
    let deadline = Instant::now() + STOP_WITHIN;
    rx.close();
    while let Ok(update) = rx.try_recv() {
        record(&mut dev, &mut policy, &mut defines, update);
    }
    sealed.clear();
    if let Err(e) = dev.flush(clock.mono_ms(), &mut sealed) {
        eprintln!("sealing at stop failed: {e:?}");
        if let Some(l) = link.take() {
            l.abort();
        }
        dev.disconnect();
        return Err(format!("sealing at stop failed: {e:?}"));
    }
    eprintln!(
        "sealed through P0 {} P1 {} P2 {}",
        dev.log().next_seq(Class::P0),
        dev.log().next_seq(Class::P1),
        dev.log().next_seq(Class::P2)
    );
    let mut fault = None;
    if let Some(l) = link.take() {
        if dev.connected() {
            let out = dev.poll();
            fault = dev.take_storage_fault();
            let _ = l.queue(out);
        }
        l.finish(deadline).await;
    }
    dev.disconnect();
    if let Some(e) = fault {
        eprintln!("reading the log at stop failed: {e:?}");
        return Err(format!("reading the log at stop failed: {e:?}"));
    }
    eprintln!("stopped cleanly");
    Ok(())
}

type Tls = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

/// The session is lost: drop the connection at once, tell the device (which rewinds to its
/// upload cursor on the next Hello), and wait the backoff.
fn lose(link: &mut Option<Link<Tls>>, dev: &mut AgentDevice, retry: &mut Retry, why: &str) {
    eprintln!("{why}");
    if let Some(l) = link.take() {
        l.abort();
    }
    dev.disconnect();
    retry.failed();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_adds_at_most_a_quarter() {
        let d = Duration::from_secs(8);
        assert_eq!(jittered(d, 0), d);
        assert_eq!(jittered(d, 1000), d);
        assert_eq!(jittered(d, 500), Duration::from_secs(9));
        assert!(jittered(d, 999) < d + d / 4);
        assert!(jittered(d, u64::MAX) <= d + d / 4);
        // Not stuck at one value, as a clock with microsecond resolution would make it.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            seen.insert(jitter(d));
        }
        assert!(seen.len() > 10, "{seen:?}");
    }

    /// A client `Link` and the gateway's end of an in-memory WebSocket with `buf` bytes of
    /// buffer each way.
    async fn pair(buf: usize) -> (Link<tokio::io::DuplexStream>, WebSocketStream<tokio::io::DuplexStream>) {
        let (a, b) = tokio::io::duplex(buf);
        let (client, server) = tokio::join!(
            tokio_tungstenite::client_async("ws://ingest.sim/", a),
            tokio_tungstenite::accept_async(b)
        );
        (Link::new(client.unwrap().0), server.unwrap())
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_gateway_is_dropped_after_its_idle_timeout() {
        let (mut link, mut gw) = pair(4096).await;
        let start = Instant::now();
        gw.send(Message::Binary(vec![1].into())).await.unwrap();
        assert!(matches!(
            link.next().await,
            LinkEvent::Msg(Some(Ok(Message::Binary(_))))
        ));
        // Heard at start + 30 s; silent from then on.
        tokio::time::advance(Duration::from_secs(30)).await;
        gw.send(Message::Ping(vec![].into())).await.unwrap();
        assert!(matches!(link.next().await, LinkEvent::Msg(Some(Ok(Message::Ping(_))))));
        assert!(matches!(link.next().await, LinkEvent::Silent));
        assert_eq!(Instant::now() - start, Duration::from_secs(30) + GATEWAY_IDLE);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_uplink_never_waits_the_caller_and_ends_the_writer() {
        // The gateway never reads; it keeps talking, so the link is not silent.
        let (mut link, mut gw) = pair(256).await;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                if gw.send(Message::Text("still here".into())).await.is_err() {
                    break;
                }
            }
        });
        let env = Envelope { body: None };
        // Queueing returns at once while the writer is stuck, then reports the queue full.
        let start = Instant::now();
        let mut full = false;
        for _ in 0..2 * OUT_QUEUE {
            if link.queue(vec![env.clone(); 1]).is_err() {
                full = true;
                break;
            }
        }
        assert!(full, "the queue never filled");
        assert_eq!(Instant::now(), start);
        let ended = loop {
            match link.next().await {
                LinkEvent::Msg(Some(Ok(_))) => continue,
                other => break other,
            }
        };
        match ended {
            LinkEvent::WriterEnded(e) => assert!(e.contains("waited"), "{e}"),
            LinkEvent::Silent => panic!("silent"),
            LinkEvent::Msg(m) => panic!("{m:?}"),
        }
        assert!(Instant::now() - start >= GATEWAY_IDLE);
        assert!(link.queue(vec![env]).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_doubles_to_five_minutes_and_only_a_session_that_stays_up_resets_it() {
        let mut r = Retry::new();
        assert!(Instant::now() >= r.at);
        r.failed();
        assert!(r.at > Instant::now());
        assert!(r.at <= Instant::now() + Duration::from_millis(1250));
        for _ in 0..20 {
            r.failed();
        }
        assert_eq!(r.backoff, BACKOFF_MAX);
        assert!(r.at <= Instant::now() + BACKOFF_MAX + BACKOFF_MAX / 4);
        // Welcomed, then lost within the minute: the backoff stands.
        r.welcomed();
        tokio::time::advance(STAYED_UP - Duration::from_secs(1)).await;
        r.failed();
        assert!(r.at >= Instant::now() + BACKOFF_MAX);
        assert_eq!(r.backoff, BACKOFF_MAX);
        // A failed connect after a lost session is not a session that stayed up.
        tokio::time::advance(STAYED_UP * 2).await;
        r.failed();
        assert_eq!(r.backoff, BACKOFF_MAX);
        // Welcomed and up for the minute: the next loss waits the first backoff.
        r.welcomed();
        tokio::time::advance(STAYED_UP).await;
        r.failed();
        assert!(r.at <= Instant::now() + BACKOFF_FIRST + BACKOFF_FIRST / 4);
        assert_eq!(r.backoff, BACKOFF_FIRST * 2);
    }

    #[test]
    fn the_flags_and_their_defaults() {
        let a = Args::try_parse_from(["sl-agent"]).unwrap();
        assert_eq!(a.state_dir, PathBuf::from("/var/lib/sl-agent"));
        assert_eq!(a.capacity, 4 * 1024 * 1024 * 1024);
        assert_eq!(a.signalk_url, "ws://localhost:3000/signalk/v1/stream");
        assert!(!a.print_pubkey && a.hostname.is_none());
        let a = Args::try_parse_from([
            "sl-agent",
            "--hostname",
            "ingest.sim",
            "--addr",
            "127.0.0.1:4443",
            "--device-id",
            "00112233445566778899aabbccddeeff",
            "--capacity",
            "1000",
        ])
        .unwrap();
        assert_eq!(a.hostname.as_deref(), Some("ingest.sim"));
        assert_eq!(a.addr.as_deref(), Some("127.0.0.1:4443"));
        assert_eq!(a.capacity, 1000);
    }
}
