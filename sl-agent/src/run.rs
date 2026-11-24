//! The agent's loop (agent spec 3.8): SignalK into the device, the device's seals on a 200 ms
//! tick, and its session over one WebSocket at a time, until SIGTERM or SIGINT.
//!
//! A storage error is a reboot, as in the simulator's boat: the loop closes the socket and
//! `run` returns an error, so the process exits non-zero and systemd starts a new boot that
//! reopens and recovers the log.
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use sl_core::device::{Device, DeviceConfig};
use sl_core::recorder::RecorderConfig;
use sl_core::session::SessionError;
use sl_proto::auth::{KeySigner, Signer as _};
use sl_proto::compress::Compression;
use sl_proto::ids::Class;
use sl_proto::trust::SignedTrustStore;
use sl_proto::wire::{Body, Envelope};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior, interval};
use tokio_tungstenite::tungstenite::Message;

use crate::clock::Clock;
use crate::defines::{Defines, to_value};
use crate::file_store::FileStore;
use crate::identity::{load_or_create_seed, next_boot};
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
const INTAKE: usize = 8_192;

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
    std::fs::create_dir_all(&args.state_dir).map_err(|e| format!("{}: {e}", args.state_dir.display()))?;
    let seed = load_or_create_seed(&args.state_dir.join("device.seed")).map_err(|e| e.to_string())?;
    println!("{}", hex::encode(KeySigner::from_seed(seed).public_key()));
    Ok(())
}

type Connecting = Pin<Box<dyn Future<Output = Result<(Ws, [u8; 32]), String>>>>;

/// SignalK into `tx` for ever, reconnecting with backoff; `$source` NAMEs refreshed from the
/// sources document at each connect and when an unknown source appears (at most once a minute).
/// An update that finds the channel full is dropped and counted.
async fn signalk(url: String, tx: mpsc::Sender<(Update, u64)>) {
    let mut backoff = Duration::from_secs(1);
    let names_url = sources_url(&url);
    let mut known: HashMap<String, u64> = HashMap::new();
    let mut dropped: u64 = 0;
    let mut dropped_logged: Option<Instant> = None;
    loop {
        match tokio_tungstenite::connect_async(url.as_str()).await {
            Ok((mut ws, _)) => {
                eprintln!("SignalK connected: {url}");
                backoff = Duration::from_secs(1);
                // A new connection fetches the names again at its first update.
                let mut fetched_at: Option<Instant> = None;
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
                    let Message::Text(text) = msg else { continue };
                    for u in parse_delta(text.as_str()) {
                        if !known.contains_key(&u.source)
                            && fetched_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(60))
                            && let Some(src_url) = &names_url
                        {
                            fetched_at = Some(Instant::now());
                            let src_url = src_url.clone();
                            let doc = tokio::task::spawn_blocking(move || {
                                ureq::get(&src_url)
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
                                known = names(&doc);
                            }
                        }
                        let name = known.get(&u.source).copied().unwrap_or(0);
                        match tx.try_send((u, name)) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                // The device task is far behind: dropping is the intake budget.
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

/// `d` lengthened by up to a quarter, by `r` (any u32; its value mod 1000 is used).
fn jittered(d: Duration, r: u32) -> Duration {
    d + d.mul_f64(f64::from(r % 1000) / 4000.0)
}

fn jitter(d: Duration) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.subsec_nanos())
        .unwrap_or(0);
    jittered(d, nanos)
}

/// The reconnect schedule: a failed attempt or a lost session waits the backoff (jittered),
/// which doubles to five minutes; a Welcome resets it.
struct Retry {
    at: Instant,
    backoff: Duration,
}

impl Retry {
    fn new() -> Self {
        Self {
            at: Instant::now(),
            backoff: BACKOFF_FIRST,
        }
    }

    fn failed(&mut self) {
        self.at = Instant::now() + jitter(self.backoff);
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
    }

    fn welcomed(&mut self) {
        self.backoff = BACKOFF_FIRST;
    }
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
    std::fs::create_dir_all(state).map_err(|e| format!("{}: {e}", state.display()))?;
    let seed = load_or_create_seed(&state.join("device.seed")).map_err(|e| e.to_string())?;
    let boot_id = next_boot(&state.join("boot")).map_err(|e| e.to_string())?;
    let clock = Clock::start();
    let store = FileStore::open(&state.join("log"), args.capacity).map_err(|e| format!("the log: {e}"))?;
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
    let (mut dev, recovery) =
        Device::open(cfg, store, AgentSink::default(), &baseline).map_err(|e| format!("opening the device: {e:?}"))?;
    let mut sealed = Vec::new();
    if let Err(e) = dev.report_recovery(&recovery, clock.mono_ms(), &mut sealed) {
        eprintln!("declaring the losses found at open failed ({e:?}); the next tick declares them");
    }
    eprintln!(
        "boot {boot_id}; log P0 {} P1 {} P2 {} frames; torn bytes {:?}; {} corrupt ranges",
        dev.log().next_seq(Class::P0),
        dev.log().next_seq(Class::P1),
        dev.log().next_seq(Class::P2),
        recovery.truncated_bytes,
        recovery.corrupt.len()
    );
    if let Some(a) = clock.ntp_anchor() {
        dev.anchor(a);
    }

    let (tx, mut rx) = mpsc::channel::<(Update, u64)>(INTAKE);
    tokio::spawn(signalk(args.signalk_url.clone(), tx));

    let mut policy = Policy::new();
    let mut defines = Defines::new();
    let mut tick = interval(Duration::from_millis(TICK_MS));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut ntp = interval(NTP_EVERY);
    ntp.tick().await;
    let mut fill = interval(FILL_EVERY);
    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
    let mut ws: Option<Ws> = None;
    let mut connecting: Option<Connecting> = None;
    let mut retry = Retry::new();
    let mut welcomed = false;

    loop {
        if ws.is_none() && connecting.is_none() && Instant::now() >= retry.at {
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
            Some((u, name)) = rx.recv() => {
                let now = clock.mono_ms();
                if let Some(class) = policy.decide(&u.path, &u.value, now)
                    && let Some(value) = to_value(&u.path, &u.value)
                {
                    let def = defines.get(&u.path, name, value.value_type()).clone();
                    dev.sample(class, &def, now, value);
                }
                Turn::Poll
            }
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
                    Ok((mut socket, binding)) => match dev.connect(binding, clock.mono_ms()) {
                        Some(hello) => {
                            if socket.send(Message::Binary(hello.encode_to_vec().into())).await.is_ok() {
                                ws = Some(socket);
                                welcomed = false;
                                Turn::Poll
                            } else {
                                eprintln!("gateway {addr}: sending the Hello failed");
                                dev.disconnect();
                                retry.failed();
                                Turn::Skip
                            }
                        }
                        None => {
                            let _ = tokio::time::timeout(Duration::from_secs(1), socket.close(None)).await;
                            Turn::Fatal("the log could not be read to say Hello".into())
                        }
                    },
                    Err(e) => {
                        eprintln!("gateway {addr}: {e}");
                        retry.failed();
                        Turn::Skip
                    }
                }
            }
            msg = async { ws.as_mut().unwrap().next().await }, if ws.is_some() => {
                let env = match msg {
                    Some(Ok(Message::Binary(b))) => Some(Envelope::decode(b.as_ref()).ok()),
                    Some(Ok(Message::Close(f))) => { eprintln!("gateway closed: {f:?}"); Some(None) }
                    // Text, Ping, Pong: tungstenite answers pings itself.
                    Some(Ok(_)) => None,
                    Some(Err(e)) => { eprintln!("gateway: {e}"); Some(None) }
                    None => { eprintln!("gateway: connection ended"); Some(None) }
                };
                match env {
                    None => Turn::Skip,
                    Some(None) => {
                        drop_ws(&mut ws, &mut dev).await;
                        retry.failed();
                        Turn::Skip
                    }
                    Some(Some(env)) => {
                        let is_welcome = matches!(env.body, Some(Body::Welcome(_)));
                        match dev.receive(env, clock.mono_ms()) {
                            Ok(out) => {
                                if is_welcome && !welcomed {
                                    welcomed = true;
                                    retry.welcomed();
                                    eprintln!("Welcome received: device {:?}", dev.state());
                                }
                                if send_all(ws.as_mut().unwrap(), out).await.is_err() {
                                    eprintln!("gateway: sending failed");
                                    drop_ws(&mut ws, &mut dev).await;
                                    retry.failed();
                                    Turn::Skip
                                } else {
                                    Turn::Poll
                                }
                            }
                            Err(SessionError::Storage(e)) => Turn::Fatal(format!("the log failed in the session: {e:?}")),
                            Err(e) => {
                                eprintln!("session ended: {e:?}");
                                drop_ws(&mut ws, &mut dev).await;
                                retry.failed();
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
            Turn::Poll => match ws.as_mut() {
                Some(socket) if dev.connected() => {
                    let out = dev.poll();
                    if let Some(e) = dev.take_storage_fault() {
                        Some(format!("reading the log failed: {e:?}"))
                    } else {
                        if send_all(socket, out).await.is_err() {
                            eprintln!("gateway: sending failed");
                            drop_ws(&mut ws, &mut dev).await;
                            retry.failed();
                        }
                        None
                    }
                }
                _ => None,
            },
        };
        if let Some(e) = fault {
            eprintln!("{e}; ending this boot so the next one recovers the log");
            drop_ws(&mut ws, &mut dev).await;
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

    // Clean stop: seal, send what the credit allows, close.
    let deadline = Instant::now() + STOP_WITHIN;
    sealed.clear();
    if let Err(e) = dev.flush(clock.mono_ms(), &mut sealed) {
        eprintln!("sealing at stop failed: {e:?}");
        drop_ws(&mut ws, &mut dev).await;
        return Err(format!("sealing at stop failed: {e:?}"));
    }
    eprintln!(
        "sealed through P0 {} P1 {} P2 {}",
        dev.log().next_seq(Class::P0),
        dev.log().next_seq(Class::P1),
        dev.log().next_seq(Class::P2)
    );
    let mut fault = None;
    if let Some(socket) = ws.as_mut()
        && dev.connected()
    {
        let out = dev.poll();
        fault = dev.take_storage_fault();
        let _ = tokio::time::timeout_at(deadline, send_all(socket, out)).await;
    }
    if let Some(mut socket) = ws.take() {
        let _ = tokio::time::timeout_at(deadline, socket.close(None)).await;
    }
    dev.disconnect();
    if let Some(e) = fault {
        eprintln!("reading the log at stop failed: {e:?}");
        return Err(format!("reading the log at stop failed: {e:?}"));
    }
    eprintln!("stopped cleanly");
    Ok(())
}

async fn send_all(ws: &mut Ws, out: Vec<Envelope>) -> Result<(), ()> {
    for env in out {
        ws.send(Message::Binary(env.encode_to_vec().into()))
            .await
            .map_err(|_| ())?;
    }
    Ok(())
}

async fn drop_ws(ws: &mut Option<Ws>, dev: &mut Device<FileStore, AgentSink>) {
    if let Some(mut s) = ws.take() {
        let _ = tokio::time::timeout(Duration::from_secs(1), s.close(None)).await;
    }
    dev.disconnect();
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
        assert!(jittered(d, u32::MAX) <= d + d / 4);
    }

    #[test]
    fn backoff_doubles_to_five_minutes_and_a_welcome_resets_it() {
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
        r.welcomed();
        assert_eq!(r.backoff, BACKOFF_FIRST);
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
