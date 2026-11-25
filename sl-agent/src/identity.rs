//! The device's key seed and its boot counter, each a small file in the state directory.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub fn load_or_create_seed(path: &Path) -> io::Result<[u8; 32]> {
    match fs::read(path) {
        Ok(b) => b
            .try_into()
            .map_err(|_| io::Error::other(format!("{}: not a 32-byte seed", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut seed = [0u8; 32];
            File::open("/dev/urandom")?.read_exact(&mut seed)?;
            let tmp = path.with_extension("tmp");
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&seed)?;
            f.sync_all()?;
            fs::rename(&tmp, path)?;
            if let Some(dir) = path.parent() {
                File::open(dir)?.sync_all()?;
            }
            Ok(seed)
        }
        Err(e) => Err(e),
    }
}

/// This process's boot id: one more than the last, written and synced before it is used. A
/// missing counter counts as 0; a damaged one is an error. The agent itself starts through
/// `resolve_boot`, which also knows when a missing counter is not a first start.
pub fn next_boot(path: &Path) -> io::Result<u32> {
    let last = match fs::read(path) {
        Ok(b) if b.len() == 4 => u32::from_le_bytes(b.try_into().unwrap()),
        Ok(_) => return Err(io::Error::other(format!("{}: damaged boot counter", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e),
    };
    let next = last
        .checked_add(1)
        .ok_or_else(|| io::Error::other("boot counter exhausted"))?;
    write_boot(path, next)?;
    Ok(next)
}

/// No wall clock this early is set: 2026-01-01T00:00:00Z.
pub const CLOCK_SET_AFTER: u64 = 1_767_225_600;

/// What `resolve_boot` decided.
#[derive(Debug, PartialEq, Eq)]
pub struct Boot {
    pub id: u32,
    /// Why the counter was restarted from the clock, if it was.
    pub restarted: Option<String>,
}

/// This process's boot id, from the counter `state/boot`. Boot ids must only go up: the
/// decoder orders a device's timelines by them.
///
/// - A readable counter gives one more. Writing it is the only thing that can fail then, and
///   a failure (a full disk, say) is an error with the counter untouched: never a reason to
///   restart it.
/// - A counter that is damaged or cannot be read, or one that is missing when earlier state is
///   not (`boot.broken-*`, a `log.broken-*`, or any file under `log`), restarts from the wall
///   clock: `max(clock seconds, floor + 1)`, where the floor is `log_floor()` (the newest boot
///   found in the log and in any log set aside). A `boot.broken-*` copy is never a floor: one
///   is only made of a counter that did not read as a boot id. `clock()` is
///   called only then and must return seconds at or after `CLOCK_SET_AFTER` (the agent waits
///   for the clock to be set). The new counter is written first (temporary file, fsync, rename
///   over, directory sync), and only then are the old bytes, if any, copied aside to
///   `boot.broken-<secs>`.
/// - A missing counter with no earlier state is a first start: boot 1.
pub fn resolve_boot(
    state: &Path,
    clock: &mut dyn FnMut() -> u64,
    log_floor: &mut dyn FnMut() -> Option<u32>,
) -> io::Result<Boot> {
    let path = state.join("boot");
    let (old, why) = match fs::read(&path) {
        Ok(b) if b.len() == 4 => {
            let next = u32::from_le_bytes(b.try_into().unwrap())
                .checked_add(1)
                .ok_or_else(|| io::Error::other("boot counter exhausted"))?;
            write_boot(&path, next)?;
            return Ok(Boot {
                id: next,
                restarted: None,
            });
        }
        Ok(b) => {
            let why = format!("{}: damaged ({} bytes)", path.display(), b.len());
            (Some(b), why)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if !earlier_state(state)? {
                write_boot(&path, 1)?;
                return Ok(Boot { id: 1, restarted: None });
            }
            (
                None,
                format!("{}: missing, but this state directory has run before", path.display()),
            )
        }
        Err(e) => (None, format!("{}: {e}", path.display())),
    };
    let floor = log_floor().unwrap_or(0);
    let secs = clock();
    if secs < CLOCK_SET_AFTER {
        return Err(io::Error::other(
            "the wall clock is not set, so no boot id is known to be new",
        ));
    }
    let from_clock = u32::try_from(secs).map_err(|_| io::Error::other("the wall clock is past u32 seconds"))?;
    let id = from_clock.max(
        floor
            .checked_add(1)
            .ok_or_else(|| io::Error::other("boot counter exhausted"))?,
    );
    write_boot(&path, id)?;
    if let Some(old) = old {
        let mut aside = state.join(format!("boot.broken-{secs}"));
        let mut n = 1;
        while aside.exists() {
            aside = state.join(format!("boot.broken-{secs}-{n}"));
            n += 1;
        }
        // Kept for diagnosis only; the new counter is already durable.
        if let Err(e) = fs::write(&aside, &old) {
            eprintln!("{}: {e}", aside.display());
        }
    }
    Ok(Boot {
        id,
        restarted: Some(why),
    })
}

/// Whether `state` holds anything an earlier start made, besides the seed.
fn earlier_state(state: &Path) -> io::Result<bool> {
    for entry in fs::read_dir(state)? {
        let name = entry?.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("boot.broken-") || name.starts_with("log.broken-") {
            return Ok(true);
        }
    }
    any_file(&state.join("log"))
}

fn any_file(dir: &Path) -> io::Result<bool> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if any_file(&entry.path())? {
                return Ok(true);
            }
        } else {
            return Ok(true);
        }
    }
    Ok(false)
}

fn write_boot(path: &Path, boot: u32) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(&boot.to_le_bytes())?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}
