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

/// This process's boot id: one more than the last, written and synced before it is used.
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
const CLOCK_SET_AFTER: u64 = 1_767_225_600;

/// A boot id for when the counter at `path` cannot be read: the wall clock in seconds
/// (`now_secs`), which a counter that gains one per start has not reached, written as the new
/// counter. The unreadable file is kept beside it as `boot.broken-<secs>`. Refused while the
/// clock is not set, since boot ids must only go up; systemd's restarts try again until it is.
pub fn restart_boot_from_clock(path: &Path, now_secs: u64) -> io::Result<u32> {
    if now_secs < CLOCK_SET_AFTER {
        return Err(io::Error::other(
            "the wall clock is not set, so no boot id is known to be new",
        ));
    }
    let next = u32::try_from(now_secs).map_err(|_| io::Error::other("the wall clock is past u32 seconds"))?;
    if path.exists() {
        let mut aside = path.as_os_str().to_owned();
        aside.push(format!(".broken-{now_secs}"));
        fs::rename(path, &aside)?;
    }
    write_boot(path, next)?;
    Ok(next)
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
