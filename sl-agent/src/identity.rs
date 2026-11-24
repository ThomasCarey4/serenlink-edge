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
    let tmp = path.with_extension("tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(&next.to_le_bytes())?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    Ok(next)
}
