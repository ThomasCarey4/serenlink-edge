use std::os::unix::fs::PermissionsExt;

use sl_agent::identity::{Boot, load_or_create_seed, next_boot, resolve_boot};

#[test]
fn a_seed_is_made_once_private_and_then_kept() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("device.seed");
    let a = load_or_create_seed(&p).unwrap();
    assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(load_or_create_seed(&p).unwrap(), a);
    assert_ne!(a, [0; 32]);
}

#[test]
fn a_seed_file_of_the_wrong_size_is_an_error_not_a_new_key() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("device.seed");
    std::fs::write(&p, [1; 31]).unwrap();
    assert!(load_or_create_seed(&p).is_err());
}

#[test]
fn boots_count_up_from_one() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("boot");
    assert_eq!(next_boot(&p).unwrap(), 1);
    assert_eq!(next_boot(&p).unwrap(), 2);
    assert_eq!(next_boot(&p).unwrap(), 3);
}

const NOW: u64 = 1_790_000_000;

fn resolve(state: &std::path::Path, now: u64, log: Option<u32>) -> std::io::Result<Boot> {
    resolve_boot(state, &mut || now, &mut || log)
}

#[test]
fn a_first_start_is_boot_one_and_each_start_counts_on() {
    let dir = tempfile::tempdir().unwrap();
    let never = &mut || -> u64 { panic!("no clock is needed") };
    assert_eq!(resolve_boot(dir.path(), never, &mut || None).unwrap().id, 1);
    assert_eq!(resolve_boot(dir.path(), never, &mut || None).unwrap().id, 2);
}

#[test]
fn a_failed_write_is_an_error_and_leaves_the_counter_alone() {
    // A full disk: the counter reads, its successor cannot be written.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("boot");
    std::fs::write(&p, 5u32.to_le_bytes()).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let r = resolve(dir.path(), NOW, None);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(r.is_err());
    assert_eq!(std::fs::read(&p).unwrap(), 5u32.to_le_bytes());
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["boot"]);
    // The disk has room again: counting goes on from 5.
    assert_eq!(resolve(dir.path(), NOW, None).unwrap().id, 6);
}

#[test]
fn a_damaged_counter_restarts_from_the_clock_and_counts_on() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("boot");
    std::fs::write(&p, [1, 2, 3]).unwrap();
    assert!(next_boot(&p).is_err());
    // An unset clock gives no id known to be new, and nothing is changed.
    assert!(resolve(dir.path(), 1_000, None).is_err());
    assert_eq!(std::fs::read(&p).unwrap(), [1, 2, 3]);
    let b = resolve(dir.path(), NOW, Some(7)).unwrap();
    assert_eq!(b.id, NOW as u32);
    assert!(b.restarted.is_some());
    assert_eq!(
        std::fs::read(dir.path().join(format!("boot.broken-{NOW}"))).unwrap(),
        [1, 2, 3]
    );
    assert_eq!(resolve(dir.path(), NOW, None).unwrap().id, NOW as u32 + 1);
}

#[test]
fn a_damaged_counter_with_the_clock_set_but_failing_writes_is_left_in_place() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("boot");
    std::fs::write(&p, [1, 2, 3]).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let r = resolve(dir.path(), NOW, None);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(r.is_err());
    assert_eq!(std::fs::read(&p).unwrap(), [1, 2, 3]);
    assert!(!dir.path().join(format!("boot.broken-{NOW}")).exists());
}

#[test]
fn a_missing_counter_beside_earlier_state_is_not_a_first_start() {
    let dir = tempfile::tempdir().unwrap();
    // An earlier restart left its copy aside; the counter itself is gone.
    std::fs::write(dir.path().join("boot.broken-1789999000"), [4, 1]).unwrap();
    let b = resolve(dir.path(), NOW, None).unwrap();
    assert_eq!(b.id, NOW as u32);
    assert!(b.restarted.is_some());

    // A log with files in it, and no counter.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("log/p0")).unwrap();
    std::fs::write(dir.path().join("log/p0/start"), 0u64.to_le_bytes()).unwrap();
    assert!(
        resolve(dir.path(), 1_000, None).is_err(),
        "an unset clock is refused, not boot 1"
    );
    assert!(!dir.path().join("boot").exists());
    assert_eq!(resolve(dir.path(), NOW, None).unwrap().id, NOW as u32);

    // Empty log directories are what a first start leaves before it writes anything.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("log/p0")).unwrap();
    assert_eq!(resolve(dir.path(), 1_000, None).unwrap().id, 1);
}

#[test]
fn a_clock_restart_never_goes_below_what_the_log_holds() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("boot"), [9]).unwrap();
    // A boot id from the future of this clock, found in the log.
    let b = resolve(dir.path(), NOW, Some(NOW as u32 + 500)).unwrap();
    assert_eq!(b.id, NOW as u32 + 501);
}
