use std::os::unix::fs::PermissionsExt;

use sl_agent::identity::{load_or_create_seed, next_boot};

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
