//! What every `Storage` must do, generic over the store, for `MemStorage` here and the agent's
//! file store (`edge/sl-agent/tests/file_store.rs` includes this file by path).
#![allow(dead_code)]

use sl_core::storage::{META_SLOTS, Storage, StorageError};
use sl_proto::ids::Class;

pub fn check_all<S: Storage>(make: &dyn Fn(u64) -> S) {
    offsets_are_logical_and_survive_trimming(make(1_000));
    a_full_store_refuses_without_writing(make(4));
    reads_outside_what_is_held_fail(make(1_000));
    trim_and_truncate_clamp_to_what_is_held(make(1_000));
    trimming_everything_then_appending_continues_the_offsets(make(1_000));
    classes_are_independent_and_share_the_capacity(make(10));
    meta_slots_round_trip_and_start_empty(make(1_000));
}

pub fn offsets_are_logical_and_survive_trimming<S: Storage>(mut s: S) {
    s.append(Class::P1, b"abcdef").unwrap();
    s.trim_front(Class::P1, 4).unwrap();
    assert_eq!((s.start(Class::P1), s.end(Class::P1)), (4, 6));
    let mut buf = [0u8; 2];
    s.read(Class::P1, 4, &mut buf).unwrap();
    assert_eq!(&buf, b"ef");
    s.append(Class::P1, b"gh").unwrap();
    assert_eq!(s.end(Class::P1), 8);
    s.truncate(Class::P1, 6).unwrap();
    assert_eq!(s.end(Class::P1), 6);
}

pub fn a_full_store_refuses_without_writing<S: Storage>(mut s: S) {
    assert_eq!(s.capacity(), 4);
    assert_eq!(s.append(Class::P0, b"abcde"), Err(StorageError::Full));
    assert_eq!(s.end(Class::P0), 0);
    s.append(Class::P0, b"abcd").unwrap();
    assert_eq!(s.append(Class::P1, b"x"), Err(StorageError::Full));
}

pub fn reads_outside_what_is_held_fail<S: Storage>(mut s: S) {
    s.append(Class::P2, b"0123456789").unwrap();
    s.trim_front(Class::P2, 3).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(s.read(Class::P2, 2, &mut buf), Err(StorageError::Io));
    assert_eq!(s.read(Class::P2, 7, &mut buf), Err(StorageError::Io));
    s.read(Class::P2, 6, &mut buf).unwrap();
    assert_eq!(&buf, b"6789");
}

pub fn trim_and_truncate_clamp_to_what_is_held<S: Storage>(mut s: S) {
    s.append(Class::P0, b"abcdef").unwrap();
    s.trim_front(Class::P0, 100).unwrap();
    assert_eq!((s.start(Class::P0), s.end(Class::P0)), (6, 6));
    s.append(Class::P0, b"gh").unwrap();
    s.truncate(Class::P0, 0).unwrap();
    assert_eq!((s.start(Class::P0), s.end(Class::P0)), (6, 6));
}

pub fn trimming_everything_then_appending_continues_the_offsets<S: Storage>(mut s: S) {
    s.append(Class::P1, b"abc").unwrap();
    s.trim_front(Class::P1, 3).unwrap();
    s.append(Class::P1, b"de").unwrap();
    assert_eq!((s.start(Class::P1), s.end(Class::P1)), (3, 5));
    let mut buf = [0u8; 2];
    s.read(Class::P1, 3, &mut buf).unwrap();
    assert_eq!(&buf, b"de");
}

pub fn classes_are_independent_and_share_the_capacity<S: Storage>(mut s: S) {
    s.append(Class::P0, b"aaaa").unwrap();
    s.append(Class::P1, b"bbbb").unwrap();
    assert_eq!(s.append(Class::P2, b"ccc"), Err(StorageError::Full));
    s.trim_front(Class::P0, 4).unwrap();
    s.append(Class::P2, b"ccc").unwrap();
    assert_eq!(s.end(Class::P0), 4);
    assert_eq!(s.end(Class::P1), 4);
    assert_eq!(s.end(Class::P2), 3);
}

pub fn meta_slots_round_trip_and_start_empty<S: Storage>(mut s: S) {
    for slot in 0..META_SLOTS {
        assert_eq!(s.read_meta(slot).unwrap(), None);
    }
    s.write_meta(2, b"two").unwrap();
    s.write_meta(2, b"second").unwrap();
    s.write_meta(5, b"").unwrap();
    assert_eq!(s.read_meta(2).unwrap().as_deref(), Some(&b"second"[..]));
    assert_eq!(s.read_meta(5).unwrap().as_deref(), Some(&b""[..]));
    assert_eq!(s.read_meta(0).unwrap(), None);
}
