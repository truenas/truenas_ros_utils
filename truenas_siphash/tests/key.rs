// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! What a key shows of itself, and how two keys compare.

use truenas_siphash::Key;

/// Catches a key whose bytes reach `Debug`, in either form, and so a log.
#[test]
fn a_key_never_prints_its_bytes() {
    let key = Key::new([0xa5; 16]);
    assert_eq!(format!("{key:?}"), "Key { .. }");
    assert_eq!(format!("{key:#?}"), "Key { .. }");
}

/// Catches equality that ignores the bytes, or a clone that changes them.
#[test]
fn keys_are_equal_exactly_when_their_bytes_are() {
    let key = Key::new(core::array::from_fn(|i| i as u8));
    assert_eq!(key.clone(), key);
    assert_eq!(Key::new(core::array::from_fn(|i| i as u8)), key);
    for at in 0..16 {
        let mut bytes: [u8; 16] = core::array::from_fn(|i| i as u8);
        bytes[at] ^= 1;
        assert_ne!(Key::new(bytes), key, "byte {at}");
    }
}

/// Catches a key that leaves some of its bytes out of the hash.
#[test]
fn every_byte_of_the_key_changes_the_hash() {
    let message: Vec<u8> = (0..15).collect();
    let hash = Key::new(core::array::from_fn(|i| i as u8)).hash(&message);
    for at in 0..16 {
        let mut bytes: [u8; 16] = core::array::from_fn(|i| i as u8);
        bytes[at] ^= 1;
        assert_ne!(Key::new(bytes).hash(&message), hash, "byte {at}");
    }
}
