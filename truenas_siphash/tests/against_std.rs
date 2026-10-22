// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Agreement with std's `SipHasher`, which is SipHash-2-4, at lengths the
//! reference vectors do not reach. It is deprecated, which matters only to
//! this test.
#![allow(deprecated)]

use std::hash::{Hasher, SipHasher};
use truenas_siphash::Key;

/// Bytes from xorshift64 with a fixed seed, so a failure repeats.
struct Bytes(u64);

impl Bytes {
    fn next(&mut self) -> u8 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 as u8
    }
}

/// Catches a length byte that does not wrap at 256, and any word past the
/// 63 bytes the reference vectors cover, under keys other than 00 to 0f.
#[test]
fn every_length_up_to_300_bytes_agrees_with_std() {
    let mut bytes = Bytes(0x9e37_79b9_7f4a_7c15);
    for len in 0..=300 {
        for _ in 0..8 {
            let key: [u8; 16] = core::array::from_fn(|_| bytes.next());
            let data: Vec<u8> = (0..len).map(|_| bytes.next()).collect();
            let k0 = u64::from_le_bytes(key[..8].try_into().unwrap());
            let k1 = u64::from_le_bytes(key[8..].try_into().unwrap());
            let mut std = SipHasher::new_with_keys(k0, k1);
            std.write(&data);
            assert_eq!(Key::new(key).hash(&data), std.finish(), "{len} bytes");
        }
    }
}
