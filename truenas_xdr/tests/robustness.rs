// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Hostile-input sweep: for a battery of target types and a corpus of crafted
//! and pseudo-random byte strings, every decode must return `Ok` or `Err` and
//! never panic. A panic here — an out-of-range index, a slice past the end, or
//! an arithmetic overflow under `-C overflow-checks=on` — would be a decoder
//! fault. Recursive types are covered separately in `recursion.rs`; a stack
//! overflow is not catchable and would abort the whole binary.

// Fixture fields exist to be decoded into, not read back.
#![allow(dead_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use serde::Deserialize;
use truenas_xdr::{
    FixedOpaque, Strictness, VarOpaque, VarOpaqueRef, from_bytes_with,
};

#[derive(Deserialize)]
struct Point {
    x: i32,
    y: i32,
}

#[derive(Deserialize)]
enum Stock {
    First,
    Second(i32),
    Third { a: i32, b: bool },
}

/// Feed every input to `from_bytes_with::<T>` in both modes; return the number
/// of attempts and panic if any decode unwound.
fn probe<'de, T: Deserialize<'de>>(inputs: &'de [Vec<u8>]) -> u64 {
    let mut n = 0;
    for inp in inputs {
        for mode in [Strictness::Lenient, Strictness::Strict] {
            n += 1;
            let r = catch_unwind(AssertUnwindSafe(|| {
                let _ = from_bytes_with::<T>(inp, mode);
            }));
            assert!(
                r.is_ok(),
                "panic decoding {} from {inp:02x?} ({mode:?})",
                std::any::type_name::<T>(),
            );
        }
    }
    n
}

fn corpus() -> Vec<Vec<u8>> {
    let mut c: Vec<Vec<u8>> = Vec::new();
    for n in 0..=9usize {
        c.push(vec![0u8; n]);
        c.push(vec![0xffu8; n]);
    }
    // Length prefixes that promise far more than follows, at and around the
    // u32 boundary — the over-read / over-allocate surface.
    for l in [
        0u32,
        1,
        2,
        3,
        4,
        5,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_fffe,
        0xffff_ffff,
    ] {
        let mut v = l.to_be_bytes().to_vec();
        v.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        c.push(v);
    }
    // Discriminants (bool/enum/optional) in and out of range, alone and with a
    // trailing unit.
    for d in [0u32, 1, 2, 3, 9, 0x8000_0000, 0xffff_ffff] {
        c.push(d.to_be_bytes().to_vec());
        let mut v = d.to_be_bytes().to_vec();
        v.extend_from_slice(&[0, 0, 0, 7]);
        c.push(v);
    }
    // Dirty padding and invalid UTF-8.
    c.push(vec![0, 0, 0, 3, b'a', b'b', b'c', 0xff]);
    c.push(vec![0, 0, 0, 2, 0xff, 0xfe, 0, 0]);
    // Deterministic pseudo-random strings at several lengths (LCG, so the
    // corpus is fixed and a failure reproduces).
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
    for len in [4usize, 8, 12, 16, 24, 40] {
        for _ in 0..48 {
            let mut v = Vec::with_capacity(len);
            for _ in 0..len {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                v.push((s >> 33) as u8);
            }
            c.push(v);
        }
    }
    c
}

#[test]
fn no_target_type_panics_on_hostile_input() {
    let inputs = corpus();
    let mut total = 0u64;
    total += probe::<u8>(&inputs);
    total += probe::<u16>(&inputs);
    total += probe::<u32>(&inputs);
    total += probe::<u64>(&inputs);
    total += probe::<i8>(&inputs);
    total += probe::<i16>(&inputs);
    total += probe::<i32>(&inputs);
    total += probe::<i64>(&inputs);
    total += probe::<f32>(&inputs);
    total += probe::<f64>(&inputs);
    total += probe::<bool>(&inputs);
    total += probe::<char>(&inputs);
    total += probe::<String>(&inputs);
    total += probe::<&str>(&inputs);
    total += probe::<VarOpaque>(&inputs);
    total += probe::<VarOpaqueRef>(&inputs);
    total += probe::<&[u8]>(&inputs);
    total += probe::<FixedOpaque<0>>(&inputs);
    total += probe::<FixedOpaque<1>>(&inputs);
    total += probe::<FixedOpaque<4>>(&inputs);
    total += probe::<FixedOpaque<7>>(&inputs);
    total += probe::<Vec<u32>>(&inputs);
    total += probe::<Vec<String>>(&inputs);
    total += probe::<Vec<Vec<u8>>>(&inputs);
    total += probe::<(i32, String)>(&inputs);
    total += probe::<[i32; 3]>(&inputs);
    total += probe::<Option<u32>>(&inputs);
    total += probe::<Option<String>>(&inputs);
    total += probe::<Point>(&inputs);
    total += probe::<Stock>(&inputs);

    // A guard on the guard: the sweep must actually have run.
    assert!(total > 10_000, "sweep too small: {total}");
}
