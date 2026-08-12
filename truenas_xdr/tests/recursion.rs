// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Decoding bounds its own nesting, so a hostile deeply-nested stream is an
//! error rather than a stack overflow. RFC 4506 §4.19 optional-data encodes a
//! linked list as a chain of optionals, so an attacker drives the depth by
//! repeating a four-byte "present" discriminant.

use serde::Deserialize;
use truenas_xdr::{Deserializer, Error, Strictness, from_bytes};

#[derive(Deserialize, PartialEq, Debug)]
struct Node {
    next: Option<Box<Node>>,
}

/// `levels` "present" discriminants then one "absent": a chain that deep.
fn nested(levels: usize) -> Vec<u8> {
    let mut wire = Vec::with_capacity(4 * levels + 4);
    for _ in 0..levels {
        wire.extend_from_slice(&[0, 0, 0, 1]);
    }
    wire.extend_from_slice(&[0, 0, 0, 0]);
    wire
}

#[test]
fn a_hostile_deep_chain_is_an_error_not_a_crash() {
    // Without the bound this recurses a million frames deep and the process
    // aborts on the stack guard page; with it, the decode is a clean error.
    let err = from_bytes::<Node>(&nested(1_000_000)).unwrap_err();
    assert!(
        matches!(err, Error::RecursionLimit { .. }),
        "expected RecursionLimit, got {err:?}"
    );
}

#[test]
fn nesting_within_the_limit_still_decodes() {
    // Each list node is two levels deep — the struct and its optional — so a
    // node count well under half the bound decodes and round-trips.
    let nodes = 30;
    assert!(2 * nodes + 1 < Deserializer::DEFAULT_MAX_DEPTH);
    let decoded = from_bytes::<Node>(&nested(nodes)).unwrap();
    let mut n = &decoded;
    let mut count = 0;
    while let Some(next) = &n.next {
        count += 1;
        n = &**next;
    }
    assert_eq!(count, nodes);
}

#[test]
fn the_depth_bound_is_configurable() {
    let wire = nested(500);
    // The default refuses a 500-deep chain.
    assert!(matches!(
        from_bytes::<Node>(&wire).unwrap_err(),
        Error::RecursionLimit { .. }
    ));
    // Raised, the same chain decodes and consumes the input exactly.
    let mut de =
        Deserializer::new(&wire, Strictness::default()).with_max_depth(4096);
    let decoded = Node::deserialize(&mut de).unwrap();
    assert!(decoded.next.is_some());
    assert!(de.remaining().is_empty());
    // Lowered, even a shallow chain is refused.
    let shallow = nested(8);
    let mut de =
        Deserializer::new(&shallow, Strictness::default()).with_max_depth(4);
    assert!(matches!(
        Node::deserialize(&mut de).unwrap_err(),
        Error::RecursionLimit { .. }
    ));
}
