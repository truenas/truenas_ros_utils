// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Decoding bounds its own nesting, so a hostile deeply-nested stream is an
//! error rather than a stack overflow. RFC 4506 §4.19 optional-data encodes a
//! linked list as a chain of optionals, so an attacker drives the depth by
//! repeating a four-byte "present" discriminant.

use serde::Deserialize;
use truenas_xdr::{Deserializer, Error, Strictness, VarArrayRef, from_bytes};

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

/// A tree whose children stay in the input. RFC 4506 §4.13 lets an array
/// hold values of its own type, so the same four bytes repeated nest it as
/// deep as an attacker likes.
#[derive(Deserialize, PartialEq, Debug)]
struct Tree<'a> {
    #[serde(borrow)]
    children: VarArrayRef<'a, Tree<'a>>,
}

/// How many levels of single children lie under `tree`, found by reading
/// each array as it is reached.
fn depth_of(tree: &Tree<'_>) -> usize {
    let mut levels = 0;
    let mut children = tree.children;
    while let Some(child) = children.iter().next() {
        children = child.unwrap().children;
        levels += 1;
    }
    levels
}

#[test]
fn a_hostile_deep_array_is_an_error_not_a_crash() {
    // `nested` is as many counts of one as there are levels, then a count
    // of zero, which is a tree of single children that deep.
    let err = from_bytes::<Tree<'_>>(&nested(1_000_000)).unwrap_err();
    assert!(
        matches!(err, Error::RecursionLimit { .. }),
        "expected RecursionLimit, got {err:?}"
    );
}

#[test]
fn a_borrowed_array_within_the_limit_is_read_to_its_last_level() {
    // Each level is the struct, the array and its elements, so thirty
    // levels stay well under the bound.
    let levels = 30;
    assert!(3 * levels + 3 < Deserializer::DEFAULT_MAX_DEPTH);
    let wire = nested(levels);
    let tree = from_bytes::<Tree<'_>>(&wire).unwrap();
    assert_eq!(depth_of(&tree), levels);
}

#[test]
fn an_array_decoded_under_a_raised_bound_is_still_read() {
    // The elements are decoded again when they are read. That second
    // decode must not hold them to a lower bound than the first did.
    let wire = nested(300);
    assert!(matches!(
        from_bytes::<Tree<'_>>(&wire).unwrap_err(),
        Error::RecursionLimit { .. }
    ));
    let mut de =
        Deserializer::new(&wire, Strictness::default()).with_max_depth(4096);
    let tree = Tree::deserialize(&mut de).unwrap();
    assert!(de.remaining().is_empty());
    assert_eq!(depth_of(&tree), 300);
}
