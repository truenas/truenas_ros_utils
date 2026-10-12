// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Bounded variable-length data, RFC 4506 §4.10, §4.11 and §4.13.
//!
//! A bound is a limit on the length a value declares. Each case here checks
//! one side of that limit, or checks that the limit reaches the one length it
//! belongs to and no other.

use std::cell::Cell;

use serde::{Deserialize, Serialize};
use truenas_xdr::{
    Bounded, Error, VarOpaque, VarOpaqueRef, from_bytes, serialized_size,
    to_bytes,
};

/// This catches a bound that changes the bytes, and a bound that refuses a
/// value exactly at the limit.
#[test]
fn a_value_at_its_bound_encodes_like_the_unbounded_value() {
    let opaque = Bounded::<_, 3>(VarOpaque(vec![1, 2, 3]));
    let wire = [0, 0, 0, 3, 1, 2, 3, 0];
    assert_eq!(to_bytes(&opaque).unwrap(), wire);
    assert_eq!(to_bytes(&opaque.0).unwrap(), wire);
    assert_eq!(serialized_size(&opaque).unwrap(), wire.len());
    assert_eq!(from_bytes::<Bounded<VarOpaque, 3>>(&wire).unwrap(), opaque);

    let string = Bounded::<_, 2>("ab".to_string());
    let wire = [0, 0, 0, 2, b'a', b'b', 0, 0];
    assert_eq!(to_bytes(&string).unwrap(), wire);
    assert_eq!(to_bytes(&string.0).unwrap(), wire);
    assert_eq!(from_bytes::<Bounded<String, 2>>(&wire).unwrap(), string);

    let array = Bounded::<_, 2>(vec![7u32, 8]);
    let wire = [0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 8];
    assert_eq!(to_bytes(&array).unwrap(), wire);
    assert_eq!(to_bytes(&array.0).unwrap(), wire);
    assert_eq!(from_bytes::<Bounded<Vec<u32>, 2>>(&wire).unwrap(), array);

    // A bound of zero admits the empty value and nothing else.
    let empty = Bounded::<_, 0>(VarOpaque(vec![]));
    assert_eq!(to_bytes(&empty).unwrap(), [0, 0, 0, 0]);
    assert_eq!(
        from_bytes::<Bounded<VarOpaque, 0>>(&[0, 0, 0, 0]).unwrap(),
        empty
    );
}

/// This catches a decoder that accepts a declared length one past the bound.
#[test]
fn one_past_the_bound_is_refused_on_decode() {
    let too_long = Error::TooLong { len: 4, max: 3 };

    let opaque = [0, 0, 0, 4, 1, 2, 3, 4];
    assert_eq!(
        from_bytes::<Bounded<VarOpaque, 3>>(&opaque).unwrap_err(),
        too_long
    );
    assert_eq!(
        from_bytes::<Bounded<VarOpaqueRef<'_>, 3>>(&opaque).unwrap_err(),
        too_long
    );

    let string = [0, 0, 0, 4, b'a', b'b', b'c', b'd'];
    assert_eq!(
        from_bytes::<Bounded<String, 3>>(&string).unwrap_err(),
        too_long
    );
    assert_eq!(
        from_bytes::<Bounded<&str, 3>>(&string).unwrap_err(),
        too_long
    );

    let array = [0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4];
    assert_eq!(
        from_bytes::<Bounded<Vec<u32>, 3>>(&array).unwrap_err(),
        too_long
    );
}

/// This catches an encoder that writes a value its bound does not admit. The
/// standard calls that an error for all three shapes.
#[test]
fn one_past_the_bound_is_refused_on_encode() {
    let too_long = Error::TooLong { len: 4, max: 3 };
    assert_eq!(
        to_bytes(&Bounded::<_, 3>(VarOpaque(vec![0; 4]))).unwrap_err(),
        too_long
    );
    assert_eq!(
        to_bytes(&Bounded::<_, 3>(VarOpaqueRef(&[0; 4]))).unwrap_err(),
        too_long
    );
    assert_eq!(
        to_bytes(&Bounded::<_, 3>("abcd".to_string())).unwrap_err(),
        too_long
    );
    assert_eq!(to_bytes(&Bounded::<_, 3>("abcd")).unwrap_err(), too_long);
    assert_eq!(
        to_bytes(&Bounded::<_, 3>(vec![0u32; 4])).unwrap_err(),
        too_long
    );
    assert_eq!(
        serialized_size(&Bounded::<_, 3>(vec![0u32; 4])).unwrap_err(),
        too_long
    );
}

thread_local! {
    static DECODED: Cell<usize> = const { Cell::new(0) };
}

/// An array element that counts how many times it was decoded.
#[derive(Debug)]
struct Counting;

impl<'de> Deserialize<'de> for Counting {
    fn deserialize<D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Self, D::Error> {
        DECODED.with(|n| n.set(n.get() + 1));
        u32::deserialize(d).map(|_| Counting)
    }
}

/// This catches a bound that is applied after the elements were decoded. A
/// hostile count must cost nothing past its four bytes.
#[test]
fn an_array_over_its_bound_decodes_no_element() {
    let wire = [0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3];
    DECODED.with(|n| n.set(0));
    assert_eq!(
        from_bytes::<Bounded<Vec<Counting>, 2>>(&wire).unwrap_err(),
        Error::TooLong { len: 3, max: 2 }
    );
    assert_eq!(DECODED.with(Cell::get), 0);

    // The control. Within the bound, every element is decoded.
    let within = from_bytes::<Bounded<Vec<Counting>, 3>>(&wire).unwrap();
    assert_eq!(within.0.len(), 3);
    assert_eq!(DECODED.with(Cell::get), 3);
}

/// This catches a decoder that reads what a length covers before it holds
/// the length to the bound. The input ends right after the length, so
/// reading first would report the missing bytes and not the bound.
#[test]
fn the_declared_length_is_checked_before_anything_it_covers() {
    let too_long = Error::TooLong { len: 9, max: 3 };
    let wire = [0, 0, 0, 9];
    assert_eq!(
        from_bytes::<Bounded<VarOpaqueRef<'_>, 3>>(&wire).unwrap_err(),
        too_long
    );
    assert_eq!(from_bytes::<Bounded<&str, 3>>(&wire).unwrap_err(), too_long);
    assert_eq!(
        from_bytes::<Bounded<Vec<u32>, 3>>(&wire).unwrap_err(),
        too_long
    );
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Pair {
    short: Bounded<VarOpaque, 2>,
    long: VarOpaque,
}

/// This catches a bound that outlives its own field and is held against the
/// next length in the message, in either direction.
#[test]
fn a_bound_applies_to_its_own_length_and_no_other() {
    let value = Pair {
        short: Bounded(VarOpaque(vec![1])),
        long: VarOpaque(vec![9; 8]),
    };
    let wire = [
        0, 0, 0, 1, 1, 0, 0, 0, // short
        0, 0, 0, 8, 9, 9, 9, 9, 9, 9, 9, 9, // long
    ];
    assert_eq!(to_bytes(&value).unwrap(), wire);
    assert_eq!(from_bytes::<Pair>(&wire).unwrap(), value);

    // An array's bound counts elements. It says nothing about how long each
    // element is.
    let items = Bounded::<_, 2>(vec![VarOpaque(vec![7; 5])]);
    let wire = [0, 0, 0, 1, 0, 0, 0, 5, 7, 7, 7, 7, 7, 0, 0, 0];
    assert_eq!(to_bytes(&items).unwrap(), wire);
    assert_eq!(
        from_bytes::<Bounded<Vec<VarOpaque>, 2>>(&wire).unwrap(),
        items
    );
}

/// This catches nested bounds being confused with each other. The outer one
/// counts the names and the inner one counts the bytes of each name.
#[test]
fn nested_bounds_each_hold_their_own_level() {
    type Names = Bounded<Vec<Bounded<String, 4>>, 2>;

    let wire = [
        0, 0, 0, 2, // two names
        0, 0, 0, 1, b'a', 0, 0, 0, // "a"
        0, 0, 0, 4, b'b', b'c', b'd', b'e', // "bcde"
    ];
    let names: Names = from_bytes(&wire).unwrap();
    assert_eq!(names.0[1].0, "bcde");
    assert_eq!(to_bytes(&names).unwrap(), wire);

    let long_name = [0, 0, 0, 1, 0, 0, 0, 5, b'a', b'b', b'c', b'd', b'e'];
    assert_eq!(
        from_bytes::<Names>(&long_name).unwrap_err(),
        Error::TooLong { len: 5, max: 4 }
    );
    let many_names = [0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        from_bytes::<Names>(&many_names).unwrap_err(),
        Error::TooLong { len: 3, max: 2 }
    );
}

/// Whether `part` points into `whole` and not at separate storage.
fn borrows_from(part: &[u8], whole: &[u8]) -> bool {
    let start = whole.as_ptr() as usize;
    let at = part.as_ptr() as usize;
    at >= start && at + part.len() <= start + whole.len()
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Handle<'a> {
    #[serde(borrow)]
    bytes: Bounded<VarOpaqueRef<'a>, 128>,
}

/// This catches a bound that turns a borrowed decode into a copy.
#[test]
fn a_bounded_borrow_points_into_the_input() {
    let wire = [0, 0, 0, 3, 1, 2, 3, 0];
    let opaque: Bounded<VarOpaqueRef<'_>, 8> = from_bytes(&wire).unwrap();
    assert!(borrows_from(opaque.0.0, &wire));
    let handle: Handle<'_> = from_bytes(&wire).unwrap();
    assert!(borrows_from(handle.bytes.0.0, &wire));

    let wire = [0, 0, 0, 2, b'a', b'b', 0, 0];
    let text: Bounded<&str, 8> = from_bytes(&wire).unwrap();
    assert!(borrows_from(text.0.as_bytes(), &wire));
}
