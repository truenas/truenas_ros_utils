// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! A list of optional data that stays in the input, RFC 4506 §4.19.
//!
//! The list keeps its count and the bytes of its elements with the booleans
//! between them. Each case here checks that those bytes are the right ones,
//! that they are the caller's and not a copy, or that a list the input cannot
//! back is refused.

use serde::{Deserialize, Serialize};
use truenas_xdr::{
    Error, ListRef, Strictness, VarOpaqueRef, from_bytes, from_bytes_with,
    from_prefix, serialized_size, to_bytes,
};

/// The elements of `list`, each decoded.
fn elements<'a, T: Deserialize<'a>>(list: &ListRef<'a, T>) -> Vec<T> {
    list.iter().collect::<Result<Vec<T>, Error>>().unwrap()
}

/// Two words of 7 and 8, each behind a boolean of 1, and a boolean of 0.
const TWO: [u8; 20] =
    [0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 0];

/// This catches a list laid out otherwise than §4.19 has it, which is a
/// boolean of 1 before each element and a boolean of 0 after the last.
#[test]
fn a_list_is_each_element_behind_a_one_and_a_zero_after_the_last() {
    let list: ListRef<'_, u32> = from_bytes(&TWO).unwrap();
    assert_eq!(list.len(), 2);
    assert!(!list.is_empty());
    assert_eq!(elements(&list), [7, 8]);
    assert_eq!(to_bytes(&list).unwrap(), TWO);
    assert_eq!(serialized_size(&list).unwrap(), TWO.len());

    // The empty list is the boolean of 0 alone, and it is the default.
    let none: ListRef<'_, u32> = from_bytes(&[0, 0, 0, 0]).unwrap();
    assert!(none.is_empty());
    assert_eq!(elements(&none), [0u32; 0]);
    assert_eq!(none, ListRef::default());
    assert_eq!(to_bytes(&none).unwrap(), [0, 0, 0, 0]);
    assert_eq!(to_bytes(&ListRef::<u32>::default()).unwrap(), [0, 0, 0, 0]);
}

/// This catches a list that copies its elements out of the input.
#[test]
fn the_elements_are_a_borrow_of_the_input() {
    let list: ListRef<'_, u32> = from_bytes(&TWO).unwrap();
    assert!(std::ptr::eq(list.encoded().as_ptr(), TWO.as_ptr()));
    assert_eq!(list.encoded(), &TWO);
}

/// This catches a span that ends at the wrong place when the elements differ
/// in length, and a field after the list read from the wrong place.
#[test]
fn the_span_ends_at_the_boolean_of_zero() {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct After<'a> {
        #[serde(borrow)]
        names: ListRef<'a, VarOpaqueRef<'a>>,
        eof: bool,
    }
    let mut wire = vec![0, 0, 0, 1, 0, 0, 0, 2, b'a', b'b', 0, 0];
    wire.extend([
        0, 0, 0, 1, 0, 0, 0, 5, b'a', b'b', b'c', b'd', b'e', 0, 0, 0,
    ]);
    wire.extend([0, 0, 0, 0, 0, 0, 0, 1]);
    let after: After<'_> = from_bytes(&wire).unwrap();
    assert!(after.eof);
    assert_eq!(after.names.len(), 2);
    let names: Vec<&[u8]> =
        elements(&after.names).iter().map(|name| name.0).collect();
    assert_eq!(names, [&b"ab"[..], b"abcde"]);
    assert_eq!(after.names.encoded(), &wire[..wire.len() - 4]);
    assert_eq!(to_bytes(&after).unwrap(), wire);

    // Behind a prefix the unread tail starts after the list.
    let (list, rest) = from_prefix::<ListRef<'_, u32>>(&TWO).unwrap();
    assert_eq!((list.len(), rest.len()), (2, 0));
    let mut longer = TWO.to_vec();
    longer.extend([9, 9, 9, 9]);
    let (list, rest) = from_prefix::<ListRef<'_, u32>>(&longer).unwrap();
    assert_eq!((list.len(), rest), (2, &[9, 9, 9, 9][..]));
}

/// This catches a boolean that is read as any word. §4.4 allows 0 and 1
/// alone, so a 2 before an element is an error when strict, and is taken
/// as a 1 when lenient, as any boolean is.
#[test]
fn a_boolean_other_than_zero_or_one_is_refused_when_strict() {
    let mut wire = TWO;
    wire[3] = 2;
    let strict = from_bytes_with::<ListRef<'_, u32>>(&wire, Strictness::Strict);
    assert!(strict.is_err());
    let lenient =
        from_bytes_with::<ListRef<'_, u32>>(&wire, Strictness::Lenient);
    assert_eq!(elements(&lenient.unwrap()), [7, 8]);
}

/// This catches a list that decodes without its boolean of 0 or with an
/// element cut short.
#[test]
fn a_list_cut_short_is_an_error_at_every_length() {
    for cut in 0..TWO.len() {
        assert!(
            from_bytes::<ListRef<'_, u32>>(&TWO[..cut]).is_err(),
            "decoded from {cut} bytes"
        );
    }
}

/// This catches bytes taken as a list when they hold more or less than one.
#[test]
fn from_encoded_takes_a_whole_list_and_nothing_else() {
    let list = ListRef::<u32>::from_encoded(&TWO).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(elements(&list), [7, 8]);
    assert_eq!(to_bytes(&list).unwrap(), TWO);
    let mut longer = TWO.to_vec();
    longer.extend([0, 0, 0, 0]);
    assert_eq!(
        ListRef::<u32>::from_encoded(&longer).unwrap_err(),
        Error::TrailingBytes { rest: 4 }
    );
    assert!(matches!(
        ListRef::<u32>::from_encoded(&TWO[..16]).unwrap_err(),
        Error::Eof { .. }
    ));
}
