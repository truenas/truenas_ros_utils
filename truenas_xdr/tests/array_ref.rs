// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! A variable-length array that stays in the input, RFC 4506 §4.13.
//!
//! The array keeps its count and the bytes of its elements. Each case here
//! checks that those bytes are the right ones, that they are the caller's and
//! not a copy, or that an array the input cannot back is refused.

use serde::{Deserialize, Serialize};
use truenas_xdr::{
    Bounded, Error, Strictness, VarArrayRef, VarOpaqueRef, from_bytes,
    from_bytes_with, from_prefix, serialized_size, to_bytes,
};

/// Whether `part` points into `whole` rather than at separate storage.
fn borrows_from(part: &[u8], whole: &[u8]) -> bool {
    let (start, end) = (
        whole.as_ptr() as usize,
        whole.as_ptr() as usize + whole.len(),
    );
    let at = part.as_ptr() as usize;
    at >= start && at + part.len() <= end
}

/// The elements of `array`, each decoded.
fn elements<'a, T: Deserialize<'a>>(array: &VarArrayRef<'a, T>) -> Vec<T> {
    array.iter().collect::<Result<Vec<T>, Error>>().unwrap()
}

/// This catches an array that is laid out otherwise than §4.13 has it, which
/// is the count as an unsigned integer and then each element in order.
#[test]
fn an_array_is_its_count_and_then_its_elements() {
    let wire = [0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 8];
    let array: VarArrayRef<'_, u32> = from_bytes(&wire).unwrap();
    assert_eq!(array.len(), 2);
    assert!(!array.is_empty());
    assert_eq!(elements(&array), [7, 8]);
    assert_eq!(to_bytes(&array).unwrap(), wire);
    assert_eq!(serialized_size(&array).unwrap(), wire.len());
    // The same elements in a `Vec` are the same bytes.
    assert_eq!(to_bytes(&vec![7u32, 8]).unwrap(), wire);

    let none: VarArrayRef<'_, u32> = from_bytes(&[0, 0, 0, 0]).unwrap();
    assert!(none.is_empty());
    assert_eq!(elements(&none), [0u32; 0]);
    assert_eq!(none, VarArrayRef::default());
    assert_eq!(to_bytes(&none).unwrap(), [0, 0, 0, 0]);
}

/// This catches an array that copies its elements out of the input.
#[test]
fn the_elements_are_a_borrow_of_the_input() {
    let wire = [0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 8];
    let array: VarArrayRef<'_, u32> = from_bytes(&wire).unwrap();
    assert!(std::ptr::eq(array.encoded().as_ptr(), wire[4..].as_ptr()));
    assert_eq!(array.encoded(), &wire[4..]);
}

/// This catches a span that ends at the wrong place when elements differ in
/// length, and an element's own opaque being taken for the span. The two
/// elements are opaque data of three bytes and of one.
#[test]
fn elements_of_differing_length_are_each_found() {
    let wire = [0, 0, 0, 2, 0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 0, 1, 9, 0, 0, 0];
    let array: VarArrayRef<'_, VarOpaqueRef<'_>> = from_bytes(&wire).unwrap();
    assert_eq!(array.len(), 2);
    assert_eq!(array.encoded(), &wire[4..]);
    let found = elements(&array);
    assert_eq!(found, [VarOpaqueRef(&[1, 2, 3]), VarOpaqueRef(&[9])]);
    // Each element is the caller's bytes too.
    assert!(found.iter().all(|opaque| borrows_from(opaque.0, &wire)));
    assert_eq!(to_bytes(&array).unwrap(), wire);
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Between<'a> {
    before: u32,
    #[serde(borrow)]
    names: VarArrayRef<'a, &'a str>,
    after: u32,
}

/// This catches an array that takes too few or too many bytes of the value
/// around it. The field behind the array must be read from where the array
/// ends.
#[test]
fn what_follows_an_array_is_read_from_where_it_ends() {
    let wire = [
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0, 0, 1, b'c',
        0, 0, 0, 0, 0, 0, 5,
    ];
    let value: Between<'_> = from_bytes(&wire).unwrap();
    assert_eq!((value.before, value.after), (1, 5));
    assert_eq!(elements(&value.names), ["ab", "c"]);
    assert_eq!(value.names.encoded(), &wire[8..24]);
    assert_eq!(to_bytes(&value).unwrap(), wire);

    // Read from the front of a longer input, the array leaves the rest.
    let (names, rest) =
        from_prefix::<VarArrayRef<'_, &str>>(&wire[4..]).unwrap();
    assert_eq!(names, value.names);
    assert_eq!(rest, [0, 0, 0, 5]);
}

/// This catches an inner array that moves the start of the outer one. The
/// outer array holds one array of two numbers and one of one number.
#[test]
fn an_array_of_arrays_keeps_each_span_apart() {
    let wire = [
        0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 3,
    ];
    let outer: VarArrayRef<'_, VarArrayRef<'_, u32>> =
        from_bytes(&wire).unwrap();
    assert_eq!(outer.len(), 2);
    assert_eq!(outer.encoded(), &wire[4..]);
    let inner = elements(&outer);
    assert_eq!(inner[0].encoded(), &wire[8..16]);
    assert_eq!(inner[1].encoded(), &wire[20..24]);
    assert_eq!(elements(&inner[0]), [1, 2]);
    assert_eq!(elements(&inner[1]), [3]);
    assert_eq!(to_bytes(&outer).unwrap(), wire);
}

/// This catches a bound that does not reach the count of a borrowed array,
/// on the way in or on the way out.
#[test]
fn a_bound_holds_the_count_in_both_directions() {
    type AtMostTwo<'a> = Bounded<VarArrayRef<'a, u32>, 2>;
    let two = [0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 8];
    let array: AtMostTwo<'_> = from_bytes(&two).unwrap();
    assert_eq!(elements(&array.0), [7, 8]);
    assert_eq!(to_bytes(&array).unwrap(), two);

    // The count is refused before any element is read, so the elements
    // need not be there.
    let too_long = Error::TooLong { len: 3, max: 2 };
    let three = [0, 0, 0, 3];
    assert_eq!(from_bytes::<AtMostTwo<'_>>(&three).unwrap_err(), too_long);

    let encoded = [0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3];
    let built = VarArrayRef::<u32>::from_encoded(3, &encoded).unwrap();
    assert_eq!(to_bytes(&Bounded::<_, 2>(built)).unwrap_err(), too_long);
    assert!(to_bytes(&Bounded::<_, 3>(built)).is_ok());
}

/// This catches an array that decodes from fewer bytes than it has, and a
/// count the input cannot back.
#[test]
fn an_array_the_input_cannot_back_is_refused() {
    let wire = [0, 0, 0, 2, 0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 0, 1, 9, 0, 0, 0];
    for cut in 0..wire.len() {
        let short =
            from_bytes::<VarArrayRef<'_, VarOpaqueRef<'_>>>(&wire[..cut]);
        assert!(short.is_err(), "decoded from {cut} of {} bytes", wire.len());
    }
    // A count far past the input, with one element behind it.
    let huge = [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1];
    assert!(matches!(
        from_bytes::<VarArrayRef<'_, u32>>(&huge),
        Err(Error::Eof { .. })
    ));
    // The same count over an element that takes no bytes at all.
    assert!(matches!(
        from_bytes::<VarArrayRef<'_, ()>>(&huge[..4]),
        Err(Error::Eof { .. })
    ));
}

/// This catches an array that accepts an element its type refuses. §4.4 has
/// a boolean be 0 or 1, and §4.11 has a string hold bytes this crate reads
/// as UTF-8.
#[test]
fn an_element_that_does_not_decode_fails_the_array() {
    let two = [0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2];
    assert_eq!(
        from_bytes_with::<VarArrayRef<'_, bool>>(&two, Strictness::Strict),
        Err(Error::InvalidBool { value: 2 })
    );
    let not_text = [0, 0, 0, 1, 0, 0, 0, 1, 0xff, 0, 0, 0];
    assert_eq!(
        from_bytes::<VarArrayRef<'_, &str>>(&not_text),
        Err(Error::Utf8)
    );
}

/// This catches elements that were accepted when the array was decoded and
/// are refused when they are read. A lenient decode takes a boolean of 2 and
/// padding that is not zero, and the array hands both back.
#[test]
fn what_decoded_leniently_is_still_read_and_written_as_it_came() {
    let odd_bool = [0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2];
    let array: VarArrayRef<'_, bool> =
        from_bytes_with(&odd_bool, Strictness::Lenient).unwrap();
    assert_eq!(elements(&array), [true, true]);
    assert_eq!(to_bytes(&array).unwrap(), odd_bool);

    let odd_pad = [0, 0, 0, 1, 0, 0, 0, 1, 9, 0, 0, 7];
    let array: VarArrayRef<'_, VarOpaqueRef<'_>> =
        from_bytes_with(&odd_pad, Strictness::Lenient).unwrap();
    assert_eq!(elements(&array), [VarOpaqueRef(&[9])]);
    assert_eq!(to_bytes(&array).unwrap(), odd_pad);
    // The strict decode refuses the same bytes.
    let strict = from_bytes_with::<VarArrayRef<'_, VarOpaqueRef<'_>>>(
        &odd_pad,
        Strictness::Strict,
    );
    assert_eq!(strict, Err(Error::NonZeroPadding));
}

/// This catches an array built from bytes that do not hold the elements it
/// claims.
#[test]
fn an_array_is_built_only_from_bytes_that_hold_its_elements() {
    let encoded = [0, 0, 0, 7, 0, 0, 0, 8];
    let array = VarArrayRef::<u32>::from_encoded(2, &encoded).unwrap();
    assert_eq!(elements(&array), [7, 8]);
    assert_eq!(
        to_bytes(&array).unwrap(),
        [0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 8]
    );
    assert_eq!(array, from_bytes(&to_bytes(&array).unwrap()).unwrap());

    assert_eq!(
        VarArrayRef::<u32>::from_encoded(1, &encoded),
        Err(Error::TrailingBytes { rest: 4 })
    );
    assert_eq!(
        VarArrayRef::<u32>::from_encoded(3, &encoded),
        Err(Error::Eof { need: 4 })
    );
    assert_eq!(
        VarArrayRef::<u64>::from_encoded(2, &encoded),
        Err(Error::Eof { need: 8 })
    );
    // A count no input could back, over an element that takes no bytes.
    assert!(VarArrayRef::<()>::from_encoded(usize::MAX, &[]).is_err());
    // Building holds the elements to what an encoder may emit.
    assert_eq!(
        VarArrayRef::<bool>::from_encoded(1, &[0, 0, 0, 2]),
        Err(Error::InvalidBool { value: 2 })
    );
}

/// This catches two arrays being told apart, or taken for one another, by
/// anything but their count and their bytes.
#[test]
fn arrays_are_equal_when_their_counts_and_bytes_are() {
    let wire = [0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 8];
    let copy = wire;
    let a: VarArrayRef<'_, u32> = from_bytes(&wire).unwrap();
    let b: VarArrayRef<'_, u32> = from_bytes(&copy).unwrap();
    assert_eq!(a, b);
    let other: VarArrayRef<'_, u32> =
        from_bytes(&[0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 9]).unwrap();
    assert_ne!(a, other);
    // The same bytes read as one element of eight bytes are another array.
    let one = VarArrayRef::<u64>::from_encoded(1, &wire[4..]).unwrap();
    assert_eq!((one.len(), one.encoded()), (1, a.encoded()));

    // Equal arrays hash alike, so they are one entry in a set.
    let set: std::collections::HashSet<VarArrayRef<'_, u32>> =
        [a, b, other].into_iter().collect();
    assert_eq!(set.len(), 2);

    let shown = format!("{a:?}");
    assert!(shown.starts_with("VarArrayRef { len: 2"), "{shown}");
    let mut walk = a.iter();
    assert_eq!(walk.len(), 2);
    assert_eq!(walk.next(), Some(Ok(7)));
    assert_eq!(walk.size_hint(), (1, Some(1)));
    assert!(format!("{walk:?}").starts_with("VarArrayIter { left: 1"));
}
