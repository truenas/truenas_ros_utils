// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Codec tests: canonical byte layouts, round-trips, and the error paths.
//!
//! Expected encodings are written out by hand from RFC 4506 rather than
//! captured from this implementation, so a test failing means the wire changed
//! and not just that the code did.

use serde::{Deserialize, Serialize};
use truenas_xdr::{
    BYTES_PER_XDR_UNIT, Error, FixedOpaque, Strictness, VarOpaque, from_bytes,
    from_bytes_with, from_prefix, from_prefix_with, serialized_size, to_bytes,
    to_writer,
};

/// Encode `value`, check it byte for byte, decode it back, and check that
/// `serialized_size` and `to_writer` agree with `to_bytes`.
#[track_caller]
fn check<T>(value: &T, expected: &[u8])
where
    T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    let bytes = to_bytes(value).unwrap();
    assert_eq!(bytes, expected, "encoding of {value:?}");
    assert_eq!(
        bytes.len() % BYTES_PER_XDR_UNIT,
        0,
        "encodings are whole units"
    );
    assert_eq!(serialized_size(value).unwrap(), bytes.len());

    let mut written = Vec::new();
    to_writer(&mut written, value).unwrap();
    assert_eq!(written, bytes, "to_writer matches to_bytes");

    let decoded: T = from_bytes(&bytes).unwrap();
    assert_eq!(&decoded, value, "round trip of {value:?}");
}

// --- scalars -------------------------------------------------------------

#[test]
fn booleans_are_one_unit() {
    check(&false, &[0, 0, 0, 0]);
    check(&true, &[0, 0, 0, 1]);
    // Decoding is lenient about which non-zero value stands for true.
    assert!(from_bytes::<bool>(&[0, 0, 0, 2]).unwrap());
}

#[test]
fn signed_integers_are_big_endian_twos_complement() {
    check(&0i32, &[0, 0, 0, 0]);
    check(&1i32, &[0, 0, 0, 1]);
    check(&-1i32, &[0xff, 0xff, 0xff, 0xff]);
    check(&i32::MIN, &[0x80, 0, 0, 0]);
    check(&i32::MAX, &[0x7f, 0xff, 0xff, 0xff]);
    // Narrower types widen to one unit.
    check(&-2i8, &[0xff, 0xff, 0xff, 0xfe]);
    check(&-2i16, &[0xff, 0xff, 0xff, 0xfe]);
}

#[test]
fn unsigned_integers_are_big_endian() {
    check(&0u32, &[0, 0, 0, 0]);
    check(&u32::MAX, &[0xff, 0xff, 0xff, 0xff]);
    check(&7u8, &[0, 0, 0, 7]);
    check(&258u16, &[0, 0, 1, 2]);
}

#[test]
fn hypers_are_two_units() {
    check(&0i64, &[0, 0, 0, 0, 0, 0, 0, 0]);
    check(&-1i64, &[0xff; 8]);
    check(&i64::MAX, &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    check(&1u64, &[0, 0, 0, 0, 0, 0, 0, 1]);
    check(&u64::MAX, &[0xff; 8]);
}

#[test]
fn floats_are_ieee_754_big_endian() {
    check(&1.0f32, &[0x3f, 0x80, 0x00, 0x00]);
    check(&-2.0f32, &[0xc0, 0x00, 0x00, 0x00]);
    check(&1.0f64, &[0x3f, 0xf0, 0, 0, 0, 0, 0, 0]);
    check(&0.0f64, &[0; 8]);

    // NaN survives the bit-level round trip even though it is not equal to
    // itself, so it cannot go through `check`.
    let bytes = to_bytes(&f64::NAN).unwrap();
    assert!(from_bytes::<f64>(&bytes).unwrap().is_nan());
    assert_eq!(to_bytes(&f32::INFINITY).unwrap(), [0x7f, 0x80, 0x00, 0x00]);
}

#[test]
fn chars_are_one_unit_of_code_point() {
    check(&'A', &[0, 0, 0, 0x41]);
    check(&'\u{1F600}', &[0, 0x01, 0xF6, 0x00]);
}

// --- strings and opaque --------------------------------------------------

#[test]
fn strings_are_length_prefixed_and_padded() {
    check(&String::new(), &[0, 0, 0, 0]);
    check(&"a".to_string(), &[0, 0, 0, 1, b'a', 0, 0, 0]);
    check(&"ab".to_string(), &[0, 0, 0, 2, b'a', b'b', 0, 0]);
    check(&"abc".to_string(), &[0, 0, 0, 3, b'a', b'b', b'c', 0]);
    check(&"abcd".to_string(), &[0, 0, 0, 4, b'a', b'b', b'c', b'd']);
    // Multi-byte UTF-8 is counted in bytes, not characters.
    check(&"é".to_string(), &[0, 0, 0, 2, 0xc3, 0xa9, 0, 0]);
}

#[test]
fn variable_opaque_is_length_prefixed_and_padded() {
    check(&VarOpaque(vec![]), &[0, 0, 0, 0]);
    check(&VarOpaque(vec![1]), &[0, 0, 0, 1, 1, 0, 0, 0]);
    check(&VarOpaque(vec![1, 2, 3]), &[0, 0, 0, 3, 1, 2, 3, 0]);
    check(&VarOpaque(vec![1, 2, 3, 4]), &[0, 0, 0, 4, 1, 2, 3, 4]);
    // Zero bytes inside the payload are data, not terminators.
    check(&VarOpaque(vec![0, 0xff, 0]), &[0, 0, 0, 3, 0, 0xff, 0, 0]);
}

#[test]
fn fixed_opaque_has_no_length_and_is_padded() {
    check(&FixedOpaque([1u8, 2, 3, 4]), &[1, 2, 3, 4]);
    check(&FixedOpaque([1u8]), &[1, 0, 0, 0]);
    check(&FixedOpaque([1u8, 2, 3, 4, 5]), &[1, 2, 3, 4, 5, 0, 0, 0]);
    check(&FixedOpaque::<0>([]), &[]);
    check(&FixedOpaque([0xffu8; 16]), &[0xff; 16]);
}

#[test]
fn a_vec_of_bytes_is_a_sequence_not_opaque() {
    // The distinction VarOpaque exists for: four bytes per element.
    check(&vec![1u8, 2], &[0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2]);
}

// --- composites ----------------------------------------------------------

#[test]
fn sequences_are_counted_then_concatenated() {
    check(&Vec::<i32>::new(), &[0, 0, 0, 0]);
    check(
        &vec![1i32, -1],
        &[0, 0, 0, 2, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff],
    );
    check(
        &vec!["hi".to_string()],
        &[0, 0, 0, 1, 0, 0, 0, 2, b'h', b'i', 0, 0],
    );
}

#[test]
fn fixed_arrays_and_tuples_have_no_count() {
    check(&[1i32, 2], &[0, 0, 0, 1, 0, 0, 0, 2]);
    check(&(1i32, true), &[0, 0, 0, 1, 0, 0, 0, 1]);
    check(&(), &[]);
}

#[test]
fn options_are_a_discriminant_then_the_value() {
    check(&None::<i32>, &[0, 0, 0, 0]);
    check(&Some(7i32), &[0, 0, 0, 1, 0, 0, 0, 7]);
    check(
        &Some("a".to_string()),
        &[0, 0, 0, 1, 0, 0, 0, 1, b'a', 0, 0, 0],
    );
    // Nested options each get their own discriminant.
    check(&Some(Some(1i32)), &[0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]);
    check(&Some(None::<i32>), &[0, 0, 0, 1, 0, 0, 0, 0]);
    // Any non-zero discriminant decodes as present.
    assert_eq!(
        from_bytes::<Option<i32>>(&[0, 0, 0, 9, 0, 0, 0, 5]).unwrap(),
        Some(5)
    );
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Point {
    x: i32,
    y: i32,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Nested {
    label: String,
    at: Point,
    tags: Vec<u32>,
    note: Option<String>,
}

#[test]
fn structs_concatenate_their_fields() {
    check(
        &Point { x: 1, y: -1 },
        &[0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff],
    );
}

#[test]
fn nested_structures_round_trip() {
    check(
        &Nested {
            label: "ab".to_string(),
            at: Point { x: 2, y: 3 },
            tags: vec![9],
            note: None,
        },
        &[
            0, 0, 0, 2, b'a', b'b', 0, 0, // label
            0, 0, 0, 2, 0, 0, 0, 3, // at
            0, 0, 0, 1, 0, 0, 0, 9, // tags
            0, 0, 0, 0, // note
        ],
    );
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Unit;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Wrapper(i32);

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Pair(i32, bool);

#[test]
fn unit_structs_are_empty_and_newtypes_are_transparent() {
    check(&Unit, &[]);
    check(&Wrapper(-1), &[0xff, 0xff, 0xff, 0xff]);
    check(&Pair(1, true), &[0, 0, 0, 1, 0, 0, 0, 1]);
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
enum Stock {
    First,
    Second(i32),
    Third { a: i32, b: bool },
    Fourth(i32, i32),
}

#[test]
fn stock_enums_use_the_declaration_index() {
    check(&Stock::First, &[0, 0, 0, 0]);
    check(&Stock::Second(5), &[0, 0, 0, 1, 0, 0, 0, 5]);
    check(
        &Stock::Third { a: 1, b: false },
        &[0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0],
    );
    check(&Stock::Fourth(1, 2), &[0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2]);
}

// --- decoding entry points ----------------------------------------------

#[test]
fn from_bytes_requires_exact_consumption() {
    let bytes = to_bytes(&1i32).unwrap();
    assert_eq!(from_bytes::<i32>(&bytes).unwrap(), 1);

    let mut extra = bytes.clone();
    extra.extend_from_slice(&[0, 0, 0, 2]);
    assert_eq!(
        from_bytes::<i32>(&extra).unwrap_err(),
        Error::TrailingBytes { rest: 4 }
    );
}

#[test]
fn from_prefix_returns_the_tail() {
    let mut wire = to_bytes(&(1i32, "hi".to_string())).unwrap();
    let tail_start = wire.len();
    wire.extend_from_slice(b"trailing payload");

    let (value, rest) = from_prefix::<(i32, String)>(&wire).unwrap();
    assert_eq!(value, (1, "hi".to_string()));
    assert_eq!(rest, b"trailing payload");
    assert_eq!(rest.len(), wire.len() - tail_start);

    // With nothing after the value the tail is empty.
    let exact = to_bytes(&1i32).unwrap();
    let (_, rest) = from_prefix::<i32>(&exact).unwrap();
    assert!(rest.is_empty());
}

#[test]
fn a_short_buffer_reports_how_much_was_missing() {
    assert_eq!(from_bytes::<i32>(&[]).unwrap_err(), Error::Eof { need: 4 });
    assert_eq!(
        from_bytes::<i32>(&[0, 0]).unwrap_err(),
        Error::Eof { need: 2 }
    );
    assert_eq!(
        from_bytes::<i64>(&[0; 4]).unwrap_err(),
        Error::Eof { need: 4 }
    );
    // A length prefix promising more than is present.
    assert_eq!(
        from_bytes::<String>(&[0, 0, 0, 8, b'a', b'b', b'c', b'd'])
            .unwrap_err(),
        Error::Eof { need: 4 }
    );
    // ...including when only the padding is missing.
    assert_eq!(
        from_bytes::<String>(&[0, 0, 0, 1, b'a']).unwrap_err(),
        Error::Eof { need: 3 }
    );
}

#[test]
fn out_of_range_values_are_rejected_per_target_type() {
    assert_eq!(
        from_bytes::<i8>(&[0, 0, 0x01, 0x00]).unwrap_err(),
        Error::Range
    );
    assert_eq!(
        from_bytes::<i16>(&[0, 0x01, 0, 0]).unwrap_err(),
        Error::Range
    );
    assert_eq!(
        from_bytes::<u8>(&[0, 0, 0x01, 0x00]).unwrap_err(),
        Error::Range
    );
    assert_eq!(
        from_bytes::<u16>(&[0, 0x01, 0, 0]).unwrap_err(),
        Error::Range
    );
    // A surrogate is not a scalar value, so it is not a char.
    assert_eq!(
        from_bytes::<char>(&[0, 0, 0xD8, 0x00]).unwrap_err(),
        Error::Range
    );

    // The boundaries themselves decode.
    assert_eq!(
        from_bytes::<i8>(&[0xff, 0xff, 0xff, 0x80]).unwrap(),
        i8::MIN
    );
    assert_eq!(from_bytes::<u8>(&[0, 0, 0, 0xff]).unwrap(), u8::MAX);
}

#[test]
fn invalid_utf8_is_rejected() {
    assert_eq!(
        from_bytes::<String>(&[0, 0, 0, 2, 0xff, 0xfe, 0, 0]).unwrap_err(),
        Error::Utf8
    );
}

// --- strictness ----------------------------------------------------------

#[test]
fn lenient_decoding_ignores_padding_and_nuls() {
    // A string whose pad bytes are not zero.
    let wire = [0, 0, 0, 1, b'a', 0xde, 0xad, 0xbe];
    assert_eq!(from_bytes::<String>(&wire).unwrap(), "a");
    assert_eq!(
        from_bytes::<VarOpaque>(&wire).unwrap(),
        VarOpaque(vec![b'a'])
    );

    // A string containing a NUL.
    let nul = [0, 0, 0, 2, b'a', 0, 0, 0];
    assert_eq!(from_bytes::<String>(&nul).unwrap(), "a\0");
}

#[test]
fn strict_decoding_rejects_padding_and_nuls() {
    let dirty_pad = [0, 0, 0, 1, b'a', 0xde, 0xad, 0xbe];
    assert_eq!(
        from_bytes_with::<String>(&dirty_pad, Strictness::Strict).unwrap_err(),
        Error::NonZeroPadding
    );
    assert_eq!(
        from_bytes_with::<VarOpaque>(&dirty_pad, Strictness::Strict)
            .unwrap_err(),
        Error::NonZeroPadding
    );

    let nul = [0, 0, 0, 2, b'a', 0, 0, 0];
    assert_eq!(
        from_bytes_with::<String>(&nul, Strictness::Strict).unwrap_err(),
        Error::EmbeddedNul
    );

    // Clean input decodes the same either way.
    let clean = to_bytes(&"ab".to_string()).unwrap();
    assert_eq!(
        from_bytes_with::<String>(&clean, Strictness::Strict).unwrap(),
        "ab"
    );
}

#[test]
fn strictness_reaches_fixed_opaque_and_prefix_decoding() {
    let dirty = [1u8, 0xff, 0xff, 0xff];
    assert_eq!(
        from_bytes_with::<FixedOpaque<1>>(&dirty, Strictness::Strict)
            .unwrap_err(),
        Error::NonZeroPadding
    );
    assert_eq!(
        from_bytes_with::<FixedOpaque<1>>(&dirty, Strictness::Lenient).unwrap(),
        FixedOpaque([1])
    );
    let (value, rest) =
        from_prefix_with::<FixedOpaque<1>>(&dirty, Strictness::Lenient)
            .unwrap();
    assert_eq!(value, FixedOpaque([1]));
    assert!(rest.is_empty());

    assert_eq!(Strictness::default(), Strictness::Lenient);
}

// --- unsupported constructs ---------------------------------------------

#[test]
fn maps_are_rejected_in_both_directions() {
    use std::collections::BTreeMap;
    let map = BTreeMap::from([(1i32, 2i32)]);
    assert_eq!(to_bytes(&map).unwrap_err(), Error::Unsupported("maps"));
    assert_eq!(
        from_bytes::<BTreeMap<i32, i32>>(&[0, 0, 0, 0]).unwrap_err(),
        Error::Unsupported("maps")
    );
}

#[test]
fn self_describing_decoding_is_rejected() {
    // An untagged enum asks the decoder to look at the bytes and decide, which
    // XDR cannot answer.
    #[derive(Deserialize, Debug)]
    #[serde(untagged)]
    #[allow(dead_code)] // never constructed: decoding it is the whole test
    enum Untagged {
        Int(i32),
    }
    let err = from_bytes::<Untagged>(&[0, 0, 0, 1]).unwrap_err();
    assert_eq!(err, Error::Unsupported("self-describing decoding"));
    assert!(err.to_string().contains("self-describing"));
}

#[test]
fn a_sequence_of_unknown_length_is_rejected() {
    // An iterator serialized without a size hint has no count to write.
    struct Unsized;
    impl Serialize for Unsized {
        fn serialize<S: serde::Serializer>(
            &self,
            s: S,
        ) -> Result<S::Ok, S::Error> {
            s.collect_seq((0..3).filter(|_| true))
        }
    }
    assert_eq!(
        to_bytes(&Unsized).unwrap_err(),
        Error::Unsupported("a sequence of unknown length")
    );
}

// --- sizing --------------------------------------------------------------

#[test]
fn serialized_size_matches_the_encoding_without_building_it() {
    let value = Nested {
        label: "hello".to_string(),
        at: Point { x: 1, y: 2 },
        tags: vec![1, 2, 3],
        note: Some("x".to_string()),
    };
    assert_eq!(
        serialized_size(&value).unwrap(),
        to_bytes(&value).unwrap().len()
    );
    assert_eq!(serialized_size(&()).unwrap(), 0);
    assert_eq!(serialized_size(&1u32).unwrap(), 4);
    assert_eq!(serialized_size(&"abc".to_string()).unwrap(), 8);
}

#[test]
fn to_writer_appends_so_buffers_can_be_reused() {
    let mut buf = vec![0xAA, 0xBB];
    to_writer(&mut buf, &1u32).unwrap();
    to_writer(&mut buf, &2u32).unwrap();
    assert_eq!(buf, [0xAA, 0xBB, 0, 0, 0, 1, 0, 0, 0, 2]);
}
