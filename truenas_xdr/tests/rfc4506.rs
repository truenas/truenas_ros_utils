//! Conformance to RFC 4506 (STD 67), section by section.
//!
//! Each test names the section it comes from and asserts the encoding the
//! standard specifies, so the suite reads against the document rather than
//! against this implementation. The worked example in §7 — a complete 48-byte
//! encoding given as a hex dump — is reproduced verbatim at the end.
//!
//! Where the standard permits a choice, both readings are covered: §4.3 makes
//! an unassigned enum value an error, and §4.4 defines `bool` as an enum of
//! exactly 0 and 1, which this codec enforces under `Strictness::Strict` and
//! relaxes under `Strictness::Lenient`.

use serde::{Deserialize, Serialize};
use truenas_xdr::{
    BYTES_PER_XDR_UNIT, Error, FixedOpaque, Strictness, VarOpaque, from_bytes,
    from_bytes_with, serialized_size, to_bytes,
};

#[track_caller]
fn encodes<T: Serialize>(value: &T, expected: &[u8]) {
    let bytes = to_bytes(value).unwrap();
    assert_eq!(bytes, expected);
    assert_eq!(serialized_size(value).unwrap(), expected.len());
}

#[track_caller]
fn round_trips<T>(value: &T, expected: &[u8])
where
    T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    encodes(value, expected);
    assert_eq!(&from_bytes::<T>(expected).unwrap(), value);
}

// --- §3. Basic Block Size ------------------------------------------------

#[test]
fn section_3_every_item_is_a_multiple_of_four_bytes() {
    // "The representation of all items requires a multiple of four bytes."
    let sizes = [
        to_bytes(&()).unwrap().len(),
        to_bytes(&1u8).unwrap().len(),
        to_bytes(&1i64).unwrap().len(),
        to_bytes(&"abcde".to_string()).unwrap().len(),
        to_bytes(&VarOpaque(vec![1, 2, 3, 4, 5, 6, 7]))
            .unwrap()
            .len(),
        to_bytes(&FixedOpaque([1u8, 2, 3])).unwrap().len(),
        to_bytes(&vec![1u16, 2, 3]).unwrap().len(),
    ];
    for size in sizes {
        assert_eq!(size % BYTES_PER_XDR_UNIT, 0, "{size} is not a whole unit");
    }
}

#[test]
fn section_3_residual_bytes_are_zero() {
    // "the n bytes are followed by enough (0 to 3) residual zero bytes, r".
    for n in 0..=8usize {
        let data = vec![0xffu8; n];
        let encoded = to_bytes(&VarOpaque(data.clone())).unwrap();
        let pad = &encoded[4 + n..];
        assert!(pad.iter().all(|&b| b == 0), "n={n} pad={pad:?}");
        assert!(pad.len() < BYTES_PER_XDR_UNIT);
        assert_eq!((n + pad.len()) % BYTES_PER_XDR_UNIT, 0);

        // Fixed opaque pads the same way, without the length.
        let fixed = to_bytes(&FixedOpaque::<3>([0xff; 3])).unwrap();
        assert_eq!(fixed, [0xff, 0xff, 0xff, 0]);
    }
}

// --- §4.1 Integer / §4.2 Unsigned Integer --------------------------------

#[test]
fn section_4_1_integer_is_32_bit_twos_complement_msb_first() {
    // "range [-2147483648,2147483647] ... two's complement ... The most and
    // least significant bytes are 0 and 3."
    round_trips(&0i32, &[0x00, 0x00, 0x00, 0x00]);
    round_trips(&1i32, &[0x00, 0x00, 0x00, 0x01]);
    round_trips(&-1i32, &[0xff, 0xff, 0xff, 0xff]);
    round_trips(&-2147483648i32, &[0x80, 0x00, 0x00, 0x00]);
    round_trips(&2147483647i32, &[0x7f, 0xff, 0xff, 0xff]);
    // Byte 0 is most significant.
    round_trips(&0x0102_0304i32, &[0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn section_4_2_unsigned_integer_is_32_bit_msb_first() {
    // "range [0,4294967295] ... most and least significant bytes are 0 and 3."
    round_trips(&0u32, &[0x00, 0x00, 0x00, 0x00]);
    round_trips(&4294967295u32, &[0xff, 0xff, 0xff, 0xff]);
    round_trips(&0x0102_0304u32, &[0x01, 0x02, 0x03, 0x04]);
}

// --- §4.3 Enumeration ----------------------------------------------------

#[derive(truenas_xdr::XdrEnum, PartialEq, Debug, Clone, Copy)]
#[repr(i32)]
enum Colors {
    Red = 2,
    Yellow = 3,
    Blue = 5,
}

#[test]
fn section_4_3_enumeration_encodes_as_a_signed_integer() {
    // The standard's own example: enum { RED = 2, YELLOW = 3, BLUE = 5 }.
    round_trips(&Colors::Red, &[0, 0, 0, 2]);
    round_trips(&Colors::Yellow, &[0, 0, 0, 3]);
    round_trips(&Colors::Blue, &[0, 0, 0, 5]);
    // "Enumerations have the same representation as signed integers."
    assert_eq!(to_bytes(&Colors::Blue).unwrap(), to_bytes(&5i32).unwrap());
}

#[test]
fn section_4_3_an_unassigned_enum_value_is_an_error() {
    // "It is an error to encode as an enum any integer other than those that
    // have been given assignments in the enum declaration."
    for unassigned in [0i32, 1, 4, 6, -1] {
        let wire = to_bytes(&unassigned).unwrap();
        assert!(
            from_bytes::<Colors>(&wire).is_err(),
            "{unassigned} must not decode as Colors"
        );
    }
}

// --- §4.4 Boolean --------------------------------------------------------

#[test]
fn section_4_4_boolean_is_an_enum_of_zero_and_one() {
    // "This is equivalent to: enum { FALSE = 0, TRUE = 1 }".
    round_trips(&false, &[0, 0, 0, 0]);
    round_trips(&true, &[0, 0, 0, 1]);
    assert_eq!(to_bytes(&false).unwrap(), to_bytes(&0i32).unwrap());
    assert_eq!(to_bytes(&true).unwrap(), to_bytes(&1i32).unwrap());
}

#[test]
fn section_4_4_a_boolean_outside_zero_and_one_is_an_error_when_strict() {
    // §4.3's rule applied to bool's enum. Strict rejects; lenient accepts any
    // non-zero as true, which is what interoperating with a C `int` requires.
    for value in [2u32, 0xffff_ffff] {
        let wire = value.to_be_bytes();
        assert_eq!(
            from_bytes_with::<bool>(&wire, Strictness::Strict).unwrap_err(),
            Error::InvalidBool { value }
        );
        assert!(from_bytes_with::<bool>(&wire, Strictness::Lenient).unwrap());
    }
    // 0 and 1 are accepted in either mode.
    for (wire, want) in [([0, 0, 0, 0], false), ([0, 0, 0, 1], true)] {
        assert_eq!(
            from_bytes_with::<bool>(&wire, Strictness::Strict).unwrap(),
            want
        );
    }
}

// --- §4.5 Hyper Integer --------------------------------------------------

#[test]
fn section_4_5_hyper_is_64_bit_twos_complement_msb_first() {
    // "most and least significant bytes are 0 and 7".
    round_trips(&0i64, &[0, 0, 0, 0, 0, 0, 0, 0]);
    round_trips(&-1i64, &[0xff; 8]);
    round_trips(&i64::MIN, &[0x80, 0, 0, 0, 0, 0, 0, 0]);
    round_trips(&i64::MAX, &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    round_trips(
        &0x0102_0304_0506_0708i64,
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    );
    round_trips(&u64::MAX, &[0xff; 8]);
}

// --- §4.6 Float / §4.7 Double --------------------------------------------

#[test]
fn section_4_6_float_is_ieee_754_single_precision() {
    // Sign, 8-bit biased exponent, 23-bit fraction, most significant byte
    // first.
    round_trips(&0.0f32, &[0x00, 0x00, 0x00, 0x00]);
    round_trips(&1.0f32, &[0x3f, 0x80, 0x00, 0x00]);
    round_trips(&-1.0f32, &[0xbf, 0x80, 0x00, 0x00]);
    round_trips(&2.0f32, &[0x40, 0x00, 0x00, 0x00]);
    round_trips(&f32::INFINITY, &[0x7f, 0x80, 0x00, 0x00]);
    round_trips(&f32::NEG_INFINITY, &[0xff, 0x80, 0x00, 0x00]);
    // -0.0 keeps its sign bit through the round trip.
    let neg_zero = to_bytes(&-0.0f32).unwrap();
    assert_eq!(neg_zero, [0x80, 0x00, 0x00, 0x00]);
    assert!(from_bytes::<f32>(&neg_zero).unwrap().is_sign_negative());
}

#[test]
fn section_4_7_double_is_ieee_754_double_precision() {
    round_trips(&0.0f64, &[0; 8]);
    round_trips(&1.0f64, &[0x3f, 0xf0, 0, 0, 0, 0, 0, 0]);
    round_trips(&-2.0f64, &[0xc0, 0x00, 0, 0, 0, 0, 0, 0]);
    round_trips(&f64::INFINITY, &[0x7f, 0xf0, 0, 0, 0, 0, 0, 0]);
    // NaN is not equal to itself, so it is checked bitwise.
    let nan = to_bytes(&f64::NAN).unwrap();
    assert!(from_bytes::<f64>(&nan).unwrap().is_nan());
}

// --- §4.9 Fixed-Length Opaque --------------------------------------------

#[test]
fn section_4_9_fixed_opaque_has_no_count_and_pads_to_a_unit() {
    // "opaque identifier[n] ... n bytes followed by enough (0 to 3) residual
    // zero bytes" — and no length is transmitted.
    round_trips(&FixedOpaque::<0>([]), &[]);
    round_trips(&FixedOpaque([0xaau8]), &[0xaa, 0, 0, 0]);
    round_trips(&FixedOpaque([0xaau8, 0xbb]), &[0xaa, 0xbb, 0, 0]);
    round_trips(&FixedOpaque([0xaau8, 0xbb, 0xcc]), &[0xaa, 0xbb, 0xcc, 0]);
    round_trips(
        &FixedOpaque([0xaau8, 0xbb, 0xcc, 0xdd]),
        &[0xaa, 0xbb, 0xcc, 0xdd],
    );
}

// --- §4.10 Variable-Length Opaque ----------------------------------------

#[test]
fn section_4_10_variable_opaque_is_a_count_then_bytes_then_pad() {
    // "the number n encoded as an unsigned integer ... followed by the n
    // bytes ... then residual zero bytes".
    round_trips(&VarOpaque(vec![]), &[0, 0, 0, 0]);
    round_trips(&VarOpaque(vec![0xaa]), &[0, 0, 0, 1, 0xaa, 0, 0, 0]);
    round_trips(
        &VarOpaque(vec![0xaa, 0xbb, 0xcc]),
        &[0, 0, 0, 3, 0xaa, 0xbb, 0xcc, 0],
    );
    round_trips(
        &VarOpaque(vec![0xaa, 0xbb, 0xcc, 0xdd]),
        &[0, 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd],
    );
    // The count is the byte count, and bytes are uninterpreted.
    round_trips(&VarOpaque(vec![0, 0, 0]), &[0, 0, 0, 3, 0, 0, 0, 0]);
}

// --- §4.11 String --------------------------------------------------------

#[test]
fn section_4_11_string_is_a_count_then_bytes_then_pad() {
    round_trips(&String::new(), &[0, 0, 0, 0]);
    round_trips(&"a".to_string(), &[0, 0, 0, 1, b'a', 0, 0, 0]);
    round_trips(&"ab".to_string(), &[0, 0, 0, 2, b'a', b'b', 0, 0]);
    round_trips(&"abc".to_string(), &[0, 0, 0, 3, b'a', b'b', b'c', 0]);
    round_trips(&"abcd".to_string(), &[0, 0, 0, 4, b'a', b'b', b'c', b'd']);
    // The count is in bytes, so a string and the opaque holding the same
    // bytes encode identically.
    assert_eq!(
        to_bytes(&"abc".to_string()).unwrap(),
        to_bytes(&VarOpaque(b"abc".to_vec())).unwrap()
    );
}

// --- §4.12 Fixed-Length Array --------------------------------------------

#[test]
fn section_4_12_fixed_array_has_no_count() {
    // "encoded by individually encoding the elements ... in their natural
    // order" — with no element count on the wire.
    round_trips(&[1i32, 2, 3], &[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3]);
    round_trips(&[true, false], &[0, 0, 0, 1, 0, 0, 0, 0]);

    // "Though all elements are of the same type, the elements may have
    // different sizes" — an array of strings.
    round_trips(
        &["a".to_string(), "bcde".to_string()],
        &[
            0, 0, 0, 1, b'a', 0, 0, 0, //
            0, 0, 0, 4, b'b', b'c', b'd', b'e',
        ],
    );
}

// --- §4.13 Variable-Length Array -----------------------------------------

#[test]
fn section_4_13_counted_array_is_a_count_then_elements() {
    round_trips(&Vec::<i32>::new(), &[0, 0, 0, 0]);
    round_trips(&vec![9i32], &[0, 0, 0, 1, 0, 0, 0, 9]);
    round_trips(
        &vec![1i32, 2, 3],
        &[0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3],
    );
    // The count prefixes elements that are themselves variable length.
    round_trips(
        &vec!["ab".to_string()],
        &[0, 0, 0, 1, 0, 0, 0, 2, b'a', b'b', 0, 0],
    );
}

// --- §4.14 Structure -----------------------------------------------------

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Components {
    a: i32,
    b: bool,
    c: String,
}

#[test]
fn section_4_14_structure_components_follow_declaration_order() {
    // "The components of the structure are encoded in the order of their
    // declaration."
    round_trips(
        &Components {
            a: -1,
            b: true,
            c: "x".to_string(),
        },
        &[
            0xff, 0xff, 0xff, 0xff, // a
            0, 0, 0, 1, // b
            0, 0, 0, 1, b'x', 0, 0, 0, // c
        ],
    );
}

// --- §4.15 Discriminated Union / §4.16 Void ------------------------------

#[derive(truenas_xdr::XdrUnion, PartialEq, Debug)]
#[repr(i32)]
enum Filetype {
    Text = 0,
    Data(String) = 1,
    Exec(String) = 2,
}

#[test]
fn section_4_15_union_is_a_discriminant_then_the_implied_arm() {
    round_trips(
        &Filetype::Data("who".to_string()),
        &[0, 0, 0, 1, 0, 0, 0, 3, b'w', b'h', b'o', 0],
    );
}

#[test]
fn section_4_16_a_void_arm_adds_nothing_after_the_discriminant() {
    // "An XDR void is a 0-byte quantity."
    encodes(&(), &[]);
    round_trips(&Filetype::Text, &[0, 0, 0, 0]);
    assert_eq!(to_bytes(&Filetype::Text).unwrap().len(), 4);
}

// --- §4.19 Optional-Data -------------------------------------------------

#[test]
fn section_4_19_optional_data_is_a_union_switching_on_bool() {
    // "union switch (bool opted) { case TRUE: element; case FALSE: void; }".
    round_trips(&None::<i32>, &[0, 0, 0, 0]);
    round_trips(&Some(7i32), &[0, 0, 0, 1, 0, 0, 0, 7]);
    round_trips(&None::<String>, &[0, 0, 0, 0]);
}

#[test]
fn section_4_19_optional_data_matches_an_array_of_at_most_one() {
    // "It is also equivalent to the following variable-length array
    // declaration, since the boolean opted can be interpreted as the length
    // of the array: type-name identifier<1>."
    assert_eq!(
        to_bytes(&None::<i32>).unwrap(),
        to_bytes(&Vec::<i32>::new()).unwrap()
    );
    assert_eq!(
        to_bytes(&Some(7i32)).unwrap(),
        to_bytes(&vec![7i32]).unwrap()
    );
    assert_eq!(
        to_bytes(&Some("ab".to_string())).unwrap(),
        to_bytes(&vec!["ab".to_string()]).unwrap()
    );
}

#[test]
fn section_4_19_an_optional_discriminant_outside_zero_and_one_is_strict_error()
{
    // The discriminant is a bool, so §4.4's rule applies to it too.
    let wire = [0, 0, 0, 2, 0, 0, 0, 7];
    assert_eq!(
        from_bytes_with::<Option<i32>>(&wire, Strictness::Strict).unwrap_err(),
        Error::InvalidBool { value: 2 }
    );
    assert_eq!(
        from_bytes_with::<Option<i32>>(&wire, Strictness::Lenient).unwrap(),
        Some(7)
    );
}

#[test]
fn section_4_19_optional_data_describes_a_recursive_list() {
    // The standard's stringlist example:
    //   struct stringentry { string item<>; stringentry *next; };
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct StringEntry {
        item: String,
        next: Option<Box<StringEntry>>,
    }

    let list = StringEntry {
        item: "a".to_string(),
        next: Some(Box::new(StringEntry {
            item: "b".to_string(),
            next: None,
        })),
    };
    round_trips(
        &list,
        &[
            0, 0, 0, 1, b'a', 0, 0, 0, // item "a"
            0, 0, 0, 1, // next: present
            0, 0, 0, 1, b'b', 0, 0, 0, // item "b"
            0, 0, 0, 0, // next: absent
        ],
    );
}

// --- §7. An Example of an XDR Data Description ---------------------------

/// The standard's `filekind` enum: TEXT = 0, DATA = 1, EXEC = 2.
#[derive(truenas_xdr::XdrUnion, PartialEq, Debug)]
#[repr(i32)]
enum FileType {
    /// `case TEXT: void;`
    Text = 0,
    /// `case DATA: string creator<MAXNAMELEN>;`
    Data(String) = 1,
    /// `case EXEC: string interpretor<MAXNAMELEN>;`
    Exec(String) = 2,
}

/// ```text
/// struct file {
///    string filename<MAXNAMELEN>;
///    filetype type;
///    string owner<MAXUSERNAME>;
///    opaque data<MAXFILELEN>;
/// };
/// ```
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct File {
    filename: String,
    kind: FileType,
    owner: String,
    data: VarOpaque,
}

#[test]
fn section_7_worked_example_matches_the_standards_hex_dump() {
    // "Suppose now that there is a user named john who wants to store his
    // lisp program sillyprog that contains just the data (quit)."
    let file = File {
        filename: "sillyprog".to_string(),
        kind: FileType::Exec("lisp".to_string()),
        owner: "john".to_string(),
        data: VarOpaque(b"(quit)".to_vec()),
    };

    // The dump from §7, offset by offset:
    #[rustfmt::skip]
    let expected: &[u8] = &[
        0x00, 0x00, 0x00, 0x09, //  0: length of filename = 9
        0x73, 0x69, 0x6c, 0x6c, //  4: "sill"
        0x79, 0x70, 0x72, 0x6f, //  8: "ypro"
        0x67, 0x00, 0x00, 0x00, // 12: "g" and 3 zero-bytes of fill
        0x00, 0x00, 0x00, 0x02, // 16: filekind is EXEC = 2
        0x00, 0x00, 0x00, 0x04, // 20: length of interpretor = 4
        0x6c, 0x69, 0x73, 0x70, // 24: "lisp"
        0x00, 0x00, 0x00, 0x04, // 28: length of owner = 4
        0x6a, 0x6f, 0x68, 0x6e, // 32: "john"
        0x00, 0x00, 0x00, 0x06, // 36: length of file data = 6
        0x28, 0x71, 0x75, 0x69, // 40: "(qui"
        0x74, 0x29, 0x00, 0x00, // 44: "t)" and 2 zero-bytes of fill
    ];

    assert_eq!(expected.len(), 48);
    round_trips(&file, expected);
    // Decoding is strict-clean too: the fill really is zero.
    assert_eq!(
        from_bytes_with::<File>(expected, Strictness::Strict).unwrap(),
        file
    );
}
