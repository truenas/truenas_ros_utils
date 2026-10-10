// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The `XdrEnum` and `XdrUnion` derive macros.
//!
//! The point of both is that the discriminant on the wire is the one written
//! in the type, not the variant's position, so every case here uses gaps,
//! negatives, or out-of-order values that would encode differently under a
//! stock derive.

use serde::{Deserialize, Serialize};
use truenas_xdr::{
    Error, VarOpaqueRef, XdrEnum, XdrUnion, from_bytes, serialized_size,
    to_bytes,
};

#[derive(XdrEnum, PartialEq, Debug, Clone, Copy)]
#[repr(i32)]
enum Gapped {
    Zero = 0,
    Four = 4,
    Ten = 10,
    Negative = -3,
}

#[derive(XdrEnum, PartialEq, Debug)]
#[repr(i32)]
enum Implicit {
    A = 5,
    B, // 6
    C, // 7
}

#[test]
fn an_enum_encodes_its_declared_discriminant() {
    for (value, expected) in [
        (Gapped::Zero, [0, 0, 0, 0]),
        (Gapped::Four, [0, 0, 0, 4]),
        (Gapped::Ten, [0, 0, 0, 10]),
        (Gapped::Negative, [0xff, 0xff, 0xff, 0xfd]),
    ] {
        let bytes = to_bytes(&value).unwrap();
        assert_eq!(bytes, expected, "{value:?}");
        assert_eq!(from_bytes::<Gapped>(&bytes).unwrap(), value);
        assert_eq!(serialized_size(&value).unwrap(), 4);
    }
}

#[test]
fn an_implicit_discriminant_continues_from_the_previous() {
    assert_eq!(to_bytes(&Implicit::A).unwrap(), [0, 0, 0, 5]);
    assert_eq!(to_bytes(&Implicit::B).unwrap(), [0, 0, 0, 6]);
    assert_eq!(to_bytes(&Implicit::C).unwrap(), [0, 0, 0, 7]);
    assert_eq!(from_bytes::<Implicit>(&[0, 0, 0, 7]).unwrap(), Implicit::C);
}

#[test]
fn an_unknown_enum_discriminant_is_reported_by_name() {
    let err = from_bytes::<Gapped>(&[0, 0, 0, 9]).unwrap_err();
    match &err {
        Error::Message(msg) => {
            assert!(msg.contains("Gapped"), "{msg}");
            assert!(msg.contains('9'), "{msg}");
        }
        other => panic!("expected a message, got {other:?}"),
    }
    // The declaration index is not accepted in place of the discriminant.
    assert!(from_bytes::<Gapped>(&[0, 0, 0, 1]).is_err());
}

#[derive(XdrUnion, PartialEq, Debug)]
#[repr(i32)]
enum Shape {
    Void = 1,
    Radius(u32) = 4,
    Rect { w: u32, h: u32 } = 9,
    Segment(i32, i32) = 12,
}

#[test]
fn a_union_encodes_a_discriminant_then_the_active_arm() {
    let cases: [(Shape, &[u8]); 4] = [
        (Shape::Void, &[0, 0, 0, 1]),
        (Shape::Radius(7), &[0, 0, 0, 4, 0, 0, 0, 7]),
        (
            Shape::Rect { w: 2, h: 3 },
            &[0, 0, 0, 9, 0, 0, 0, 2, 0, 0, 0, 3],
        ),
        (
            Shape::Segment(-1, 2),
            &[0, 0, 0, 12, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 2],
        ),
    ];
    for (value, expected) in cases {
        let bytes = to_bytes(&value).unwrap();
        assert_eq!(bytes, expected, "{value:?}");
        assert_eq!(from_bytes::<Shape>(&bytes).unwrap(), value);
        assert_eq!(serialized_size(&value).unwrap(), bytes.len());
    }
}

#[test]
fn a_void_arm_emits_only_its_discriminant() {
    assert_eq!(to_bytes(&Shape::Void).unwrap().len(), 4);
}

#[test]
fn an_unknown_union_discriminant_is_reported_by_name() {
    let err = from_bytes::<Shape>(&[0, 0, 0, 3]).unwrap_err();
    match &err {
        Error::Message(msg) => assert!(msg.contains("Shape"), "{msg}"),
        other => panic!("expected a message, got {other:?}"),
    }
}

#[test]
fn a_truncated_union_arm_is_an_error() {
    // The discriminant says Rect, but only one of its two fields follows.
    assert_eq!(
        from_bytes::<Shape>(&[0, 0, 0, 9, 0, 0, 0, 2]).unwrap_err(),
        Error::Eof { need: 4 }
    );
}

#[derive(XdrUnion, PartialEq, Debug)]
#[repr(i32)]
enum Nested {
    Inner(Shape) = 2,
    Payload { tag: Gapped, body: String } = 3,
}

#[test]
fn unions_compose_with_other_derived_types() {
    let value = Nested::Inner(Shape::Radius(1));
    assert_eq!(
        to_bytes(&value).unwrap(),
        [0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 1]
    );
    assert_eq!(
        from_bytes::<Nested>(&to_bytes(&value).unwrap()).unwrap(),
        value
    );

    let value = Nested::Payload {
        tag: Gapped::Ten,
        body: "ab".to_string(),
    };
    assert_eq!(
        to_bytes(&value).unwrap(),
        [0, 0, 0, 3, 0, 0, 0, 10, 0, 0, 0, 2, b'a', b'b', 0, 0]
    );
    assert_eq!(
        from_bytes::<Nested>(&to_bytes(&value).unwrap()).unwrap(),
        value
    );
}

#[test]
fn derived_types_nest_inside_ordinary_structures() {
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Holder {
        kind: Gapped,
        shapes: Vec<Shape>,
        maybe: Option<Gapped>,
    }

    let value = Holder {
        kind: Gapped::Four,
        shapes: vec![Shape::Void, Shape::Radius(2)],
        maybe: Some(Gapped::Negative),
    };
    let bytes = to_bytes(&value).unwrap();
    assert_eq!(
        bytes,
        [
            0, 0, 0, 4, // kind
            0, 0, 0, 2, // shapes: count
            0, 0, 0, 1, // Void
            0, 0, 0, 4, 0, 0, 0, 2, // Radius(2)
            0, 0, 0, 1, 0xff, 0xff, 0xff, 0xfd, // maybe
        ]
    );
    assert_eq!(from_bytes::<Holder>(&bytes).unwrap(), value);
}

#[derive(XdrUnion, PartialEq, Debug)]
#[repr(i32)]
enum Named<'a> {
    Anonymous = 0,
    Name(&'a str) = 1,
    Token { id: u32, bytes: VarOpaqueRef<'a> } = 2,
}

/// This catches a lifetime changing the bytes. A borrowed arm must encode
/// exactly as an owned arm of the same XDR type does.
#[test]
fn a_union_with_a_lifetime_encodes_its_arms_unchanged() {
    let cases: [(Named<'_>, &[u8]); 3] = [
        (Named::Anonymous, &[0, 0, 0, 0]),
        (
            Named::Name("ab"),
            &[0, 0, 0, 1, 0, 0, 0, 2, b'a', b'b', 0, 0],
        ),
        (
            Named::Token {
                id: 7,
                bytes: VarOpaqueRef(&[1, 2, 3]),
            },
            &[0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 3, 1, 2, 3, 0],
        ),
    ];
    for (value, expected) in cases {
        let bytes = to_bytes(&value).unwrap();
        assert_eq!(bytes, expected, "{value:?}");
        assert_eq!(from_bytes::<Named<'_>>(&bytes).unwrap(), value);
        assert_eq!(serialized_size(&value).unwrap(), bytes.len());
    }
}

/// Whether `part` points into `whole` and not at separate storage.
fn borrows_from(part: &[u8], whole: &[u8]) -> bool {
    let start = whole.as_ptr() as usize;
    let at = part.as_ptr() as usize;
    at >= start && at + part.len() <= start + whole.len()
}

/// This catches a derived union copying a string or opaque arm out of the
/// input when the type asked to borrow it.
#[test]
fn a_borrowed_union_arm_points_into_the_input() {
    let wire = [0, 0, 0, 1, 0, 0, 0, 2, b'a', b'b', 0, 0];
    match from_bytes::<Named<'_>>(&wire).unwrap() {
        Named::Name(name) => assert!(borrows_from(name.as_bytes(), &wire)),
        other => panic!("expected a name, got {other:?}"),
    }

    let wire = [0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 3, 1, 2, 3, 0];
    match from_bytes::<Named<'_>>(&wire).unwrap() {
        Named::Token { bytes, .. } => assert!(borrows_from(bytes.0, &wire)),
        other => panic!("expected a token, got {other:?}"),
    }
}

#[derive(XdrUnion, PartialEq, Debug)]
#[repr(i32)]
enum TwoSources<'a, 'b> {
    Left(&'a str) = 1,
    Right(VarOpaqueRef<'b>) = 2,
}

/// This catches the generated impl bounding the input by the first lifetime
/// alone, which does not compile for a union that names two.
#[test]
fn a_union_may_borrow_under_two_lifetimes() {
    let cases: [(TwoSources<'_, '_>, &[u8]); 2] = [
        (
            TwoSources::Left("a"),
            &[0, 0, 0, 1, 0, 0, 0, 1, b'a', 0, 0, 0],
        ),
        (
            TwoSources::Right(VarOpaqueRef(&[9])),
            &[0, 0, 0, 2, 0, 0, 0, 1, 9, 0, 0, 0],
        ),
    ];
    for (value, expected) in cases {
        assert_eq!(to_bytes(&value).unwrap(), expected, "{value:?}");
        assert_eq!(from_bytes::<TwoSources<'_, '_>>(expected).unwrap(), value);
    }
}
