// SPDX-License-Identifier: MIT
//! Decoding that borrows from the input buffer instead of copying it.
//!
//! Strings and opaque fields are the only variable-length payloads XDR has, so
//! they are the only places a decode can allocate. Each test here proves the
//! borrow by address: the decoded slice must point *into* the caller's buffer,
//! not at a copy of it.

use serde::{Deserialize, Serialize};
use truenas_xdr::{
    Strictness, VarOpaque, VarOpaqueRef, from_bytes, from_bytes_with,
    from_prefix, to_bytes,
};

/// Whether `part` points into `whole` rather than at separate storage.
#[track_caller]
fn borrows_from(part: &[u8], whole: &[u8]) -> bool {
    let (start, end) = (
        whole.as_ptr() as usize,
        whole.as_ptr() as usize + whole.len(),
    );
    let at = part.as_ptr() as usize;
    at >= start && at + part.len() <= end
}

#[test]
fn a_string_decodes_as_a_borrow_of_the_input() {
    let wire = to_bytes(&"hello world".to_string()).unwrap();
    let decoded: &str = from_bytes(&wire).unwrap();
    assert_eq!(decoded, "hello world");
    assert!(
        borrows_from(decoded.as_bytes(), &wire),
        "copied, not borrowed"
    );
}

#[test]
fn opaque_bytes_decode_as_a_borrow_of_the_input() {
    let payload: Vec<u8> = (0..=255u8).collect();
    let wire = to_bytes(&VarOpaque(payload.clone())).unwrap();
    let decoded: &[u8] = from_bytes(&wire).unwrap();
    assert_eq!(decoded, &payload[..]);
    assert!(borrows_from(decoded, &wire), "copied, not borrowed");
}

#[test]
fn an_empty_payload_borrows_without_panicking() {
    let wire = to_bytes(&String::new()).unwrap();
    assert_eq!(from_bytes::<&str>(&wire).unwrap(), "");
    let wire = to_bytes(&VarOpaque(vec![])).unwrap();
    assert_eq!(from_bytes::<&[u8]>(&wire).unwrap(), b"");
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Borrowed<'a> {
    id: u32,
    #[serde(borrow)]
    name: &'a str,
    #[serde(borrow)]
    blob: VarOpaqueRef<'a>,
    trailing: i64,
}

#[test]
fn a_struct_of_borrowed_fields_points_into_the_input() {
    let owned = Borrowed {
        id: 7,
        name: "sillyprog",
        blob: VarOpaqueRef(b"(quit)"),
        trailing: -1,
    };
    let wire = to_bytes(&owned).unwrap();

    let decoded: Borrowed<'_> = from_bytes(&wire).unwrap();
    assert_eq!(decoded, owned);
    assert!(borrows_from(decoded.name.as_bytes(), &wire));
    assert!(borrows_from(decoded.blob.0, &wire));

    // Fields keep their order and padding, so borrowing changes no bytes.
    assert_eq!(to_bytes(&decoded).unwrap(), wire);
    // 4 (id) + 4+9+3 (name) + 4+6+2 (blob) + 8 (trailing)
    assert_eq!(wire.len(), 40);
}

#[test]
fn borrowed_opaque_agrees_with_its_owned_form() {
    // The two spellings are one wire format, so either side can change without
    // the other noticing.
    let payload: Vec<u8> = (0..=255u8).collect();
    let borrowed = to_bytes(&VarOpaqueRef(&payload)).unwrap();
    let owned = to_bytes(&VarOpaque(payload.clone())).unwrap();
    assert_eq!(borrowed, owned);

    let as_ref: VarOpaqueRef<'_> = from_bytes(&owned).unwrap();
    let as_buf: VarOpaque = from_bytes(&borrowed).unwrap();
    assert_eq!(as_ref.0, &payload[..]);
    assert_eq!(as_buf.0, payload);
    assert_eq!(VarOpaque::from(as_ref), as_buf);
    assert!(borrows_from(as_ref.0, &owned));
}

#[test]
fn a_bare_byte_slice_is_a_sequence_not_opaque() {
    // serde encodes `&[u8]` as a sequence, one 4-byte unit per byte, which is
    // why the opaque wrappers exist. Pinned so the difference stays visible.
    let as_seq = to_bytes(&&b"ab"[..]).unwrap();
    assert_eq!(as_seq, [0, 0, 0, 2, 0, 0, 0, b'a', 0, 0, 0, b'b']);
    assert_eq!(
        to_bytes(&VarOpaqueRef(b"ab")).unwrap(),
        [0, 0, 0, 2, b'a', b'b', 0, 0]
    );
}

#[test]
fn borrowed_sequences_point_into_the_input() {
    let owned: Vec<&str> = vec!["a", "bcde", ""];
    let wire = to_bytes(&owned).unwrap();
    let decoded: Vec<&str> = from_bytes(&wire).unwrap();
    assert_eq!(decoded, owned);
    for part in &decoded {
        assert!(borrows_from(part.as_bytes(), &wire), "{part:?} was copied");
    }
}

#[test]
fn borrowing_survives_both_decode_entry_points_and_both_modes() {
    let mut wire = to_bytes(&"payload".to_string()).unwrap();
    let value_len = wire.len();
    wire.extend_from_slice(b"tail");

    let (decoded, rest) = from_prefix::<&str>(&wire).unwrap();
    assert_eq!(decoded, "payload");
    assert_eq!(rest, b"tail");
    assert!(borrows_from(decoded.as_bytes(), &wire));
    assert!(borrows_from(rest, &wire), "the tail is a borrow too");

    let exact = &wire[..value_len];
    for mode in [Strictness::Lenient, Strictness::Strict] {
        let decoded = from_bytes_with::<&str>(exact, mode).unwrap();
        assert_eq!(decoded, "payload");
        assert!(borrows_from(decoded.as_bytes(), &wire));
    }
}

#[test]
fn a_borrow_outlives_the_decoder_but_not_the_buffer() {
    // The lifetime is tied to the input, so a decoded borrow stays usable for
    // as long as the buffer does, with no decoder kept alive alongside it.
    let wire =
        to_bytes(&("abc".to_string(), VarOpaque(vec![1, 2, 3]))).unwrap();
    let (text, blob): (&str, &[u8]) = from_bytes(&wire).unwrap();
    assert_eq!(text, "abc");
    assert_eq!(blob, &[1, 2, 3]);
    assert!(borrows_from(text.as_bytes(), &wire));
    assert!(borrows_from(blob, &wire));
}

#[test]
fn invalid_utf8_still_borrows_as_opaque() {
    // A payload that is not a valid string is still readable as bytes, which
    // is what keeps a non-UTF-8 field usable without copying.
    let payload = vec![0xff, 0xfe, 0x00, 0x80];
    let wire = to_bytes(&VarOpaque(payload.clone())).unwrap();
    assert!(from_bytes::<&str>(&wire).is_err());
    let decoded: &[u8] = from_bytes(&wire).unwrap();
    assert_eq!(decoded, &payload[..]);
    assert!(borrows_from(decoded, &wire));
}
