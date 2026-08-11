// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! A byte-exact serde codec for XDR (RFC 4506).
//!
//! XDR carries no type tags, so this is a type-driven codec: encoding walks a
//! `Serialize` value to canonical big-endian bytes, and decoding is driven
//! entirely by the target type's `Deserialize` impl. `deserialize_any` is
//! therefore unsupported, which rules out `#[serde(flatten)]` and any
//! self-describing value type.
//!
//! ```
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct Point { x: i32, y: i32 }
//!
//! let bytes = truenas_xdr::to_bytes(&Point { x: 1, y: -1 })?;
//! assert_eq!(bytes, [0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff]);
//! assert_eq!(truenas_xdr::from_bytes::<Point>(&bytes)?, Point { x: 1, y: -1 });
//! # Ok::<(), truenas_xdr::Error>(())
//! ```
//!
//! # Type mapping
//!
//! The common RFC 4506 set is covered: bool, 32-bit int and unsigned, 64-bit
//! hyper, float and double, enum, fixed and variable opaque, string, fixed and
//! variable array, optional data, discriminated union, and struct. Everything
//! is padded to a 4-byte boundary.
//!
//! Three shapes need more than a stock serde call:
//!
//! - Variable opaque (`opaque<>`) is [`VarOpaque`], or [`VarOpaqueRef`] to
//!   borrow. A bare `Vec<u8>` or `&[u8]` is a serde sequence, so it would
//!   encode one 4-byte unit per byte.
//! - Fixed opaque (`opaque[N]`) is [`FixedOpaque`], which has no length prefix.
//! - Enums and unions whose discriminants are not their declaration order need
//!   [`XdrEnum`] or [`XdrUnion`]; a stock `#[derive(Serialize)]` enum encodes
//!   the declaration index.
//!
//! A single-field newtype is wire-transparent, so wrappers cost no bytes.
//!
//! Maps have no XDR representation and are rejected as
//! [`Error::Unsupported`], as are sequences whose length is not known up front.
//!
//! # Borrowing from the input
//!
//! Strings and opaque data are the only variable-length payloads, and both can
//! decode as borrows of the input buffer rather than copies: `&str` for a
//! string, [`VarOpaqueRef`] for opaque. In a struct they need serde's
//! `#[serde(borrow)]`.
//!
//! ```
//! # use serde::{Deserialize, Serialize};
//! # use truenas_xdr::{from_bytes, to_bytes, VarOpaqueRef};
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct Record<'a> {
//!     id: u32,
//!     #[serde(borrow)]
//!     name: &'a str,
//!     #[serde(borrow)]
//!     body: VarOpaqueRef<'a>,
//! }
//!
//! let wire = to_bytes(&Record {
//!     id: 1,
//!     name: "example",
//!     body: VarOpaqueRef(b"payload"),
//! })?;
//! let decoded: Record<'_> = from_bytes(&wire)?; // no allocation
//! assert_eq!(decoded.name, "example");
//! # Ok::<(), truenas_xdr::Error>(())
//! ```
//!
//! # Decoding
//!
//! [`from_bytes`] requires the input to be consumed exactly; [`from_prefix`]
//! decodes a value and returns the unread tail, for framing a value inside a
//! larger message. Both have `_with` forms taking an explicit [`Strictness`]:
//! implementations disagree on whether a non-zero pad byte or an embedded NUL
//! in a string is an error, so it is a decode-time choice. Encoding is
//! identical either way — canonical padding is always zero.
#![forbid(unsafe_code)]

mod de;
mod error;
mod ser;
mod strict;
mod wrappers;

pub use de::Deserializer;
pub use error::{Error, Result};
pub use strict::Strictness;
pub use wrappers::{FixedOpaque, VarOpaque, VarOpaqueRef};

#[cfg(feature = "derive")]
pub use truenas_xdr_derive::{XdrEnum, XdrUnion};

use serde::{Deserialize, Serialize};

/// Bytes in one XDR unit (RFC 4506 §3). Every encoded item is a whole number
/// of these.
pub const BYTES_PER_XDR_UNIT: usize = 4;

/// Newtype name by which [`FixedOpaque`] tells the codec "raw bytes, no length
/// prefix". Not a stable part of the API.
pub(crate) const SENTINEL_FIXED: &str = "\u{0}truenas-xdr-fixed-opaque";

/// Zero padding needed to bring `len` up to a 4-byte boundary, `0..=3`.
pub(crate) const fn pad4(len: usize) -> usize {
    (BYTES_PER_XDR_UNIT - (len % BYTES_PER_XDR_UNIT)) % BYTES_PER_XDR_UNIT
}

/// Encode `value` to canonical XDR bytes.
pub fn to_bytes<T: ?Sized + Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    to_writer(&mut buf, value)?;
    Ok(buf)
}

/// Encode `value` into `writer`.
///
/// Bytes are written as they are produced, so a caller can append to a
/// reusable buffer and pay no per-message allocation.
pub fn to_writer<W: std::io::Write, T: ?Sized + Serialize>(
    mut writer: W,
    value: &T,
) -> Result<()> {
    let mut ser = ser::Serializer::new(&mut writer);
    value.serialize(&mut ser)
}

/// The number of bytes `value` encodes to, without building the output.
///
/// Always a multiple of [`BYTES_PER_XDR_UNIT`].
pub fn serialized_size<T: ?Sized + Serialize>(value: &T) -> Result<usize> {
    let mut counter = ser::CountWriter { n: 0 };
    to_writer(&mut counter, value)?;
    Ok(counter.n)
}

/// Decode a `T` from `bytes`, which must be consumed exactly.
///
/// Leftover input is [`Error::TrailingBytes`]. Use [`from_prefix`] to decode a
/// value from the front of a larger buffer.
pub fn from_bytes<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T> {
    from_bytes_with(bytes, Strictness::default())
}

/// Decode a `T` from `bytes` under an explicit [`Strictness`], consuming the
/// input exactly.
pub fn from_bytes_with<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
    mode: Strictness,
) -> Result<T> {
    let (value, rest) = from_prefix_with(bytes, mode)?;
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(Error::TrailingBytes { rest: rest.len() })
    }
}

/// Decode a `T` from the front of `bytes`, returning it with the unread tail.
pub fn from_prefix<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
) -> Result<(T, &'de [u8])> {
    from_prefix_with(bytes, Strictness::default())
}

/// Decode a `T` from the front of `bytes` under an explicit [`Strictness`],
/// returning it with the unread tail.
pub fn from_prefix_with<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
    mode: Strictness,
) -> Result<(T, &'de [u8])> {
    let mut de = Deserializer::new(bytes, mode);
    let value = T::deserialize(&mut de)?;
    Ok((value, de.remaining()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad4_rounds_up_to_a_unit() {
        assert_eq!(
            [0, 1, 2, 3, 4, 5, 6, 7, 8].map(pad4),
            [0, 3, 2, 1, 0, 3, 2, 1, 0]
        );
        // The padded length is always a whole number of units.
        for len in 0..64usize {
            assert_eq!((len + pad4(len)) % BYTES_PER_XDR_UNIT, 0);
            assert!(pad4(len) < BYTES_PER_XDR_UNIT);
        }
    }
}
