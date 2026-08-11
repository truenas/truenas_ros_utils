// SPDX-License-Identifier: MIT
//! Wrapper types for the XDR shapes a stock serde call would encode wrongly.

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

use crate::SENTINEL_FIXED;

/// Variable-length opaque, RFC 4506 §4.10 (`opaque<>`): a `u32` length, the
/// bytes, then zero padding to a 4-byte boundary.
///
/// Needed because a bare `Vec<u8>` is a serde sequence, which encodes one
/// 4-byte unit per byte.
///
/// ```
/// # use truenas_xdr::{to_bytes, VarOpaque};
/// let bytes = to_bytes(&VarOpaque(vec![1, 2, 3]))?;
/// assert_eq!(bytes, [0, 0, 0, 3, 1, 2, 3, 0]); // length, data, one pad byte
/// # Ok::<(), truenas_xdr::Error>(())
/// ```
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VarOpaque(
    /// The bytes, unpadded.
    pub Vec<u8>,
);

impl From<Vec<u8>> for VarOpaque {
    fn from(bytes: Vec<u8>) -> VarOpaque {
        VarOpaque(bytes)
    }
}

impl From<VarOpaque> for Vec<u8> {
    fn from(opaque: VarOpaque) -> Vec<u8> {
        opaque.0
    }
}

impl AsRef<[u8]> for VarOpaque {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for VarOpaque {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for VarOpaque {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = VarOpaque;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("variable-length opaque bytes")
            }
            fn visit_byte_buf<E: de::Error>(
                self,
                v: Vec<u8>,
            ) -> Result<VarOpaque, E> {
                Ok(VarOpaque(v))
            }
            fn visit_bytes<E: de::Error>(
                self,
                v: &[u8],
            ) -> Result<VarOpaque, E> {
                Ok(VarOpaque(v.to_vec()))
            }
        }
        d.deserialize_byte_buf(V)
    }
}

/// Variable-length opaque borrowed from the input, the zero-copy counterpart
/// of [`VarOpaque`].
///
/// Decoding yields a slice into the caller's buffer, so a large payload costs
/// nothing to read. Use it for a field that is only inspected, and
/// [`VarOpaque`] when the bytes must outlive the input.
///
/// A bare `&[u8]` will not do: serde encodes one as a sequence, four bytes per
/// byte, while decoding one reads opaque — so a round trip through `&[u8]`
/// does not agree with itself. This type encodes and decodes as opaque both
/// ways.
///
/// ```
/// # use truenas_xdr::{from_bytes, to_bytes, VarOpaqueRef};
/// let wire = to_bytes(&VarOpaqueRef(&[1, 2, 3]))?;
/// assert_eq!(wire, [0, 0, 0, 3, 1, 2, 3, 0]);
///
/// let decoded: VarOpaqueRef<'_> = from_bytes(&wire)?;
/// assert_eq!(decoded.0, &[1, 2, 3]);
/// // The slice points into `wire` rather than at a copy.
/// assert!(std::ptr::eq(decoded.0.as_ptr(), wire[4..].as_ptr()));
/// # Ok::<(), truenas_xdr::Error>(())
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VarOpaqueRef<'a>(
    /// The borrowed bytes, unpadded.
    pub &'a [u8],
);

impl<'a> From<&'a [u8]> for VarOpaqueRef<'a> {
    fn from(bytes: &'a [u8]) -> VarOpaqueRef<'a> {
        VarOpaqueRef(bytes)
    }
}

impl<'a> From<VarOpaqueRef<'a>> for &'a [u8] {
    fn from(opaque: VarOpaqueRef<'a>) -> &'a [u8] {
        opaque.0
    }
}

impl AsRef<[u8]> for VarOpaqueRef<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl From<VarOpaqueRef<'_>> for VarOpaque {
    fn from(opaque: VarOpaqueRef<'_>) -> VarOpaque {
        VarOpaque(opaque.0.to_vec())
    }
}

impl Serialize for VarOpaqueRef<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for VarOpaqueRef<'a> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<'a>(std::marker::PhantomData<&'a ()>);
        impl<'de: 'a, 'a> Visitor<'de> for V<'a> {
            type Value = VarOpaqueRef<'a>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("borrowed variable-length opaque bytes")
            }
            fn visit_borrowed_bytes<E: de::Error>(
                self,
                v: &'de [u8],
            ) -> Result<VarOpaqueRef<'a>, E> {
                Ok(VarOpaqueRef(v))
            }
        }
        d.deserialize_bytes(V(std::marker::PhantomData))
    }
}

/// Fixed-length opaque, RFC 4506 §4.9 (`opaque[N]`): exactly `N` bytes plus
/// padding, with no length prefix.
///
/// ```
/// # use truenas_xdr::{to_bytes, FixedOpaque};
/// let bytes = to_bytes(&FixedOpaque([1, 2, 3]))?;
/// assert_eq!(bytes, [1, 2, 3, 0]); // no length, one pad byte
/// # Ok::<(), truenas_xdr::Error>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FixedOpaque<const N: usize>(
    /// The `N` bytes.
    pub [u8; N],
);

impl<const N: usize> From<[u8; N]> for FixedOpaque<N> {
    fn from(bytes: [u8; N]) -> FixedOpaque<N> {
        FixedOpaque(bytes)
    }
}

impl<const N: usize> From<FixedOpaque<N>> for [u8; N] {
    fn from(opaque: FixedOpaque<N>) -> [u8; N] {
        opaque.0
    }
}

impl<const N: usize> AsRef<[u8]> for FixedOpaque<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Default for FixedOpaque<N> {
    fn default() -> FixedOpaque<N> {
        FixedOpaque([0; N])
    }
}

impl<const N: usize> Serialize for FixedOpaque<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // The sentinel name tells the serializer that the `serialize_bytes`
        // immediately following is fixed opaque; `RawBytes` is what routes the
        // array through `serialize_bytes` rather than as a sequence.
        s.serialize_newtype_struct(SENTINEL_FIXED, &RawBytes(&self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedOpaque<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_newtype_struct(SENTINEL_FIXED, FixedVisitor::<N>)
    }
}

struct FixedVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for FixedVisitor<N> {
    type Value = FixedOpaque<N>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{N} fixed opaque bytes")
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        d: D,
    ) -> Result<Self::Value, D::Error> {
        // `deserialize_tuple` carries `N` to the codec, which — having seen the
        // sentinel — reads exactly `N` bytes plus padding.
        d.deserialize_tuple(N, self)
    }

    fn visit_borrowed_bytes<E: de::Error>(
        self,
        v: &'de [u8],
    ) -> Result<Self::Value, E> {
        let bytes: [u8; N] = v.try_into().map_err(|_| {
            E::custom(format!("expected {N} bytes, got {}", v.len()))
        })?;
        Ok(FixedOpaque(bytes))
    }
}

/// A byte slice that serializes through `serialize_bytes`.
struct RawBytes<'a>(&'a [u8]);

impl Serialize for RawBytes<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn var_opaque_converts_both_ways() {
        let opaque = VarOpaque::from(vec![1u8, 2, 3]);
        assert_eq!(opaque.as_ref(), &[1, 2, 3]);
        assert_eq!(Vec::from(opaque), vec![1, 2, 3]);
        assert_eq!(VarOpaque::default().0, Vec::<u8>::new());
    }

    #[test]
    fn fixed_opaque_converts_both_ways() {
        let opaque = FixedOpaque::from([1u8, 2, 3, 4]);
        assert_eq!(opaque.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(<[u8; 4]>::from(opaque), [1, 2, 3, 4]);
        assert_eq!(FixedOpaque::<4>::default().0, [0; 4]);
    }
}
