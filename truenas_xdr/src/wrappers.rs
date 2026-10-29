// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Wrapper types for the XDR shapes a stock serde call would encode wrongly.

use serde::de::{self, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, SerializeTupleStruct};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::fmt;
use std::marker::PhantomData;

use crate::{SENTINEL_ARRAY_REF, SENTINEL_BOUNDED, SENTINEL_FIXED};

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

/// Variable-length opaque that either borrows its bytes or owns them, for a
/// type that is decoded from a buffer in one place and built in another.
///
/// It encodes exactly as [`VarOpaque`] does. Decoding always borrows from the
/// input, as [`VarOpaqueRef`] does, and [`into_owned`](Self::into_owned)
/// copies the bytes out when the value has to outlive that input.
///
/// A bare `Cow<[u8]>` will not do, for the reason a bare `Vec<u8>` will not.
/// Serde treats it as a sequence and writes four bytes for each byte.
///
/// ```
/// # use std::borrow::Cow;
/// # use truenas_xdr::{from_bytes, to_bytes, VarOpaqueCow};
/// let built = VarOpaqueCow::from(vec![1, 2, 3]);
/// let wire = to_bytes(&built)?;
/// assert_eq!(wire, [0, 0, 0, 3, 1, 2, 3, 0]);
///
/// let decoded: VarOpaqueCow<'_> = from_bytes(&wire)?;
/// assert!(matches!(decoded.0, Cow::Borrowed(_)));
/// assert_eq!(decoded, built);
/// # Ok::<(), truenas_xdr::Error>(())
/// ```
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VarOpaqueCow<'a>(
    /// The bytes, unpadded.
    pub Cow<'a, [u8]>,
);

impl VarOpaqueCow<'_> {
    /// The same bytes in storage of their own, free of the input's lifetime.
    /// A value that already owns its bytes keeps them and copies nothing.
    pub fn into_owned(self) -> VarOpaqueCow<'static> {
        VarOpaqueCow(Cow::Owned(self.0.into_owned()))
    }
}

impl<'a> From<&'a [u8]> for VarOpaqueCow<'a> {
    fn from(bytes: &'a [u8]) -> VarOpaqueCow<'a> {
        VarOpaqueCow(Cow::Borrowed(bytes))
    }
}

impl From<Vec<u8>> for VarOpaqueCow<'_> {
    fn from(bytes: Vec<u8>) -> Self {
        VarOpaqueCow(Cow::Owned(bytes))
    }
}

impl AsRef<[u8]> for VarOpaqueCow<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for VarOpaqueCow<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for VarOpaqueCow<'a> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<'a>(PhantomData<&'a ()>);
        impl<'de: 'a, 'a> Visitor<'de> for V<'a> {
            type Value = VarOpaqueCow<'a>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("variable-length opaque bytes to borrow")
            }
            fn visit_borrowed_bytes<E: de::Error>(
                self,
                v: &'de [u8],
            ) -> Result<VarOpaqueCow<'a>, E> {
                Ok(VarOpaqueCow(Cow::Borrowed(v)))
            }
        }
        d.deserialize_bytes(V(PhantomData))
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

/// A variable-length value held to an upper bound, RFC 4506 §4.10, §4.11 and
/// §4.13 (`opaque<N>`, `string<N>`, `T<N>`).
///
/// The bound counts bytes for opaque data and strings and elements for an
/// array. Decoding checks the length the input declares before it reads
/// anything that length covers, and encoding refuses a longer value. Either
/// failure is [`Error::TooLong`](crate::Error::TooLong). The bytes of a value
/// within its bound are the same with or without the wrapper.
///
/// ```
/// # use truenas_xdr::{from_bytes, to_bytes, Bounded, Error, VarOpaqueRef};
/// // opaque handle<4>
/// type Handle<'a> = Bounded<VarOpaqueRef<'a>, 4>;
///
/// let wire = to_bytes(&Bounded::<_, 4>(VarOpaqueRef(&[1, 2, 3])))?;
/// assert_eq!(wire, [0, 0, 0, 3, 1, 2, 3, 0]);
/// let handle: Handle<'_> = from_bytes(&wire)?;
/// assert_eq!(handle.0.0, &[1, 2, 3]);
///
/// let long = [0, 0, 0, 5, 1, 2, 3, 4, 5, 0, 0, 0];
/// assert_eq!(
///     from_bytes::<Handle<'_>>(&long),
///     Err(Error::TooLong { len: 5, max: 4 }),
/// );
/// # Ok::<(), truenas_xdr::Error>(())
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Bounded<T, const MAX: usize>(
    /// The value the bound applies to.
    pub T,
);

/// A type whose encoding begins with a length, which is the length a
/// [`Bounded`] bound applies to.
///
/// It is implemented for variable opaque data, strings, `Vec` and
/// [`VarArrayRef`], and it is sealed. A bound waits for the next length the codec handles, so a type
/// that began with anything else would leave the bound waiting for a field
/// it does not belong to.
pub trait Counted: sealed::Sealed {}

mod sealed {
    pub trait Sealed {}
}

impl<T: sealed::Sealed> Counted for T {}
impl sealed::Sealed for VarOpaque {}
impl sealed::Sealed for VarOpaqueRef<'_> {}
impl sealed::Sealed for VarOpaqueCow<'_> {}
impl sealed::Sealed for String {}
impl sealed::Sealed for &str {}
impl<T> sealed::Sealed for Vec<T> {}
impl<T> sealed::Sealed for VarArrayRef<'_, T> {}

impl<T: Serialize + Counted, const MAX: usize> Serialize for Bounded<T, MAX> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // The sentinel name carries the bound to the codec, which holds the
        // next length it writes to that bound.
        let mut held = s.serialize_tuple_struct(SENTINEL_BOUNDED, MAX)?;
        held.serialize_field(&self.0)?;
        held.end()
    }
}

impl<'de, T: Deserialize<'de> + Counted, const MAX: usize> Deserialize<'de>
    for Bounded<T, MAX>
{
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_tuple_struct(
            SENTINEL_BOUNDED,
            MAX,
            BoundedVisitor(PhantomData),
        )
    }
}

struct BoundedVisitor<T, const MAX: usize>(PhantomData<T>);

impl<'de, T: Deserialize<'de> + Counted, const MAX: usize> Visitor<'de>
    for BoundedVisitor<T, MAX>
{
    type Value = Bounded<T, MAX>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a value no longer than {MAX}")
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        d: D,
    ) -> Result<Self::Value, D::Error> {
        // The codec has the bound by now and holds the length `T` reads
        // first to it.
        T::deserialize(d).map(Bounded)
    }
}

/// Variable-length array borrowed from the input, RFC 4506 §4.13
/// (`T name<>`). It keeps the count and leaves the elements as the bytes
/// they arrived in.
///
/// Decoding reads every element once, to find where the array ends, and
/// stores none of them. An array of any length therefore costs no
/// allocation of its own. [`iter`](Self::iter) decodes the elements again,
/// one at a time, when they are wanted.
///
/// It encodes as a `Vec<T>` of the same elements does, and a value that was
/// decoded encodes back to the bytes it came from. Two arrays are equal when
/// their counts and their bytes are.
///
/// ```
/// # use truenas_xdr::{from_bytes, to_bytes, VarArrayRef};
/// let wire = to_bytes(&vec![7u32, 8])?;
/// assert_eq!(wire, [0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 8]);
///
/// let array: VarArrayRef<'_, u32> = from_bytes(&wire)?;
/// assert_eq!(array.len(), 2);
/// let elements = array.iter().collect::<Result<Vec<u32>, _>>()?;
/// assert_eq!(elements, [7, 8]);
/// // The elements are the caller's bytes and not a copy of them.
/// assert!(std::ptr::eq(array.encoded().as_ptr(), wire[4..].as_ptr()));
/// assert_eq!(to_bytes(&array)?, wire);
/// # Ok::<(), truenas_xdr::Error>(())
/// ```
pub struct VarArrayRef<'a, T> {
    len: usize,
    encoded: &'a [u8],
    element: PhantomData<fn() -> T>,
}

impl<'a, T: Deserialize<'a>> VarArrayRef<'a, T> {
    /// An array of `len` elements that `encoded` holds, one after another
    /// and with no count in front.
    ///
    /// Every element is decoded once to check that `encoded` holds exactly
    /// `len` of them. Fewer is [`Error::Eof`](crate::Error::Eof) and bytes
    /// left over are [`Error::TrailingBytes`](crate::Error::TrailingBytes).
    pub fn from_encoded(len: usize, encoded: &'a [u8]) -> crate::Result<Self> {
        // An element is at least one unit, so a count past what the bytes
        // can hold is refused before the loop that would walk it.
        let units = encoded.len() / crate::BYTES_PER_XDR_UNIT;
        if len > units {
            let need = (len - units).saturating_mul(crate::BYTES_PER_XDR_UNIT);
            return Err(crate::Error::Eof { need });
        }
        let mut de =
            crate::Deserializer::new(encoded, crate::Strictness::Strict);
        for _ in 0..len {
            T::deserialize(&mut de)?;
        }
        match de.remaining().len() {
            0 => Ok(VarArrayRef {
                len,
                encoded,
                element: PhantomData,
            }),
            rest => Err(crate::Error::TrailingBytes { rest }),
        }
    }

    /// The elements in order, each decoded when it is reached.
    ///
    /// The bytes were decoded once already, so an element is not expected
    /// to fail here. An error ends the iteration.
    pub fn iter(&self) -> VarArrayIter<'a, T> {
        VarArrayIter {
            rest: self.encoded,
            left: self.len,
            element: PhantomData,
        }
    }
}

impl<'a, T> VarArrayRef<'a, T> {
    /// The number of elements.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the array has no elements.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The elements as they are encoded, with no count in front.
    pub fn encoded(&self) -> &'a [u8] {
        self.encoded
    }
}

// The impls below are written out because a derive would ask the same of
// `T`, and the array holds no `T`.

impl<T> Clone for VarArrayRef<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for VarArrayRef<'_, T> {}

impl<T> Default for VarArrayRef<'_, T> {
    fn default() -> Self {
        VarArrayRef {
            len: 0,
            encoded: &[],
            element: PhantomData,
        }
    }
}

impl<T> PartialEq for VarArrayRef<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.encoded == other.encoded
    }
}

impl<T> Eq for VarArrayRef<'_, T> {}

impl<T> std::hash::Hash for VarArrayRef<'_, T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.len.hash(state);
        self.encoded.hash(state);
    }
}

impl<T> fmt::Debug for VarArrayRef<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("VarArrayRef")
            .field("len", &self.len)
            .field("encoded", &self.encoded)
            .finish()
    }
}

impl<T> Serialize for VarArrayRef<'_, T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // The count goes out as any array's count does, so a bound reaches
        // it. The elements follow as one run of bytes that are already XDR.
        let mut array = s.serialize_seq(Some(self.len))?;
        array.serialize_element(&Encoded(self.encoded))?;
        array.end()
    }
}

impl<'de: 'a, 'a, T: Deserialize<'de>> Deserialize<'de> for VarArrayRef<'a, T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // The sentinel name has the codec mark where the array starts. The
        // two fields are then the array and the span it turned out to cover.
        d.deserialize_tuple_struct(
            SENTINEL_ARRAY_REF,
            2,
            ArrayRefVisitor(PhantomData),
        )
    }
}

struct ArrayRefVisitor<'a, T>(PhantomData<VarArrayRef<'a, T>>);

impl<'de: 'a, 'a, T: Deserialize<'de>> Visitor<'de> for ArrayRefVisitor<'a, T> {
    type Value = VarArrayRef<'a, T>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a variable-length array to borrow")
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut fields: A,
    ) -> Result<Self::Value, A::Error> {
        let Some(ElementCount(len, _)) =
            fields.next_element::<ElementCount<T>>()?
        else {
            return Err(de::Error::invalid_length(0, &self));
        };
        let Some(Span(span)) = fields.next_element::<Span<'de>>()? else {
            return Err(de::Error::invalid_length(1, &self));
        };
        // The span starts at the count, which is one unit.
        let encoded = span
            .get(crate::BYTES_PER_XDR_UNIT..)
            .ok_or_else(|| de::Error::invalid_length(span.len(), &self))?;
        Ok(VarArrayRef {
            len,
            encoded,
            element: PhantomData,
        })
    }
}

/// An array read for its count alone. Every element is decoded and dropped.
struct ElementCount<T>(usize, PhantomData<fn() -> T>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for ElementCount<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<fn() -> T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = ElementCount<T>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a variable-length array")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut elements: A,
            ) -> Result<ElementCount<T>, A::Error> {
                let mut len = 0;
                while elements.next_element::<T>()?.is_some() {
                    len += 1;
                }
                Ok(ElementCount(len, PhantomData))
            }
        }
        d.deserialize_seq(V(PhantomData))
    }
}

/// The input the codec has read since it marked the start of an array.
struct Span<'a>(&'a [u8]);

impl<'de: 'a, 'a> Deserialize<'de> for Span<'a> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<'a>(PhantomData<&'a ()>);
        impl<'de: 'a, 'a> Visitor<'de> for V<'a> {
            type Value = Span<'a>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("the span of a borrowed array")
            }
            fn visit_borrowed_bytes<E: de::Error>(
                self,
                v: &'de [u8],
            ) -> Result<Span<'a>, E> {
                Ok(Span(v))
            }
        }
        d.deserialize_newtype_struct(SENTINEL_ARRAY_REF, V(PhantomData))
    }
}

/// Bytes that are already XDR, written as they are with no length in front.
struct Encoded<'a>(&'a [u8]);

impl Serialize for Encoded<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_newtype_struct(SENTINEL_FIXED, &RawBytes(self.0))
    }
}

/// A list of optional data borrowed from the input, RFC 4506 §4.19, which
/// is how XDR links a chain (`T *next`). Each element comes behind a
/// boolean of 1, and a boolean of 0 ends the list. It keeps the count and
/// leaves the elements as the bytes they arrived in, the booleans included.
///
/// Decoding reads every element once, to find where the list ends, and
/// stores none of them. A list of any length therefore costs no allocation
/// of its own. [`iter`](Self::iter) decodes the elements again, one at a
/// time, when they are wanted.
///
/// A value that was decoded encodes back to the bytes it came from. Two
/// lists are equal when their counts and their bytes are.
///
/// ```
/// # use truenas_xdr::{from_bytes, to_bytes, ListRef};
/// let wire = [0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 0];
/// let list: ListRef<'_, u32> = from_bytes(&wire)?;
/// assert_eq!(list.len(), 2);
/// let elements = list.iter().collect::<Result<Vec<u32>, _>>()?;
/// assert_eq!(elements, [7, 8]);
/// // The elements are the caller's bytes and not a copy of them.
/// assert!(std::ptr::eq(list.encoded().as_ptr(), wire.as_ptr()));
/// assert_eq!(to_bytes(&list)?, wire);
/// # Ok::<(), truenas_xdr::Error>(())
/// ```
pub struct ListRef<'a, T> {
    len: usize,
    encoded: &'a [u8],
    element: PhantomData<fn() -> T>,
}

impl<'a, T: Deserialize<'a>> ListRef<'a, T> {
    /// The list that `encoded` holds whole, each element behind a boolean
    /// of 1 and a boolean of 0 after the last.
    ///
    /// Every element is decoded once, to count them and to check that
    /// `encoded` holds the list and nothing else. A list that runs short is
    /// [`Error::Eof`](crate::Error::Eof) and bytes left over are
    /// [`Error::TrailingBytes`](crate::Error::TrailingBytes).
    pub fn from_encoded(encoded: &'a [u8]) -> crate::Result<Self> {
        let mut de =
            crate::Deserializer::new(encoded, crate::Strictness::Strict);
        let mut len = 0;
        while Option::<T>::deserialize(&mut de)?.is_some() {
            len += 1;
        }
        match de.remaining().len() {
            0 => Ok(ListRef {
                len,
                encoded,
                element: PhantomData,
            }),
            rest => Err(crate::Error::TrailingBytes { rest }),
        }
    }

    /// The elements in order, each decoded when it is reached.
    ///
    /// The bytes were decoded once already, so an element is not expected
    /// to fail here. An error ends the iteration.
    pub fn iter(&self) -> ListIter<'a, T> {
        ListIter {
            rest: self.encoded,
            left: self.len,
            element: PhantomData,
        }
    }
}

impl<'a, T> ListRef<'a, T> {
    /// The number of elements.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the list has no elements.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The list as it is encoded, the booleans included.
    pub fn encoded(&self) -> &'a [u8] {
        self.encoded
    }
}

// The impls below are written out because a derive would ask the same of
// `T`, and the list holds no `T`.

impl<T> Clone for ListRef<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for ListRef<'_, T> {}

impl<T> Default for ListRef<'_, T> {
    /// The empty list, which is the boolean of 0 alone.
    fn default() -> Self {
        ListRef {
            len: 0,
            encoded: &[0, 0, 0, 0],
            element: PhantomData,
        }
    }
}

impl<T> PartialEq for ListRef<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.encoded == other.encoded
    }
}

impl<T> Eq for ListRef<'_, T> {}

impl<T> std::hash::Hash for ListRef<'_, T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.len.hash(state);
        self.encoded.hash(state);
    }
}

impl<T> fmt::Debug for ListRef<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ListRef")
            .field("len", &self.len)
            .field("encoded", &self.encoded)
            .finish()
    }
}

impl<T> Serialize for ListRef<'_, T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // The bytes are already XDR, the booleans among them.
        Encoded(self.encoded).serialize(s)
    }
}

impl<'de: 'a, 'a, T: Deserialize<'de>> Deserialize<'de> for ListRef<'a, T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // The sentinel name has the codec mark where the list starts. The
        // two fields are then the list and the span it turned out to cover.
        d.deserialize_tuple_struct(
            SENTINEL_ARRAY_REF,
            2,
            ListRefVisitor(PhantomData),
        )
    }
}

struct ListRefVisitor<'a, T>(PhantomData<ListRef<'a, T>>);

impl<'de: 'a, 'a, T: Deserialize<'de>> Visitor<'de> for ListRefVisitor<'a, T> {
    type Value = ListRef<'a, T>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a list of optional data to borrow")
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut fields: A,
    ) -> Result<Self::Value, A::Error> {
        let Some(ListCount(len, _)) = fields.next_element::<ListCount<T>>()?
        else {
            return Err(de::Error::invalid_length(0, &self));
        };
        let Some(Span(encoded)) = fields.next_element::<Span<'de>>()? else {
            return Err(de::Error::invalid_length(1, &self));
        };
        Ok(ListRef {
            len,
            encoded,
            element: PhantomData,
        })
    }
}

/// A list read for its count alone. Every element is decoded and dropped.
struct ListCount<T>(usize, PhantomData<fn() -> T>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for ListCount<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<fn() -> T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = ListCount<T>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a list of optional data")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut elements: A,
            ) -> Result<ListCount<T>, A::Error> {
                let mut len = 0;
                // Each element is optional data, a boolean and then the
                // element behind a 1. The list has no count in front, so
                // it is read as a tuple of no fixed length and ends at the
                // boolean of 0.
                while let Some(Some(_)) =
                    elements.next_element::<Option<T>>()?
                {
                    len += 1;
                }
                Ok(ListCount(len, PhantomData))
            }
        }
        d.deserialize_tuple(usize::MAX, V(PhantomData))
    }
}

/// The elements of a [`ListRef`], decoded one at a time.
pub struct ListIter<'a, T> {
    rest: &'a [u8],
    left: usize,
    element: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for ListIter<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ListIter")
            .field("left", &self.left)
            .field("rest", &self.rest)
            .finish()
    }
}

impl<'a, T: Deserialize<'a>> Iterator for ListIter<'a, T> {
    type Item = crate::Result<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.left = self.left.checked_sub(1)?;
        // As for an array, the list was read whole when it was decoded, so
        // neither the strictness nor the depth is held again here.
        let mut de =
            crate::Deserializer::new(self.rest, crate::Strictness::Lenient)
                .with_max_depth(usize::MAX);
        let element = match Option::<T>::deserialize(&mut de) {
            Ok(Some(element)) => Ok(element),
            Ok(None) => Err(crate::Error::Eof { need: 0 }),
            Err(error) => Err(error),
        };
        match element {
            Ok(_) => self.rest = de.remaining(),
            Err(_) => self.left = 0,
        }
        Some(element)
    }
}

/// The elements of a [`VarArrayRef`], decoded one at a time.
pub struct VarArrayIter<'a, T> {
    rest: &'a [u8],
    left: usize,
    element: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for VarArrayIter<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("VarArrayIter")
            .field("left", &self.left)
            .field("rest", &self.rest)
            .finish()
    }
}

impl<'a, T: Deserialize<'a>> Iterator for VarArrayIter<'a, T> {
    type Item = crate::Result<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.left = self.left.checked_sub(1)?;
        // The array was read whole when it was decoded, under whatever
        // strictness and depth held then. Neither is held again here, so
        // that what decoded once decodes now.
        let mut de =
            crate::Deserializer::new(self.rest, crate::Strictness::Lenient)
                .with_max_depth(usize::MAX);
        let element = T::deserialize(&mut de);
        match element {
            Ok(_) => self.rest = de.remaining(),
            Err(_) => self.left = 0,
        }
        Some(element)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl<'a, T: Deserialize<'a>> ExactSizeIterator for VarArrayIter<'a, T> {}

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
    fn var_opaque_ref_converts_both_ways() {
        let data = [1u8, 2, 3];
        let opaque = VarOpaqueRef::from(&data[..]);
        assert_eq!(opaque.as_ref(), &[1, 2, 3]);
        assert_eq!(<&[u8]>::from(opaque), &[1, 2, 3]);
        // The borrowed form promotes to the owned one by copying its bytes.
        assert_eq!(VarOpaque::from(opaque).0, vec![1, 2, 3]);
        assert_eq!(VarOpaqueRef::default().0, &[] as &[u8]);
    }

    #[test]
    fn var_opaque_cow_is_built_borrowed_or_owned() {
        let data = [1u8, 2, 3];
        let borrowed = VarOpaqueCow::from(&data[..]);
        assert!(matches!(borrowed.0, Cow::Borrowed(_)));
        let owned = VarOpaqueCow::from(vec![1u8, 2, 3]);
        assert!(matches!(owned.0, Cow::Owned(_)));
        // The two states hold the same bytes, so they compare equal.
        assert_eq!(borrowed, owned);
        assert_eq!(borrowed.as_ref(), &[1, 2, 3]);
        assert_eq!(VarOpaqueCow::default().as_ref(), &[] as &[u8]);
    }

    #[test]
    fn fixed_opaque_converts_both_ways() {
        let opaque = FixedOpaque::from([1u8, 2, 3, 4]);
        assert_eq!(opaque.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(<[u8; 4]>::from(opaque), [1, 2, 3, 4]);
        assert_eq!(FixedOpaque::<4>::default().0, [0; 4]);
    }
}
