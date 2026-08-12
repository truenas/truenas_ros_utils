// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The XDR [`serde::Serializer`].
//!
//! Encoding does not depend on [`Strictness`](crate::Strictness): canonical
//! padding is always zero, so there is one encoder.

use serde::ser::{
    Impossible, SerializeSeq, SerializeStruct, SerializeStructVariant,
    SerializeTuple, SerializeTupleStruct, SerializeTupleVariant,
};
use std::io::Write;

use crate::{Error, Result, SENTINEL_FIXED, pad4};

/// Writes XDR to an [`io::Write`](std::io::Write) sink.
pub(crate) struct Serializer<W> {
    w: W,
    /// Set by `serialize_newtype_struct(SENTINEL_FIXED, ..)`, so the next
    /// `serialize_bytes` emits fixed opaque: bytes and padding, no length.
    fixed_pending: bool,
}

impl<W: Write> Serializer<W> {
    pub(crate) fn new(w: W) -> Self {
        Serializer {
            w,
            fixed_pending: false,
        }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.w
            .write_all(bytes)
            .map_err(|e| Error::Io(e.to_string()))
    }

    fn put_u32(&mut self, v: u32) -> Result<()> {
        self.put(&v.to_be_bytes())
    }

    fn put_u64(&mut self, v: u64) -> Result<()> {
        self.put(&v.to_be_bytes())
    }

    /// A variable-length count as its `u32` prefix. The wire bounds every
    /// count at `u32::MAX`; a longer value has no encoding, so it is
    /// refused rather than truncated.
    fn put_len(&mut self, len: usize) -> Result<()> {
        let len = u32::try_from(len)
            .map_err(|_| Error::Unsupported("a length beyond u32::MAX"))?;
        self.put_u32(len)
    }

    /// Zero padding bringing `len` up to a 4-byte boundary.
    fn put_pad(&mut self, len: usize) -> Result<()> {
        let p = pad4(len);
        if p > 0 {
            self.put(&[0u8; 3][..p])?;
        }
        Ok(())
    }

    /// An opaque or string body: the bytes and their padding. Any length
    /// prefix is written by the caller.
    fn put_body(&mut self, v: &[u8]) -> Result<()> {
        self.put(v)?;
        self.put_pad(v.len())
    }
}

/// An [`io::Write`](std::io::Write) that counts bytes instead of storing them.
pub(crate) struct CountWriter {
    pub(crate) n: usize,
}

impl Write for CountWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.n += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<W: Write> serde::Serializer for &mut Serializer<W> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Impossible<(), Error>;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<()> {
        self.put_u32(u32::from(v))
    }
    fn serialize_i8(self, v: i8) -> Result<()> {
        self.serialize_i32(i32::from(v))
    }
    fn serialize_i16(self, v: i16) -> Result<()> {
        self.serialize_i32(i32::from(v))
    }
    fn serialize_i32(self, v: i32) -> Result<()> {
        self.put_u32(v as u32)
    }
    fn serialize_i64(self, v: i64) -> Result<()> {
        self.put_u64(v as u64)
    }
    fn serialize_u8(self, v: u8) -> Result<()> {
        self.put_u32(u32::from(v))
    }
    fn serialize_u16(self, v: u16) -> Result<()> {
        self.put_u32(u32::from(v))
    }
    fn serialize_u32(self, v: u32) -> Result<()> {
        self.put_u32(v)
    }
    fn serialize_u64(self, v: u64) -> Result<()> {
        self.put_u64(v)
    }
    fn serialize_f32(self, v: f32) -> Result<()> {
        self.put_u32(v.to_bits())
    }
    fn serialize_f64(self, v: f64) -> Result<()> {
        self.put_u64(v.to_bits())
    }
    fn serialize_char(self, v: char) -> Result<()> {
        self.put_u32(v as u32)
    }

    fn serialize_str(self, v: &str) -> Result<()> {
        // A string is variable-length whatever the sentinel said.
        self.fixed_pending = false;
        self.put_len(v.len())?;
        self.put_body(v.as_bytes())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<()> {
        if std::mem::take(&mut self.fixed_pending) {
            self.put_body(v)
        } else {
            self.put_len(v.len())?;
            self.put_body(v)
        }
    }

    fn serialize_none(self) -> Result<()> {
        self.put_u32(0)
    }
    fn serialize_some<T: ?Sized + serde::Serialize>(
        self,
        value: &T,
    ) -> Result<()> {
        self.put_u32(1)?;
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<()> {
        Ok(())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<()> {
        Ok(())
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
    ) -> Result<()> {
        self.put_u32(variant_index)
    }

    fn serialize_newtype_struct<T: ?Sized + serde::Serialize>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<()> {
        if name == SENTINEL_FIXED {
            self.fixed_pending = true;
        }
        // Otherwise transparent: a newtype adds no bytes.
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + serde::Serialize>(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<()> {
        self.put_u32(variant_index)?;
        value.serialize(self)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq> {
        let len =
            len.ok_or(Error::Unsupported("a sequence of unknown length"))?;
        self.put_len(len)?;
        Ok(self)
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        Ok(self)
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        Ok(self)
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        self.put_u32(variant_index)?;
        Ok(self)
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        Err(Error::Unsupported("maps"))
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct> {
        Ok(self)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        self.put_u32(variant_index)?;
        Ok(self)
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

// Compound values write each element as it arrives: XDR has no inter-field
// framing, and a variable sequence already wrote its count in `serialize_seq`.

macro_rules! forward_elements {
    ($trait:ident, $method:ident $(, $key:ty)?) => {
        impl<W: Write> $trait for &mut Serializer<W> {
            type Ok = ();
            type Error = Error;
            fn $method<T: ?Sized + serde::Serialize>(
                &mut self,
                $(_key: $key,)?
                value: &T,
            ) -> Result<()> {
                value.serialize(&mut **self)
            }
            fn end(self) -> Result<()> {
                Ok(())
            }
        }
    };
}

forward_elements!(SerializeSeq, serialize_element);
forward_elements!(SerializeTuple, serialize_element);
forward_elements!(SerializeTupleStruct, serialize_field);
forward_elements!(SerializeTupleVariant, serialize_field);
forward_elements!(SerializeStruct, serialize_field, &'static str);
forward_elements!(SerializeStructVariant, serialize_field, &'static str);

#[cfg(test)]
mod tests {
    use super::*;

    /// A length that does not fit the 32-bit prefix must be refused at
    /// the prefix: `as u32` would write `len mod 2^32` and then every
    /// byte, corrupting the stream for its decoder.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn an_oversize_length_is_refused_not_truncated() {
        struct Overlong;
        impl serde::Serialize for Overlong {
            fn serialize<S: serde::Serializer>(
                &self,
                s: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                use serde::ser::SerializeSeq;
                s.serialize_seq(Some(u32::MAX as usize + 1))?.end()
            }
        }
        let err = crate::to_bytes(&Overlong).unwrap_err();
        assert_eq!(err, Error::Unsupported("a length beyond u32::MAX"));

        // The boundary itself encodes.
        let mut ser = Serializer::new(CountWriter { n: 0 });
        assert!(ser.put_len(u32::MAX as usize).is_ok());
        assert!(ser.put_len(u32::MAX as usize + 1).is_err());
    }

    #[test]
    fn the_count_writer_counts_and_flushes() {
        let mut w = CountWriter { n: 0 };
        w.write_all(b"abcd").unwrap();
        w.write_all(b"ef").unwrap();
        w.flush().unwrap();
        assert_eq!(w.n, 6);
    }

    #[test]
    fn a_failing_writer_surfaces_as_io() {
        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::StorageFull,
                    "no space",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let err = crate::to_writer(Full, &1u32).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err:?}");
        assert!(err.to_string().contains("no space"));
    }
}
