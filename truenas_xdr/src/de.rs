//! The XDR [`serde::Deserializer`].
//!
//! Decoding is type-driven: the wire carries no tags, so each `deserialize_*`
//! reads exactly what its target type asks for. `deserialize_any`,
//! `deserialize_ignored_any`, and `deserialize_identifier` have no meaning
//! without self-description and are rejected.

use serde::de::{
    DeserializeSeed, EnumAccess, IntoDeserializer, SeqAccess, VariantAccess,
    Visitor,
};

use crate::{Error, Result, Strictness, pad4};

/// Reads XDR from a borrowed byte slice.
#[derive(Debug)]
pub struct Deserializer<'de> {
    input: &'de [u8],
    pos: usize,
    mode: Strictness,
    /// Set by `deserialize_newtype_struct(SENTINEL_FIXED, ..)`, so the next
    /// `deserialize_tuple(N, ..)` reads `N` raw bytes rather than a tuple.
    fixed_pending: bool,
}

impl<'de> Deserializer<'de> {
    /// A deserializer over `input` with the given strictness.
    pub fn new(input: &'de [u8], mode: Strictness) -> Self {
        Deserializer {
            input,
            pos: 0,
            mode,
            fixed_pending: false,
        }
    }

    /// The bytes not yet consumed.
    pub fn remaining(&self) -> &'de [u8] {
        &self.input[self.pos..]
    }

    fn take(&mut self, n: usize) -> Result<&'de [u8]> {
        // A saturated end still trips the bounds check, so no separate
        // overflow arm is reachable.
        let end = self.pos.saturating_add(n);
        if end > self.input.len() {
            return Err(Error::Eof {
                need: end - self.input.len(),
            });
        }
        let slice = &self.input[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Consume the padding after a `len`-byte field.
    fn read_pad(&mut self, len: usize) -> Result<()> {
        let p = pad4(len);
        if p > 0 {
            let pad = self.take(p)?;
            if self.mode == Strictness::Strict && pad.iter().any(|&b| b != 0) {
                return Err(Error::NonZeroPadding);
            }
        }
        Ok(())
    }

    /// A variable opaque or string body: `u32` length, bytes, padding.
    fn read_opaque(&mut self) -> Result<&'de [u8]> {
        let len = self.read_u32()? as usize;
        let data = self.take(len)?;
        self.read_pad(len)?;
        Ok(data)
    }

    /// A fixed opaque body: `n` bytes and padding, no length.
    fn read_fixed(&mut self, n: usize) -> Result<&'de [u8]> {
        let data = self.take(n)?;
        self.read_pad(n)?;
        Ok(data)
    }

    fn read_str(&mut self) -> Result<&'de str> {
        let bytes = self.read_opaque()?;
        let s = std::str::from_utf8(bytes).map_err(|_| Error::Utf8)?;
        if self.mode == Strictness::Strict && s.as_bytes().contains(&0) {
            return Err(Error::EmbeddedNul);
        }
        Ok(s)
    }

    fn seq(&mut self, remaining: usize) -> SeqReader<'_, 'de> {
        SeqReader {
            de: self,
            remaining,
        }
    }
}

impl<'de> serde::Deserializer<'de> for &mut Deserializer<'de> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, _v: V) -> Result<V::Value> {
        Err(Error::Unsupported("self-describing decoding"))
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(
        self,
        v: V,
    ) -> Result<V::Value> {
        self.deserialize_any(v)
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        self.deserialize_any(v)
    }

    fn deserialize_bool<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_bool(self.read_u32()? != 0)
    }
    fn deserialize_i8<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let w = self.read_u32()? as i32;
        v.visit_i8(i8::try_from(w).map_err(|_| Error::Range)?)
    }
    fn deserialize_i16<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let w = self.read_u32()? as i32;
        v.visit_i16(i16::try_from(w).map_err(|_| Error::Range)?)
    }
    fn deserialize_i32<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_i32(self.read_u32()? as i32)
    }
    fn deserialize_i64<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_i64(self.read_u64()? as i64)
    }
    fn deserialize_u8<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let w = self.read_u32()?;
        v.visit_u8(u8::try_from(w).map_err(|_| Error::Range)?)
    }
    fn deserialize_u16<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let w = self.read_u32()?;
        v.visit_u16(u16::try_from(w).map_err(|_| Error::Range)?)
    }
    fn deserialize_u32<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_u32(self.read_u32()?)
    }
    fn deserialize_u64<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_u64(self.read_u64()?)
    }
    fn deserialize_f32<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_f32(f32::from_bits(self.read_u32()?))
    }
    fn deserialize_f64<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_f64(f64::from_bits(self.read_u64()?))
    }
    fn deserialize_char<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let w = self.read_u32()?;
        v.visit_char(char::try_from(w).map_err(|_| Error::Range)?)
    }

    fn deserialize_str<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let s = self.read_str()?;
        v.visit_borrowed_str(s)
    }
    fn deserialize_string<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let s = self.read_str()?;
        v.visit_str(s)
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let bytes = self.read_opaque()?;
        v.visit_borrowed_bytes(bytes)
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let bytes = self.read_opaque()?;
        v.visit_byte_buf(bytes.to_vec())
    }

    fn deserialize_option<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        // Any non-zero discriminant means present, matching how encoders
        // written against `bool` treat it.
        if self.read_u32()? == 0 {
            v.visit_none()
        } else {
            v.visit_some(self)
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        v.visit_unit()
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        v: V,
    ) -> Result<V::Value> {
        v.visit_unit()
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        v: V,
    ) -> Result<V::Value> {
        if name == crate::SENTINEL_FIXED {
            self.fixed_pending = true;
        }
        v.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        let count = self.read_u32()? as usize;
        let reader = self.seq(count);
        v.visit_seq(reader)
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        len: usize,
        v: V,
    ) -> Result<V::Value> {
        if std::mem::take(&mut self.fixed_pending) {
            let bytes = self.read_fixed(len)?;
            return v.visit_borrowed_bytes(bytes);
        }
        let reader = self.seq(len);
        v.visit_seq(reader)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        v: V,
    ) -> Result<V::Value> {
        let reader = self.seq(len);
        v.visit_seq(reader)
    }

    fn deserialize_map<V: Visitor<'de>>(self, _v: V) -> Result<V::Value> {
        Err(Error::Unsupported("maps"))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value> {
        let reader = self.seq(fields.len());
        v.visit_seq(reader)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        v: V,
    ) -> Result<V::Value> {
        let tag = self.read_u32()?;
        v.visit_enum(EnumReader {
            de: self,
            variant_index: tag,
        })
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

/// Reads `remaining` elements on demand. For a variable sequence that is the
/// decoded count; for a tuple or struct it is the fixed arity.
struct SeqReader<'a, 'de> {
    de: &'a mut Deserializer<'de>,
    remaining: usize,
}

impl<'de> SeqAccess<'de> for SeqReader<'_, 'de> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.remaining)
    }
}

/// Decodes an enum or union whose discriminant is the declaration index, the
/// dual of the serializer's `serialize_*_variant`.
struct EnumReader<'a, 'de> {
    de: &'a mut Deserializer<'de>,
    variant_index: u32,
}

impl<'de> EnumAccess<'de> for EnumReader<'_, 'de> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self)> {
        let variant =
            seed.deserialize(self.variant_index.into_deserializer())?;
        Ok((variant, self))
    }
}

impl<'de> VariantAccess<'de> for EnumReader<'_, 'de> {
    type Error = Error;

    fn unit_variant(self) -> Result<()> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value> {
        seed.deserialize(&mut *self.de)
    }

    fn tuple_variant<V: Visitor<'de>>(
        self,
        len: usize,
        v: V,
    ) -> Result<V::Value> {
        let reader = self.de.seq(len);
        v.visit_seq(reader)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value> {
        let reader = self.de.seq(fields.len());
        v.visit_seq(reader)
    }
}
