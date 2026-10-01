// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The wire format's fixed parts: header values, scalar encodings, and a
//! bounded reader over a reply's data.
//!
//! Every multi-byte field is big-endian.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::types::Address;

/// The protocol version spoken here.
pub(crate) const VERSION: u8 = 6;

/// The oldest version a daemon may write a version-mismatch reply in and
/// still be heard.
pub(crate) const OLDEST_MISMATCH_VERSION: u8 = 4;

/// Packet type of a request.
pub(crate) const TYPE_REQUEST: u8 = 1;
/// Packet type of a reply.
pub(crate) const TYPE_REPLY: u8 = 2;

/// Request header length: version, type, two reserved bytes, command,
/// attempt, sequence, and two zero words.
pub(crate) const REQUEST_HEADER: usize = 20;
/// Reply header length: version, type, two reserved bytes, command,
/// reply code, status, three zero halfwords, sequence, and two zero
/// words.
pub(crate) const REPLY_HEADER: usize = 28;

/// The status of a successful reply.
pub(crate) const STATUS_OK: u16 = 0;
/// The status of a reply refusing the request's protocol version.
pub(crate) const STATUS_BAD_VERSION: u16 = 18;

/// Address family codes.
const FAMILY_NONE: u16 = 0;
const FAMILY_IPV4: u16 = 1;
const FAMILY_IPV6: u16 = 2;
const FAMILY_ID: u16 = 3;

/// The high word of a timestamp from a sender whose `time_t` is 32 bits.
const NO_HIGH_WORD: u32 = 0x7fff_ffff;

/// Nanosecond counts above this are clamped to it.
const MAX_NSEC: u32 = 999_999_999;

/// A report, and the request that asks for it.
pub(crate) trait Layout: Sized {
    /// The request's command code.
    const COMMAND: u16;
    /// The reply code of the layout read.
    const REPLY: u16;
    /// Length of the reply's data, after the header.
    const LEN: usize;

    /// Read the report from a reader held to [`Self::LEN`] bytes.
    fn read(r: &mut Reader<'_>) -> Result<Self>;
}

/// Read a successful reply's data as the report `T`.
pub(crate) fn decode<T: Layout>(reply: u16, data: &[u8]) -> Result<T> {
    if reply != T::REPLY {
        return Err(Error::UnexpectedReply(reply));
    }
    T::read(&mut Reader::new(data, T::LEN)?)
}

/// Append an address: 16 bytes holding it (IPv4 and identifiers in the
/// first four, the rest zero), the family code, and two zero bytes.
pub(crate) fn put_address(buf: &mut Vec<u8>, address: Address) {
    let mut addr = [0u8; 16];
    let family = match address {
        Address::Unspecified => FAMILY_NONE,
        Address::V4(ip) => {
            addr[..4].copy_from_slice(&ip.octets());
            FAMILY_IPV4
        }
        Address::V6(ip) => {
            addr = ip.octets();
            FAMILY_IPV6
        }
        Address::Id(id) => {
            addr[..4].copy_from_slice(&id.to_be_bytes());
            FAMILY_ID
        }
    };
    buf.extend_from_slice(&addr);
    buf.extend_from_slice(&family.to_be_bytes());
    buf.extend_from_slice(&[0, 0]);
}

/// Decode the protocol's 32-bit float: a 7-bit signed exponent over a
/// 25-bit signed coefficient, `coef * 2^(exp - 25)`, exact as `f64`.
pub(crate) fn float(raw: u32) -> f64 {
    // Arithmetic shifts sign-extend each field from its top bit.
    let exp = (raw as i32) >> 25;
    let coef = ((raw << 7) as i32) >> 7;
    f64::from(coef) * pow2(exp - 25)
}

/// `2^n`, built from its bit pattern so it is exact. `n` must lie in
/// the normal range, which `exp - 25` for a 7-bit `exp` always does.
fn pow2(n: i32) -> f64 {
    f64::from_bits(((n + 1023) as u64) << 52)
}

/// A cursor over a reply's data, held to the length of its layout.
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over the first `len` bytes of `data`; excess is ignored,
    /// a shortfall is malformed.
    fn new(data: &'a [u8], len: usize) -> Result<Reader<'a>> {
        match data.get(..len) {
            Some(rest) => Ok(Reader { rest }),
            None => Err(Error::Malformed("reply shorter than its layout")),
        }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, tail) = self
            .rest
            .split_first_chunk::<N>()
            .ok_or(Error::Malformed("reply shorter than its layout"))?;
        self.rest = tail;
        Ok(*head)
    }

    /// Step over `N` bytes of padding or reserved space.
    pub(crate) fn skip<const N: usize>(&mut self) -> Result<()> {
        self.take::<N>().map(drop)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        self.take::<1>().map(|[b]| b)
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        self.take().map(u16::from_be_bytes)
    }

    pub(crate) fn i16(&mut self) -> Result<i16> {
        self.take().map(i16::from_be_bytes)
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        self.take().map(u32::from_be_bytes)
    }

    /// Seconds since an event; all ones when there has been none.
    pub(crate) fn ago(&mut self) -> Result<Option<u32>> {
        self.u32().map(|s| (s != u32::MAX).then_some(s))
    }

    pub(crate) fn float(&mut self) -> Result<f64> {
        self.u32().map(float)
    }

    /// A timestamp: the seconds' high and low words, forming the sender's
    /// 64-bit `time_t`, then nanoseconds.
    pub(crate) fn timestamp(&mut self) -> Result<SystemTime> {
        let high = self.u32()?;
        let low = self.u32()?;
        let nsec = self.u32()?.min(MAX_NSEC);
        let high = if high == NO_HIGH_WORD { 0 } else { high };
        let secs = ((u64::from(high) << 32) | u64::from(low)) as i64;
        let time = if secs >= 0 {
            UNIX_EPOCH.checked_add(Duration::new(secs.unsigned_abs(), nsec))
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::from_secs(secs.unsigned_abs()))
                .and_then(|t| t.checked_add(Duration::from_nanos(nsec.into())))
        };
        time.ok_or(Error::Malformed("timestamp out of range"))
    }

    /// An address. An unknown family code reads as
    /// [`Address::Unspecified`].
    pub(crate) fn address(&mut self) -> Result<Address> {
        let addr: [u8; 16] = self.take()?;
        let family = self.u16()?;
        self.skip::<2>()?;
        let [a, b, c, d, ..] = addr;
        Ok(match family {
            FAMILY_IPV4 => Address::V4(Ipv4Addr::new(a, b, c, d)),
            FAMILY_IPV6 => Address::V6(Ipv6Addr::from(addr)),
            FAMILY_ID => Address::Id(u32::from_be_bytes([a, b, c, d])),
            _ => Address::Unspecified,
        })
    }
}
