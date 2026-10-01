// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Values several reports share: addresses, reference identifiers, and
//! leap status.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An address as chronyd reports one: IPv4, IPv6, an identifier for a
/// source whose name is not resolved yet, or none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    /// No address, as for a reference clock; also an unknown family.
    Unspecified,
    /// An IPv4 address.
    V4(Ipv4Addr),
    /// An IPv6 address.
    V6(Ipv6Addr),
    /// The identifier requests use for a source whose name is not
    /// resolved yet.
    Id(u32),
}

impl Address {
    /// The IP address, if this is one.
    pub fn ip(&self) -> Option<IpAddr> {
        match *self {
            Address::V4(ip) => Some(IpAddr::V4(ip)),
            Address::V6(ip) => Some(IpAddr::V6(ip)),
            Address::Unspecified | Address::Id(_) => None,
        }
    }
}

impl From<IpAddr> for Address {
    fn from(ip: IpAddr) -> Address {
        match ip {
            IpAddr::V4(ip) => Address::V4(ip),
            IpAddr::V6(ip) => Address::V6(ip),
        }
    }
}

impl From<Ipv4Addr> for Address {
    fn from(ip: Ipv4Addr) -> Address {
        Address::V4(ip)
    }
}

impl From<Ipv6Addr> for Address {
    fn from(ip: Ipv6Addr) -> Address {
        Address::V6(ip)
    }
}

/// The IP address; `ID#` and ten digits for an identifier; `[UNSPEC]`
/// for none.
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Unspecified => f.write_str("[UNSPEC]"),
            Address::V4(ip) => ip.fmt(f),
            Address::V6(ip) => ip.fmt(f),
            Address::Id(id) => write!(f, "ID#{id:010}"),
        }
    }
}

/// An NTP reference identifier.
///
/// For a source reached over IPv4 it is the address; over IPv6, the
/// first four bytes of the address's MD5 digest; for a reference clock
/// or a stratum-1 server, up to four ASCII characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RefId(pub u32);

impl RefId {
    /// `127.127.1.1`: chronyd's reference while the `local` directive
    /// stands in for a source.
    pub const LOCAL: RefId = RefId(0x7f7f_0101);

    /// The printable ASCII characters, in order: a reference clock's or
    /// stratum-1 server's name (`PPS`, `GPS`).
    pub fn name(&self) -> String {
        self.0
            .to_be_bytes()
            .into_iter()
            .filter(|b| (0x20..=0x7e).contains(b))
            .map(char::from)
            .collect()
    }
}

impl From<u32> for RefId {
    fn from(id: u32) -> RefId {
        RefId(id)
    }
}

/// Eight upper-case hexadecimal digits.
impl fmt::Display for RefId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08X}", self.0)
    }
}

/// An NTP leap indicator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Leap {
    /// 0: no leap second pending.
    Normal,
    /// 1: a leap second is to be inserted.
    InsertSecond,
    /// 2: a leap second is to be deleted.
    DeleteSecond,
    /// 3: not synchronized, or no valid measurement yet.
    Unsynchronized,
    /// Any other value.
    Unknown(u16),
}

impl Leap {
    pub(crate) fn from_code(code: u16) -> Leap {
        match code {
            0 => Leap::Normal,
            1 => Leap::InsertSecond,
            2 => Leap::DeleteSecond,
            3 => Leap::Unsynchronized,
            other => Leap::Unknown(other),
        }
    }
}
