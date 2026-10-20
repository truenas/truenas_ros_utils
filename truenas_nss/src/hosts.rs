// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The name of an address through glibc's `getnameinfo(3)`, and that name
//! checked back by a forward lookup through `getaddrinfo(3)`.
//!
//! Both go through glibc's frontend and the `hosts` line of
//! `nsswitch.conf`, and may wait on DNS. glibc documents both as safe across
//! threads, so no lock is held. A missing name is `None`, and any other
//! failure is [`Error::Lookup`] with its `EAI_*` code, so a lookup that could
//! not be made at this time stays apart from an address that has no name.
//!
//! # Safety
//!
//! `getnameinfo` reads a socket address of the length it is given, and
//! writes at most the length of its buffer, the NUL included. `getaddrinfo`
//! reads its node and hints and gives back a list that `freeaddrinfo`
//! releases once, after the last read of it.
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use std::ffi::{CStr, CString, c_char, c_int};
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

/// The name of `addr`, or `None` when it has none.
///
/// An address mapped from IPv4 into IPv6 is looked up as IPv4. The name is
/// not checked against the address, so the owner of the address's reverse
/// DNS chooses it. [`confirmed_name`] checks it.
///
/// # Errors
///
/// [`Error::Lookup`] for any failure but a missing name, which
/// [`Error::is_temporary`] says may pass, and [`Error::NotUtf8`] for a name
/// that is not UTF-8.
pub fn getnameinfo(addr: IpAddr) -> Result<Option<String>> {
    let mut host = [0 as c_char; libc::NI_MAXHOST as usize];
    let len = host.len() as libc::socklen_t;
    let (rc, errno) = with_sockaddr(addr.to_canonical(), |sa, salen| {
        // SAFETY: sa points to a socket address of salen bytes, and host
        // has len bytes, both alive for the call.
        let rc = unsafe {
            libc::getnameinfo(
                sa,
                salen,
                host.as_mut_ptr(),
                len,
                ptr::null_mut(),
                0,
                libc::NI_NAMEREQD,
            )
        };
        (rc, last_errno())
    });
    if !found("getnameinfo", rc, errno)? {
        return Ok(None);
    }
    // SAFETY: getnameinfo succeeded, so host holds a NUL-terminated name
    // within its length.
    let name = unsafe { CStr::from_ptr(host.as_ptr()) };
    let name = name.to_str().map_err(|_| Error::NotUtf8)?;
    Ok(Some(name.to_owned()))
}

/// The name of `addr`, kept only when a forward lookup of that name gives
/// `addr` back, so that the owner of the address's reverse DNS cannot claim
/// a name alone.
///
/// Addresses mapped from IPv4 into IPv6 compare as IPv4. A name whose
/// forward lookup finds no address, or none that is `addr`, is `None`.
///
/// # Errors
///
/// As [`getnameinfo`], for either lookup.
pub fn confirmed_name(addr: IpAddr) -> Result<Option<String>> {
    let Some(name) = getnameinfo(addr)? else {
        return Ok(None);
    };
    let wanted = addr.to_canonical();
    let back = addresses(&name)?.iter().any(|a| a.to_canonical() == wanted);
    Ok(back.then_some(name))
}

/// Whether a lookup that returned `rc` found an answer. A missing name or
/// address is `false`, and any other failure is the error of `op`.
fn found(op: &'static str, rc: c_int, errno: i32) -> Result<bool> {
    match rc {
        0 => Ok(true),
        libc::EAI_NONAME | libc::EAI_NODATA => Ok(false),
        code => {
            let errno = if code == libc::EAI_SYSTEM { errno } else { 0 };
            Err(Error::Lookup { op, code, errno })
        }
    }
}

/// The errno left by the call just made.
fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Run `call` with `addr` as a socket address and its length.
fn with_sockaddr<T>(
    addr: IpAddr,
    call: impl FnOnce(*const libc::sockaddr, libc::socklen_t) -> T,
) -> T {
    match addr {
        IpAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.octets()),
                },
                sin_zero: [0; 8],
            };
            let len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            call((&raw const sin).cast(), len)
        }
        IpAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.octets(),
                },
                sin6_scope_id: 0,
            };
            let len = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            call((&raw const sin6).cast(), len)
        }
    }
}

/// The list `getaddrinfo` gave, released when dropped.
struct List(*mut libc::addrinfo);

impl Drop for List {
    fn drop(&mut self) {
        // SAFETY: the list came from a getaddrinfo that succeeded and is
        // released only here, after its last read.
        unsafe { libc::freeaddrinfo(self.0) };
    }
}

/// The addresses `getaddrinfo` gives for `name`, none when it has none.
fn addresses(name: &str) -> Result<Vec<IpAddr>> {
    let node = CString::new(name).map_err(|_| Error::NulByte)?;
    let hints = libc::addrinfo {
        ai_flags: 0,
        ai_family: libc::AF_UNSPEC,
        ai_socktype: libc::SOCK_STREAM,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: ptr::null_mut(),
        ai_canonname: ptr::null_mut(),
        ai_next: ptr::null_mut(),
    };
    let mut list = ptr::null_mut();
    // SAFETY: node and hints outlive the call, and list is written only when
    // it succeeds.
    let rc = unsafe {
        libc::getaddrinfo(node.as_ptr(), ptr::null(), &hints, &mut list)
    };
    let errno = last_errno();
    if !found("getaddrinfo", rc, errno)? {
        return Ok(Vec::new());
    }
    let list = List(list);
    let mut addresses = Vec::new();
    let mut at = list.0;
    while !at.is_null() {
        // SAFETY: at is an entry of the list, which lives until list drops.
        let entry = unsafe { &*at };
        addresses.extend(address_of(entry));
        at = entry.ai_next;
    }
    Ok(addresses)
}

/// The address of `entry`, when its family is one of the two IP families
/// and its length holds that family's socket address.
fn address_of(entry: &libc::addrinfo) -> Option<IpAddr> {
    let len = entry.ai_addrlen as usize;
    match entry.ai_family {
        libc::AF_INET if len >= size_of::<libc::sockaddr_in>() => {
            // SAFETY: the family and the length say ai_addr points to a
            // sockaddr_in.
            let sin = unsafe { &*entry.ai_addr.cast::<libc::sockaddr_in>() };
            let octets = sin.sin_addr.s_addr.to_ne_bytes();
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        libc::AF_INET6 if len >= size_of::<libc::sockaddr_in6>() => {
            // SAFETY: the family and the length say ai_addr points to a
            // sockaddr_in6.
            let sin6 = unsafe { &*entry.ai_addr.cast::<libc::sockaddr_in6>() };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A missing name or address is `false` for either call, and so is the
    /// glibc code for a name with no address.
    #[test]
    fn a_missing_name_is_no_answer() {
        assert_eq!(found("getnameinfo", 0, 0), Ok(true));
        assert_eq!(found("getnameinfo", libc::EAI_NONAME, 0), Ok(false));
        assert_eq!(found("getaddrinfo", libc::EAI_NODATA, 0), Ok(false));
    }

    /// Any other code is the error of the call that returned it, with the
    /// errno kept for `EAI_SYSTEM` alone, so a stale errno never rides on
    /// another code.
    #[test]
    fn a_failure_keeps_its_code_and_the_errno_of_eai_system() {
        let again = found("getnameinfo", libc::EAI_AGAIN, libc::EINTR);
        let again = again.expect_err("EAI_AGAIN is a failure");
        assert_eq!(
            again,
            Error::Lookup {
                op: "getnameinfo",
                code: libc::EAI_AGAIN,
                errno: 0,
            }
        );
        assert!(again.is_temporary());
        let system = found("getaddrinfo", libc::EAI_SYSTEM, libc::EMFILE);
        assert_eq!(
            system,
            Err(Error::Lookup {
                op: "getaddrinfo",
                code: libc::EAI_SYSTEM,
                errno: libc::EMFILE,
            })
        );
        let fail = found("getnameinfo", libc::EAI_FAIL, 0).unwrap_err();
        assert!(!fail.is_temporary());
    }

    /// An address goes to C in network order, and comes back from C the
    /// same, in both families.
    #[test]
    fn an_address_crosses_in_network_order() {
        for addr in ["192.0.2.10", "2001:db8::10"] {
            let addr: IpAddr = addr.parse().unwrap();
            let back = with_sockaddr(addr, |sa, len| {
                let entry = libc::addrinfo {
                    ai_flags: 0,
                    // SAFETY: sa points to a socket address of len bytes,
                    // whose family is its first field.
                    ai_family: c_int::from(unsafe { (*sa).sa_family }),
                    ai_socktype: 0,
                    ai_protocol: 0,
                    ai_addrlen: len,
                    ai_addr: sa.cast_mut(),
                    ai_canonname: ptr::null_mut(),
                    ai_next: ptr::null_mut(),
                };
                address_of(&entry)
            });
            assert_eq!(back, Some(addr));
        }
    }
}
