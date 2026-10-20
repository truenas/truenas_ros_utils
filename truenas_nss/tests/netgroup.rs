// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! `innetgr` against a netgroup file of the suite's own, read through the
//! overlay on `/etc` of [`common::overlay`], so nothing is written to the
//! host's `/etc`. A user namespace needs a process of one thread, so the
//! suite runs without the test harness.

use std::thread;

use truenas_nss::{Error, innetgr};

mod common;

/// `lab` holds `client1` with any user and domain, and `client2` for
/// `alice` in `example.com` alone. `staff` holds `bob` on no host, which
/// the dash says.
const NETGROUP: &str =
    "lab (client1,,) (client2,alice,example.com)\nstaff (-,bob,)\n";

fn main() {
    // An interior NUL is refused in every position, before any lookup.
    let nul = "a\0b";
    let refused = [
        (nul, None, None, None),
        ("lab", Some(nul), None, None),
        ("lab", None, Some(nul), None),
        ("lab", None, None, Some(nul)),
    ];
    for (netgroup, host, user, domain) in refused {
        let got = innetgr(netgroup, host, user, domain);
        assert_eq!(got, Err(Error::NulByte), "{netgroup:?} {host:?}");
    }
    let files: [(&str, &[u8]); 2] = [
        ("netgroup", NETGROUP.as_bytes()),
        ("nsswitch.conf", b"netgroup: files\n"),
    ];
    let Some(dir) = common::overlay("netgroup", &files) else {
        return;
    };
    // Each position is passed through as given, and `None` as any value.
    // A swapped or dropped argument, or `None` passed as an empty string,
    // changes one of these.
    let cases = [
        ("lab", Some("client1"), None, None, true),
        ("lab", Some("client3"), None, None, false),
        (
            "lab",
            Some("client2"),
            Some("alice"),
            Some("example.com"),
            true,
        ),
        ("lab", Some("client2"), Some("carol"), None, false),
        ("lab", Some("client2"), None, Some("example.org"), false),
        ("lab", None, Some("carol"), None, true),
        ("staff", Some("client1"), None, None, false),
        ("staff", None, Some("bob"), None, true),
        ("nosuch", Some("client1"), None, None, false),
    ];
    for (netgroup, host, user, domain, want) in cases {
        let got = innetgr(netgroup, host, user, domain);
        assert_eq!(got, Ok(want), "{netgroup} {host:?} {user:?} {domain:?}");
    }
    // Threads that ask at once each get their own answer.
    let threads: Vec<_> = (0..8)
        .map(|n| {
            thread::spawn(move || {
                let (host, want) = match n % 2 {
                    0 => ("client1", true),
                    _ => ("client3", false),
                };
                for _ in 0..200 {
                    let got = innetgr("lab", Some(host), None, None);
                    assert_eq!(got, Ok(want), "{host}");
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("a thread asked without failing");
    }
    common::leave(dir);
    println!("netgroup passed {} cases", refused.len() + cases.len() + 1);
}
