// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! `getnameinfo` and `confirmed_name` against a hosts file of the suite's
//! own, read through the overlay on `/etc` of `common::overlay` with `files`
//! alone on the `hosts` line, so no DNS is asked and nothing is written to
//! the host's `/etc`. A user namespace needs a process of one thread, so the
//! suite runs without the test harness.

use std::net::IpAddr;

use truenas_nss::{Error, confirmed_name, getnameinfo};

mod common;

/// `liar.example.test` is on two lines, so `192.0.2.40` finds it by
/// address while its forward lookup finds `192.0.2.41` alone, under `multi
/// off`. `192.0.2.70` has a name that is not UTF-8.
const HOSTS: &[u8] = b"127.0.0.1 localhost
192.0.2.10 client1.example.test client1
2001:db8::10 client6.example.test
192.0.2.41 liar.example.test
192.0.2.40 liar.example.test
192.0.2.70 bad\xffname.example.test
";

/// The address `text` writes.
fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

fn main() {
    let files: [(&str, &[u8]); 3] = [
        ("hosts", HOSTS),
        ("host.conf", b"multi off\n"),
        ("nsswitch.conf", b"hosts: files\n"),
    ];
    let Some(dir) = common::overlay("hosts", &files) else {
        return;
    };
    let client1 = Some("client1.example.test".to_owned());
    let client6 = Some("client6.example.test".to_owned());
    let liar = Some("liar.example.test".to_owned());
    // The name the hosts file gives an address, in both families, and from
    // an address mapped from IPv4 into IPv6. An address with no line has
    // no name.
    let named = [
        ("192.0.2.10", client1.clone()),
        ("::ffff:192.0.2.10", client1.clone()),
        ("2001:db8::10", client6.clone()),
        ("192.0.2.40", liar.clone()),
        ("192.0.2.99", None),
    ];
    for (addr, want) in &named {
        assert_eq!(getnameinfo(ip(addr)), Ok(want.clone()), "{addr}");
    }
    // A name is kept only when its forward lookup gives the address back,
    // so the second line of `liar.example.test` names no one.
    let confirmed = [
        ("192.0.2.10", client1.clone()),
        ("::ffff:192.0.2.10", client1),
        ("2001:db8::10", client6),
        ("192.0.2.41", liar),
        ("192.0.2.40", None),
        ("192.0.2.99", None),
    ];
    for (addr, want) in &confirmed {
        assert_eq!(confirmed_name(ip(addr)), Ok(want.clone()), "{addr}");
    }
    // A name that is not UTF-8 is refused, not altered.
    let bad = ip("192.0.2.70");
    assert_eq!(getnameinfo(bad), Err(Error::NotUtf8));
    assert_eq!(confirmed_name(bad), Err(Error::NotUtf8));
    common::leave(dir);
    println!("hosts passed {} cases", named.len() + confirmed.len() + 2);
}
