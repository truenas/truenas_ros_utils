// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! `innetgr` against a netgroup file of the suite's own.
//!
//! The process enters a mount namespace of its own, after a user namespace
//! when it is not root, and lays an overlay on `/etc` whose upper layer
//! already holds `netgroup` and `nsswitch.conf`, before its first NSS call.
//! So it reads only those, and nothing is written through `/etc`. A user namespace needs a process
//! of one thread, so the suite runs without the test harness. Where a
//! namespace cannot be made it skips, and `TRUENAS_NSS_REQUIRE_NAMESPACE=1`
//! makes that a failure.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs;
use std::io;
use std::path::Path;
use std::thread;

use truenas_nss::{Error, innetgr};

/// `lab` holds `client1` with any user and domain, and `client2` for
/// `alice` in `example.com` alone. `staff` holds `bob` on no host, which
/// the dash says.
const NETGROUP: &str =
    "lab (client1,,) (client2,alice,example.com)\nstaff (-,bob,)\n";

fn required() -> bool {
    std::env::var_os("TRUENAS_NSS_REQUIRE_NAMESPACE").is_some_and(|v| v == "1")
}

/// `mount(2)`, with `None` passed as null.
fn mount(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), String> {
    let c = |s: &str| CString::new(s).expect("no NUL in a mount argument");
    let (source, fstype, data) = (source.map(c), fstype.map(c), data.map(c));
    let path = c(target);
    let ptr = |s: &Option<CString>| {
        s.as_ref().map_or(std::ptr::null(), |s| s.as_ptr())
    };
    // SAFETY: each pointer is null or a NUL-terminated string owned above,
    // which outlives the call.
    let done = unsafe {
        libc::mount(
            ptr(&source),
            path.as_ptr(),
            ptr(&fstype),
            flags,
            ptr(&data).cast(),
        )
    };
    match done {
        0 => Ok(()),
        _ => Err(format!(
            "mount on {target} ({})",
            io::Error::last_os_error()
        )),
    }
}

/// Write `contents` to `path`, naming the path in the error.
fn write(path: &str, contents: String) -> Result<(), String> {
    fs::write(path, contents).map_err(|e| format!("write {path} ({e})"))
}

/// Enter the namespaces and lay the overlay on `/etc`, giving back the
/// directory that holds its layers.
fn enter() -> Result<tempfile::TempDir, String> {
    // SAFETY: neither call takes an argument or fails.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let flags = match uid {
        0 => libc::CLONE_NEWNS,
        _ => libc::CLONE_NEWUSER | libc::CLONE_NEWNS,
    };
    // SAFETY: unshare takes flags alone, and the process has the one
    // thread a new user namespace needs.
    if unsafe { libc::unshare(flags) } != 0 {
        return Err(format!("unshare ({})", io::Error::last_os_error()));
    }
    if uid != 0 {
        write("/proc/self/setgroups", "deny".into())?;
        write("/proc/self/uid_map", format!("0 {uid} 1"))?;
        write("/proc/self/gid_map", format!("0 {gid} 1"))?;
    }
    // Nothing mounted here may reach the host's namespace.
    mount(None, "/", None, libc::MS_REC | libc::MS_PRIVATE, None)?;
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir ({e})"))?;
    let (upper, work) = (dir.path().join("upper"), dir.path().join("work"));
    for layer in [&upper, &work] {
        fs::create_dir(layer).map_err(|e| format!("mkdir ({e})"))?;
    }
    // The files are laid in the upper layer before the mount, since a
    // file the host's root owns cannot be copied up for writing from a user
    // namespace.
    let files = [
        ("netgroup", NETGROUP),
        ("nsswitch.conf", "netgroup: files\n"),
    ];
    for (name, contents) in files {
        let path = upper.join(name);
        fs::write(&path, contents)
            .map_err(|e| format!("write {} ({e})", path.display()))?;
    }
    let layers = format!(
        "lowerdir=/etc,upperdir={},workdir={}",
        upper.display(),
        work.display()
    );
    mount(Some("overlay"), "/etc", Some("overlay"), 0, Some(&layers))?;
    // A running nscd would answer from the host's netgroups.
    if Path::new("/run/nscd").is_dir() {
        mount(Some("tmpfs"), "/run/nscd", Some("tmpfs"), 0, None)?;
    }
    Ok(dir)
}

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
    let dir = match enter() {
        Ok(dir) => dir,
        Err(why) => {
            assert!(
                !required(),
                "TRUENAS_NSS_REQUIRE_NAMESPACE=1 but the suite could not \
                 lay its overlay, {why}"
            );
            println!("netgroup skipped, {why}");
            return;
        }
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
    // SAFETY: the path is a NUL-terminated literal.
    let unmounted = unsafe { libc::umount2(c"/etc".as_ptr(), 0) };
    assert_eq!(unmounted, 0, "umount /etc ({})", io::Error::last_os_error());
    dir.close().expect("remove the overlay's layers");
    println!("netgroup passed {} cases", refused.len() + cases.len() + 1);
}
