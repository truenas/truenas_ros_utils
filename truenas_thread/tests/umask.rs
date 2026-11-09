// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The umask of a thread that unshared its `fs_struct`, against the rest of
//! the process. Each test unshares in a thread of its own, which ends with
//! it, and reads a umask from `/proc/thread-self/status` rather than by
//! setting one, so the process's umask stays as it was and tests that run
//! at once see nothing of each other's.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use truenas_thread::{umask, unshare_fs};

/// The umask of the calling thread as the kernel reports it.
fn reported() -> u32 {
    let status = fs::read_to_string("/proc/thread-self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("Umask:")).unwrap();
    u32::from_str_radix(line["Umask:".len()..].trim(), 8).unwrap()
}

/// The permission bits of a new file the calling thread makes with `mode`.
fn made_with(mode: u32) -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let name = format!(
        "truenas_thread-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let path = std::env::temp_dir().join(name);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&path)
        .unwrap();
    let got = file.metadata().unwrap().permissions().mode() & 0o777;
    fs::remove_file(&path).unwrap();
    got
}

/// Run `body` in a thread of its own that has unshared its `fs_struct`.
fn unshared<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    thread::spawn(move || {
        unshare_fs().expect("a thread may unshare its fs_struct");
        body()
    })
    .join()
    .unwrap()
}

/// Catches a umask that does not reach the files the thread makes, or that
/// keeps bits it was not given.
#[test]
fn a_thread_makes_files_under_the_umask_it_set() {
    let modes = unshared(|| {
        umask(0);
        let whole = made_with(0o666);
        umask(0o077);
        let owner = made_with(0o666);
        umask(0o022);
        let some = made_with(0o777);
        (whole, owner, some)
    });
    assert_eq!(modes, (0o666, 0o600, 0o755));
}

/// Catches an `unshare_fs` that leaves the thread sharing the process's
/// `fs_struct`, so that its umask reaches every other thread.
#[test]
fn the_rest_of_the_process_keeps_its_umask() {
    let before = reported();
    let other = if before == 0o077 { 0o022 } else { 0o077 };
    let set = unshared(move || {
        umask(other);
        reported()
    });
    assert_eq!(set, other, "the thread that unshared");
    let seen = thread::spawn(|| (reported(), made_with(0o666)))
        .join()
        .unwrap();
    assert_eq!(seen, (before, 0o666 & !before), "a thread that did not");
}

/// Catches a `umask` that gives back the new umask, or none.
#[test]
fn umask_gives_back_the_umask_before() {
    let (first, second, now) = unshared(|| {
        umask(0o027);
        let first = umask(0o077);
        let second = umask(0);
        (first, second, reported())
    });
    assert_eq!((first, second, now), (0o027, 0o077, 0));
}

/// Catches an `unshare_fs` that starts the thread from some umask other
/// than the one it shared, since the copy is of the process's.
#[test]
fn a_thread_that_unshares_keeps_the_umask_it_had() {
    let before = reported();
    let after = unshared(reported);
    assert_eq!(after, before);
}
