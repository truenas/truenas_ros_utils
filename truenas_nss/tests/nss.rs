// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Behavioral suite over fixture modules loaded by explicit path.
//!
//! Every FFI path here also runs under CI's valgrind pass, which is what
//! holds the copy-out-before-free discipline to account.

mod common;

use std::time::Duration;
use truenas_nss::{EntScope, Error, NssStatus, Service, Source};

/// A fixture built with its own symbol infix, so suites and counters never
/// interfere across tests.
fn fixture(
    infix: &str,
    extra: &[&str],
) -> Option<(tempfile::TempDir, std::path::PathBuf)> {
    common::cc()?;
    let dir = tempfile::tempdir().unwrap();
    let mut defines = vec![format!("NSS_FIXTURE_NAME={infix}")];
    defines.extend(extra.iter().map(|d| d.to_string()));
    let defines: Vec<&str> = defines.iter().map(String::as_str).collect();
    let path = common::build_fixture(dir.path(), "fixture.so", &defines);
    Some((dir, path))
}

/// Lookups must return every field, source-stamped as the service was
/// opened; a name or ID no table holds is `Ok(None)`, not an error.
#[test]
fn lookups_copy_every_field() {
    let Some((_dir, path)) = fixture("fields", &[]) else {
        return;
    };
    let svc =
        Service::open(&path, "fields", EntScope::Process, Source::Sss).unwrap();

    let alice = svc.getpwnam("alice").unwrap().unwrap();
    assert_eq!(alice.name, "alice");
    assert_eq!(alice.uid, 1000);
    assert_eq!(alice.gid, 1000);
    assert_eq!(alice.gecos, "Alice Fixture");
    assert_eq!(alice.dir, "/home/alice");
    assert_eq!(alice.shell, "/bin/sh");
    assert_eq!(alice.source, Source::Sss);
    assert!(!alice.is_local());
    assert_eq!(svc.getpwuid(1000).unwrap().unwrap(), alice);

    // A NULL gecos reads as empty.
    let bob = svc.getpwuid(1001).unwrap().unwrap();
    assert_eq!(bob.gecos, "");

    let alpha = svc.getgrnam("alpha").unwrap().unwrap();
    assert_eq!(alpha.name, "alpha");
    assert_eq!(alpha.gid, 2000);
    assert_eq!(alpha.members, ["alice", "bob"]);
    assert_eq!(alpha.source, Source::Sss);
    assert_eq!(svc.getgrgid(2000).unwrap().unwrap(), alpha);

    // Empty and NULL member arrays both read as no members.
    assert!(svc.getgrnam("empty").unwrap().unwrap().members.is_empty());
    assert!(svc.getgrnam("nullmem").unwrap().unwrap().members.is_empty());

    assert_eq!(svc.getpwnam("nobody-here").unwrap(), None);
    assert_eq!(svc.getpwuid(9999).unwrap(), None);
    assert_eq!(svc.getgrnam("no-group").unwrap(), None);
    assert_eq!(svc.getgrgid(9999).unwrap(), None);

    assert_eq!(svc.name(), "fields");
    assert_eq!(svc.source(), Source::Sss);
    assert_eq!(svc.scope(), EntScope::Process);
}

/// The 1024-byte buffer must double until the entry fits: the giant gecos
/// needs two doublings, so the module sees exactly three calls. A driver
/// that failed to reset the errno slot or to retry would diverge here.
#[test]
fn erange_grows_the_buffer() {
    let Some((_dir, path)) = fixture("erange", &[]) else {
        return;
    };
    let svc = Service::open(&path, "erange", EntScope::Process, Source::Files)
        .unwrap();

    let before = common::counter(&path, "_nss_erange_fixture_lookup_calls");
    let giant = svc.getpwnam("gecos-giant").unwrap().unwrap();
    assert_eq!(giant.gecos.len(), 3072);
    assert!(giant.gecos.bytes().all(|b| b == b'a'));
    let after = common::counter(&path, "_nss_erange_fixture_lookup_calls");
    assert_eq!(after - before, 3, "1024 -> 2048 -> 4096: three calls");

    // The same protocol drives group lookups: one 3072-byte member.
    let before = common::counter(&path, "_nss_erange_fixture_lookup_calls");
    let giant = svc.getgrnam("giant").unwrap().unwrap();
    assert_eq!(giant.members.len(), 1);
    assert_eq!(giant.members[0].len(), 3072);
    let after = common::counter(&path, "_nss_erange_fixture_lookup_calls");
    assert_eq!(after - before, 3);
}

/// The classification contract: TRYAGAIN with an errno is that errno;
/// UNAVAIL without one is the status-only error the fan-out skips;
/// NOTFOUND is a clean miss.
#[test]
fn statuses_classify_as_the_contract_says() {
    let Some((_dir, path)) =
        fixture("tryagain", &["NSS_FIXTURE_DEFAULT_MODE=\"tryagain\""])
    else {
        return;
    };
    let svc = Service::open(&path, "tryagain", EntScope::Process, Source::Sss)
        .unwrap();
    let err = svc.getpwnam("alice").unwrap_err();
    assert_eq!(err.errno(), Some(libc::EAGAIN));
    assert_eq!(err.status(), Some(NssStatus::TryAgain));
    assert!(!err.is_unavail());

    let Some((_dir, path)) =
        fixture("unavail", &["NSS_FIXTURE_DEFAULT_MODE=\"unavail\""])
    else {
        return;
    };
    let svc = Service::open(&path, "unavail", EntScope::Process, Source::Sss)
        .unwrap();
    let err = svc.getgrgid(2000).unwrap_err();
    assert!(err.is_unavail());
    assert_eq!(err.errno(), None);

    let Some((_dir, path)) =
        fixture("notfound", &["NSS_FIXTURE_DEFAULT_MODE=\"notfound\""])
    else {
        return;
    };
    let svc = Service::open(&path, "notfound", EntScope::Process, Source::Sss)
        .unwrap();
    assert_eq!(svc.getpwnam("alice").unwrap(), None);
    assert_eq!(svc.getgrnam("alpha").unwrap(), None);
}

/// An interior NUL never reaches the module; a non-UTF-8 entry is refused
/// on the way out rather than mangled.
#[test]
fn nul_in_and_bad_utf8_out_are_refused() {
    let Some((_dir, path)) = fixture("strict", &[]) else {
        return;
    };
    let svc = Service::open(&path, "strict", EntScope::Process, Source::Files)
        .unwrap();

    assert_eq!(svc.getpwnam("a\0b").unwrap_err(), Error::NulByte);
    assert_eq!(svc.getgrnam("a\0b").unwrap_err(), Error::NulByte);
    // uid 1003's name is not UTF-8.
    assert_eq!(svc.getpwuid(1003).unwrap_err(), Error::NotUtf8);
}

/// A path that does not load is `Load` with the dlerror text; a module
/// that resolves nothing for the prefix fails at open; one that lacks only
/// some symbols fails per operation.
#[test]
fn load_and_symbol_failures_name_what_is_missing() {
    let err = Service::open(
        "/nonexistent/libnss_missing.so.2",
        "missing",
        EntScope::Process,
        Source::Sss,
    )
    .unwrap_err();
    match err {
        Error::Load { module, reason } => {
            assert_eq!(module, "missing");
            assert!(!reason.is_empty());
        }
        other => panic!("expected Load, got {other:?}"),
    }

    let Some((_dir, path)) = fixture("nogrp", &["NSS_FIXTURE_NO_GROUPS"])
    else {
        return;
    };
    // The wrong prefix resolves nothing and must fail at open.
    let err = Service::open(&path, "wrong", EntScope::Process, Source::Files)
        .unwrap_err();
    assert!(matches!(err, Error::Symbol { .. }), "got {err:?}");

    // The right prefix opens, and only the group operations are missing.
    let svc = Service::open(&path, "nogrp", EntScope::Process, Source::Files)
        .unwrap();
    assert_eq!(svc.getpwuid(1000).unwrap().unwrap().name, "alice");
    match svc.getgrnam("alpha").unwrap_err() {
        Error::Symbol { symbol, .. } => {
            assert_eq!(&*symbol, "_nss_nogrp_getgrnam_r");
        }
        other => panic!("expected Symbol, got {other:?}"),
    }
    assert!(matches!(
        svc.group_entries().unwrap_err(),
        Error::Symbol { .. }
    ));
}

/// Enumeration yields the table in order, grows through an oversized entry
/// mid-walk, reports a non-UTF-8 entry and continues, ends the enumeration
/// exactly once, and is fused afterwards.
#[test]
fn enumeration_walks_the_table_in_order() {
    let Some((_dir, path)) = fixture("walk", &[]) else {
        return;
    };
    let svc =
        Service::open(&path, "walk", EntScope::Process, Source::Files).unwrap();
    let endent = || common::counter(&path, "_nss_walk_fixture_endent_calls");

    let before = endent();
    let mut iter = svc.passwd_entries().unwrap();
    assert_eq!(iter.next().unwrap().unwrap().name, "alice");
    assert_eq!(iter.next().unwrap().unwrap().name, "bob");
    // The giant entry forces ERANGE growth mid-enumeration.
    assert_eq!(iter.next().unwrap().unwrap().gecos.len(), 3072);
    // The non-UTF-8 entry is an error, and the walk goes on.
    assert_eq!(iter.next().unwrap().unwrap_err(), Error::NotUtf8);
    assert_eq!(iter.next().unwrap().unwrap().name, "carol");
    assert!(iter.next().is_none());
    assert_eq!(endent() - before, 1, "end of data ends the enumeration");
    // Fused: the closed iterator stays closed.
    assert!(iter.next().is_none());
    assert_eq!(endent() - before, 1);
    drop(iter);
    assert_eq!(endent() - before, 1, "drop after close must not end again");

    // The group walk, including the member-carrying and giant entries.
    let before = endent();
    let names: Vec<String> = svc
        .group_entries()
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|group| group.name)
        .collect();
    assert_eq!(names, ["alpha", "empty", "nullmem", "giant"]);
    assert_eq!(endent() - before, 1);

    // A fresh enumeration starts from the top.
    let mut again = svc.passwd_entries().unwrap();
    assert_eq!(again.next().unwrap().unwrap().name, "alice");
}

/// Dropping a live iterator must end the enumeration and release its
/// claim; leaving either behind would wedge every later enumeration.
#[test]
fn early_drop_ends_the_enumeration() {
    let Some((_dir, path)) = fixture("edrop", &[]) else {
        return;
    };
    let svc = Service::open(&path, "edrop", EntScope::Process, Source::Files)
        .unwrap();
    let endent = || common::counter(&path, "_nss_edrop_fixture_endent_calls");

    let before = endent();
    let mut iter = svc.passwd_entries().unwrap();
    assert_eq!(iter.next().unwrap().unwrap().name, "alice");
    drop(iter);
    assert_eq!(endent() - before, 1);

    // The claim is free again and the cursor was reset.
    let mut iter = svc.passwd_entries().unwrap();
    assert_eq!(iter.next().unwrap().unwrap().name, "alice");
}

/// A failing `set*ent` must surface as its own error and leave no claim
/// behind: the next attempt reports the same failure, not `Busy`.
#[test]
fn a_setent_failure_releases_the_claim() {
    let Some((_dir, path)) =
        fixture("setfail", &["NSS_FIXTURE_DEFAULT_MODE=\"unavail\""])
    else {
        return;
    };
    let svc = Service::open(&path, "setfail", EntScope::Process, Source::Sss)
        .unwrap();
    for _ in 0..2 {
        match svc.passwd_entries().unwrap_err() {
            Error::Call { op, status, .. } => {
                assert_eq!(op, "setpwent");
                assert_eq!(status, NssStatus::Unavail.raw());
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }
}

/// A second same-thread enumeration that would share a cursor or a lock
/// must be `Busy` up front — never a deadlock.
#[test]
fn conflicting_enumerations_are_busy_not_deadlocked() {
    let Some((_dir, path)) = fixture("busyp", &[]) else {
        return;
    };
    let process =
        Service::open(&path, "busyp", EntScope::Process, Source::Files)
            .unwrap();
    let iter = process.passwd_entries().unwrap();
    // Process scope: one lock spans both databases.
    assert!(matches!(
        process.passwd_entries().unwrap_err(),
        Error::Busy { .. }
    ));
    assert!(matches!(
        process.group_entries().unwrap_err(),
        Error::Busy { .. }
    ));
    drop(iter);
    drop(process.passwd_entries().unwrap());

    let Some((_dir, path)) = fixture("busyt", &["NSS_FIXTURE_THREAD_STATE=1"])
    else {
        return;
    };
    let thread =
        Service::open(&path, "busyt", EntScope::Thread, Source::Sss).unwrap();
    let mut pw = thread.passwd_entries().unwrap();
    assert!(matches!(
        thread.passwd_entries().unwrap_err(),
        Error::Busy { .. }
    ));
    // Thread scope: the group cursor is its own, so both run interleaved.
    let mut gr = thread.group_entries().unwrap();
    assert_eq!(pw.next().unwrap().unwrap().name, "alice");
    assert_eq!(gr.next().unwrap().unwrap().name, "alpha");
    assert_eq!(pw.next().unwrap().unwrap().name, "bob");
    assert_eq!(gr.next().unwrap().unwrap().name, "empty");
}

/// Thread-scoped cursors belong to their threads: another thread draining
/// the same database must not move this thread's cursor.
#[test]
fn thread_scoped_cursors_are_independent() {
    let Some((_dir, path)) = fixture("thrcur", &["NSS_FIXTURE_THREAD_STATE=1"])
    else {
        return;
    };
    let svc =
        Service::open(&path, "thrcur", EntScope::Thread, Source::Sss).unwrap();

    let mut mine = svc.passwd_entries().unwrap();
    assert_eq!(mine.next().unwrap().unwrap().name, "alice");
    assert_eq!(mine.next().unwrap().unwrap().name, "bob");

    // The scope joins the other thread's full drain before this thread
    // continues.
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let names: Vec<String> = svc
                .passwd_entries()
                .unwrap()
                .filter_map(|entry| entry.ok())
                .map(|user| user.name)
                .collect();
            assert_eq!(names, ["alice", "bob", "gecos-giant", "carol"]);
        });
    });

    assert_eq!(mine.next().unwrap().unwrap().name, "gecos-giant");
    assert_eq!(mine.next().unwrap().unwrap_err(), Error::NotUtf8);
    assert_eq!(mine.next().unwrap().unwrap().name, "carol");
    assert!(mine.next().is_none());
}

/// A process-scoped enumeration on another thread waits for the live
/// iterator to drop, then starts from the top.
#[test]
fn process_scoped_enumeration_serializes_across_threads() {
    let Some((_dir, path)) = fixture("plock", &[]) else {
        return;
    };
    let svc = Service::open(&path, "plock", EntScope::Process, Source::Files)
        .unwrap();

    let (tx, rx) = std::sync::mpsc::channel::<&str>();
    let mut held = svc.passwd_entries().unwrap();
    assert_eq!(held.next().unwrap().unwrap().name, "alice");

    std::thread::scope(|scope| {
        let tx = tx.clone();
        scope.spawn(move || {
            tx.send("attempting").unwrap();
            let mut blocked = svc.passwd_entries().unwrap();
            tx.send("acquired").unwrap();
            // The lock came with a reset cursor, not the first thread's.
            assert_eq!(blocked.next().unwrap().unwrap().name, "alice");
        });

        assert_eq!(rx.recv().unwrap(), "attempting");
        // Without the lock the spawned thread acquires immediately and
        // this window observes its "acquired".
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            rx.try_recv().is_err(),
            "the other thread acquired while an iterator was live"
        );
        drop(held);
        assert_eq!(rx.recv().unwrap(), "acquired");
    });
}
