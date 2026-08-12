// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The fan-out over the real soname registry, end to end.
//!
//! The parent test builds three fixtures named exactly
//! `libnss_{files,sss,winbind}.so.2` and re-executes this binary with
//! `LD_LIBRARY_PATH` pointing at them, so the child's bare-soname `dlopen`
//! resolves to fixtures whose behavior each case steers through
//! `NSS_FIXTURE_*_MODE`. The loader reads `LD_LIBRARY_PATH` at process
//! start, which is why the cases need a child at all. The children escape
//! CI's valgrind runner; the identical FFI paths run under it in-process
//! through the `nss` suite.

mod common;

use std::process::Command;
use truenas_nss::{NssStatus, Source};

/// Build the three fixtures and run every child case against them.
#[test]
fn fan_out_matrix() {
    let Some(()) = common::cc() else { return };
    let dir = tempfile::tempdir().unwrap();
    for source in Source::LOOKUP_ORDER {
        let infix = source.soname();
        let infix = &infix["libnss_".len()..infix.len() - ".so.2".len()];
        common::build_fixture(
            dir.path(),
            source.soname(),
            &[&format!("NSS_FIXTURE_NAME={infix}")],
        );
    }

    let cases: [(&str, &[(&str, &str)]); 5] = [
        ("child_files_answers_first", &[]),
        (
            "child_unavail_is_skipped",
            &[("NSS_FIXTURE_files_MODE", "unavail")],
        ),
        (
            "child_a_hard_error_stops_the_walk",
            &[("NSS_FIXTURE_files_MODE", "tryagain")],
        ),
        (
            "child_every_miss_is_none",
            &[
                ("NSS_FIXTURE_files_MODE", "notfound"),
                ("NSS_FIXTURE_sss_MODE", "notfound"),
                ("NSS_FIXTURE_winbind_MODE", "notfound"),
            ],
        ),
        (
            "child_the_last_module_answers",
            &[
                ("NSS_FIXTURE_files_MODE", "notfound"),
                ("NSS_FIXTURE_sss_MODE", "notfound"),
            ],
        ),
    ];

    for (case, env) in cases {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.arg(case)
            .args(["--exact", "--ignored"])
            .env("LD_LIBRARY_PATH", dir.path());
        for (key, value) in env {
            cmd.env(key, value);
        }
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "case {case} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

/// All three modules hold "alice" and "alpha"; the walk must stop at
/// FILES.
#[test]
#[ignore = "child case, run by fan_out_matrix"]
fn child_files_answers_first() {
    let alice = truenas_nss::getpwnam("alice").unwrap().unwrap();
    assert_eq!(alice.source, Source::Files);
    assert!(alice.is_local());
    let alpha = truenas_nss::getgrnam("alpha").unwrap().unwrap();
    assert_eq!(alpha.source, Source::Files);
}

/// FILES reports UNAVAIL: the walk must skip it and take SSS's answer.
#[test]
#[ignore = "child case, run by fan_out_matrix"]
fn child_unavail_is_skipped() {
    let alice = truenas_nss::getpwnam("alice").unwrap().unwrap();
    assert_eq!(alice.source, Source::Sss);
    let alpha = truenas_nss::getgrgid(2000).unwrap().unwrap();
    assert_eq!(alpha.source, Source::Sss);
}

/// FILES fails with an errno: the walk must stop and surface it, not fall
/// through to a module that would have answered.
#[test]
#[ignore = "child case, run by fan_out_matrix"]
fn child_a_hard_error_stops_the_walk() {
    let err = truenas_nss::getpwnam("alice").unwrap_err();
    assert_eq!(err.errno(), Some(libc::EAGAIN));
    assert_eq!(err.status(), Some(NssStatus::TryAgain));
}

/// Every module misses: the walk is a clean `Ok(None)`.
#[test]
#[ignore = "child case, run by fan_out_matrix"]
fn child_every_miss_is_none() {
    assert_eq!(truenas_nss::getpwnam("alice").unwrap(), None);
    assert_eq!(truenas_nss::getgrnam("alpha").unwrap(), None);
    assert_eq!(truenas_nss::getpwuid(1000).unwrap(), None);
}

/// FILES and SSS miss: the walk must reach WINBIND and credit it.
#[test]
#[ignore = "child case, run by fan_out_matrix"]
fn child_the_last_module_answers() {
    let alice = truenas_nss::getpwuid(1000).unwrap().unwrap();
    assert_eq!(alice.source, Source::Winbind);
    assert!(!alice.is_local());
    let alpha = truenas_nss::getgrnam("alpha").unwrap().unwrap();
    assert_eq!(alpha.source, Source::Winbind);
}
