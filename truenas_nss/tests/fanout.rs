// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The fan-out over the real soname registry, end to end.
//!
//! The parent test builds fixtures named exactly
//! `libnss_{files,sss,winbind}.so.2` and re-executes this binary with
//! `LD_LIBRARY_PATH` pointing at them, so the child's bare-soname `dlopen`
//! resolves to fixtures whose behavior each case steers through
//! `NSS_FIXTURE_*_MODE`. A second set, in which the SSS soname cannot be
//! loaded, covers the walk over a module that is not there. The loader
//! reads `LD_LIBRARY_PATH` at process start, which is why the cases need a
//! child at all. A case reads its fixtures' counters back, so a child that
//! reached the host's own modules cannot pass. The children escape
//! CI's valgrind runner; the identical FFI paths run under it in-process
//! through the `nss` suite.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use truenas_nss::{Error, NssStatus, Source};

/// One child case: the test name, the directory its `LD_LIBRARY_PATH`
/// points at, and the fixture modes it steers.
type Case<'a> = (&'a str, &'a Path, &'a [(&'a str, &'a str)]);

/// The symbol infix inside a module's soname: `libnss_files.so.2` is
/// `files`.
fn infix(source: Source) -> &'static str {
    let soname = source.soname();
    &soname["libnss_".len()..soname.len() - ".so.2".len()]
}

/// How many raw lookups a child's fixture served. The directory is the one
/// the parent put on `LD_LIBRARY_PATH`, so a child whose bare-soname
/// `dlopen` reached anything else reads zero here.
fn lookup_calls(source: Source) -> i64 {
    let dir = std::env::var_os("LD_LIBRARY_PATH")
        .expect("the parent sets LD_LIBRARY_PATH for every child case");
    let path = PathBuf::from(dir).join(source.soname());
    let symbol = format!("_nss_{}_fixture_lookup_calls", infix(source));
    common::counter(&path, &symbol)
}

/// Build the three fixtures and run every child case against them.
#[test]
fn fan_out_matrix() {
    let Some(()) = common::cc() else { return };
    let dir = tempfile::tempdir().unwrap();
    // A second set in which SSS cannot be loaded at all.
    let unloadable = tempfile::tempdir().unwrap();
    for source in Source::LOOKUP_ORDER {
        let name = format!("NSS_FIXTURE_NAME={}", infix(source));
        common::build_fixture(dir.path(), source.soname(), &[&name]);
        let mut defines = vec![name.as_str()];
        if source == Source::Sss {
            defines.push("NSS_FIXTURE_UNRESOLVED");
        }
        common::build_fixture(unloadable.path(), source.soname(), &defines);
    }

    let cases: [Case<'_>; 6] = [
        ("child_files_answers_first", dir.path(), &[]),
        (
            "child_unavail_is_skipped",
            dir.path(),
            &[("NSS_FIXTURE_files_MODE", "unavail")],
        ),
        (
            "child_a_hard_error_stops_the_walk",
            dir.path(),
            &[("NSS_FIXTURE_files_MODE", "tryagain")],
        ),
        (
            "child_every_miss_is_none",
            dir.path(),
            &[
                ("NSS_FIXTURE_files_MODE", "notfound"),
                ("NSS_FIXTURE_sss_MODE", "notfound"),
                ("NSS_FIXTURE_winbind_MODE", "notfound"),
            ],
        ),
        (
            "child_the_last_module_answers",
            dir.path(),
            &[
                ("NSS_FIXTURE_files_MODE", "notfound"),
                ("NSS_FIXTURE_sss_MODE", "notfound"),
            ],
        ),
        (
            "child_a_load_failure_stops_the_walk",
            unloadable.path(),
            &[("NSS_FIXTURE_files_MODE", "notfound")],
        ),
    ];

    for (case, ld_path, env) in cases {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.arg(case)
            .args(["--exact", "--ignored"])
            .env("LD_LIBRARY_PATH", ld_path);
        for (key, value) in env {
            cmd.env(key, value);
        }
        let output = cmd.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "case {case} failed\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        // A filter that matches nothing is an exit status of zero, so
        // without this a renamed or no-longer-ignored case would stop
        // being run and still report success.
        assert!(
            stdout.contains("1 passed"),
            "case {case} did not run\nstdout:\n{stdout}"
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
    // Three fan-out lookups, each asking every module. The count is what
    // says the fixtures answered: a host whose own modules hold no such
    // name or ID satisfies the assertions above without them.
    for source in Source::LOOKUP_ORDER {
        assert_eq!(lookup_calls(source), 3, "{source} was not asked");
    }
}

/// SSS cannot be loaded: the walk must stop and surface that, not treat an
/// absent module as one more miss and take WINBIND's answer.
#[test]
#[ignore = "child case, run by fan_out_matrix"]
fn child_a_load_failure_stops_the_walk() {
    match truenas_nss::getpwnam("alice").unwrap_err() {
        Error::Load { module, reason } => {
            assert_eq!(module, "SSS");
            assert!(!reason.is_empty());
        }
        other => panic!("expected Load, got {other:?}"),
    }
    // The failure is not cached: the next lookup reports it again.
    assert!(matches!(
        truenas_nss::getgrnam("alpha").unwrap_err(),
        Error::Load { module: "SSS", .. }
    ));
    // WINBIND holds both entries, so a count of zero is what says the walk
    // stopped at SSS rather than falling through.
    assert_eq!(lookup_calls(Source::Files), 2);
    assert_eq!(lookup_calls(Source::Winbind), 0);
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
