// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Smoke tests against the running system's `files` module.
//!
//! These are what break first if a future glibc stops the stub
//! `libnss_files.so.2` from reaching the `_nss_files_*` functions through
//! its dependency scope. Only `files` is assumed installed — it ships in
//! `libc6`; sss and winbind may be absent from the host.

use truenas_nss::{Service, Source};

fn system_required() -> bool {
    std::env::var_os("TRUENAS_NSS_REQUIRE_SYSTEM").is_some_and(|v| v == "1")
}

/// The system `files` service, or a skip — which
/// `TRUENAS_NSS_REQUIRE_SYSTEM=1` (set by CI) turns into a failure, so an
/// unloadable module can never read as a pass.
fn files() -> Option<&'static Service> {
    match Source::Files.service() {
        Ok(svc) => Some(svc),
        Err(err) => {
            assert!(
                !system_required(),
                "TRUENAS_NSS_REQUIRE_SYSTEM=1 but the system files \
                 module did not load: {err}"
            );
            None
        }
    }
}

/// uid 0 exists on any Linux host; the entry must come back complete and
/// local, by ID and by the name the ID lookup reported.
#[test]
fn root_resolves_by_uid_and_name() {
    let Some(svc) = files() else { return };
    let root = svc.getpwuid(0).unwrap().expect("uid 0 missing from files");
    assert_eq!(root.uid, 0);
    assert!(!root.name.is_empty());
    assert!(!root.dir.is_empty());
    assert!(root.is_local());
    assert_eq!(root.source, Source::Files);

    let by_name = svc.getpwnam(&root.name).unwrap().unwrap();
    assert_eq!(by_name, root);
}

/// gid 0 exists on any Linux host.
#[test]
fn the_root_group_resolves() {
    let Some(svc) = files() else { return };
    let group = svc.getgrgid(0).unwrap().expect("gid 0 missing from files");
    assert_eq!(group.gid, 0);
    assert!(!group.name.is_empty());
    assert!(group.is_local());
}

/// Enumerating the host's passwd database must include uid 0. Entries a
/// host may legitimately hold that this crate refuses (non-UTF-8) are
/// skipped, not fatal.
#[test]
fn enumeration_reaches_the_whole_database() {
    let Some(svc) = files() else { return };
    let found_root = svc
        .passwd_entries()
        .unwrap()
        .filter_map(|entry| entry.ok())
        .any(|user| user.uid == 0);
    assert!(found_root, "uid 0 not seen in the files enumeration");
}

/// The fan-out must answer uid 0 from FILES without consulting the other
/// modules, which this host may not have installed.
#[test]
fn the_fan_out_answers_locally() {
    let Some(svc) = files() else { return };
    if svc.getpwuid(0).unwrap().is_none() {
        return;
    }
    let root = truenas_nss::getpwuid(0).unwrap().unwrap();
    assert_eq!(root.source, Source::Files);
}
