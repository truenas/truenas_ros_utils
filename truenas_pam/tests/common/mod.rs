// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Fixtures shared by the suites: the module probe, and the configuration
//! directory they run against.
//!
//! Nothing here touches `/etc/pam.d` or needs privilege. The service files
//! live in `tests/pam.d` and are handed to libpam through
//! [`Builder::confdir`](truenas_pam::Builder::confdir).

// Each suite drives a different part of this.
#![allow(dead_code)]

use std::path::Path;
use tempfile::TempDir;

/// Where a distribution keeps PAM modules.
const MODULE_DIRS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/security",
    "/usr/lib/aarch64-linux-gnu/security",
    "/lib/x86_64-linux-gnu/security",
    "/usr/lib64/security",
    "/usr/lib/security",
    "/lib/security",
];

/// The modules the service files in `tests/pam.d` name. All ship in
/// `libpam-modules`.
const REQUIRED: &[&str] = &[
    "pam_permit.so",
    "pam_deny.so",
    "pam_debug.so",
    "pam_echo.so",
    "pam_stress.so",
];

/// Whether a missing module should fail rather than skip.
fn modules_required() -> bool {
    std::env::var_os("TRUENAS_PAM_REQUIRE_MODULES").is_some_and(|v| v == "1")
}

/// `Some(())` when the suite can run; `None` to skip.
///
/// A stack whose modules are absent does not fail, it silently does less, so a
/// suite that ran against one would report success having tested nothing.
pub fn modules() -> Option<()> {
    let missing: Vec<&str> = REQUIRED
        .iter()
        .copied()
        .filter(|m| !MODULE_DIRS.iter().any(|d| Path::new(d).join(m).exists()))
        .collect();
    if missing.is_empty() {
        return Some(());
    }
    assert!(
        !modules_required(),
        "TRUENAS_PAM_REQUIRE_MODULES=1 but these are missing: {missing:?}; \
         install libpam-modules"
    );
    None
}

/// Assemble the service files into a directory of their own.
///
/// Copied rather than used in place because pam_echo takes an absolute path,
/// which only exists once the directory does.
pub fn confdir() -> TempDir {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pam.d");
    let dir = tempfile::tempdir().expect("temporary directory");
    let path = dir.path().to_str().expect("temporary directory is UTF-8");
    for entry in std::fs::read_dir(&src).expect("tests/pam.d is readable") {
        let entry = entry.expect("directory entry");
        let text = std::fs::read_to_string(entry.path()).expect("service file");
        std::fs::write(
            dir.path().join(entry.file_name()),
            text.replace("@CONFDIR@", path),
        )
        .expect("service file is writable");
    }
    dir
}
