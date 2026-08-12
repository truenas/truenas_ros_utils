// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Fixture support for the suites: the C-compiler probe with its
//! skip-or-fail gate, fixture compilation, and counter readback.
//!
//! # Safety
//!
//! [`counter`] dlopens the fixture the suite already loaded — same path,
//! same module, refcounted — and reads a `long` the fixture exports.
#![allow(unsafe_code)]
// Not every suite uses every helper.
#![allow(dead_code)]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn cc_required() -> bool {
    std::env::var_os("TRUENAS_NSS_REQUIRE_CC").is_some_and(|v| v == "1")
}

/// `Some(())` when a C compiler is present. `None` skips the caller —
/// unless `TRUENAS_NSS_REQUIRE_CC=1` (which CI sets) turns the skip into a
/// failure, so a missing compiler can never read as a pass.
pub fn cc() -> Option<()> {
    let ok = Command::new("cc")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    if ok {
        return Some(());
    }
    assert!(
        !cc_required(),
        "TRUENAS_NSS_REQUIRE_CC=1 but `cc` is missing or broken; \
         install a C compiler"
    );
    None
}

/// Compile the fixture module into `dir` as `file_name`. `defines` are
/// passed as `-D` options; `NSS_FIXTURE_NAME=<infix>` picks the symbol
/// names. A present-but-broken compile is always a failure, never a skip.
///
/// No soname is set on the output — see the note in the fixture source.
pub fn build_fixture(dir: &Path, file_name: &str, defines: &[&str]) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixture/nss_fixture.c");
    let out = dir.join(file_name);
    let mut cmd = Command::new("cc");
    cmd.args(["-shared", "-fPIC", "-O1", "-Wall", "-Werror", "-o"])
        .arg(&out)
        .arg(&src);
    for define in defines {
        cmd.arg(format!("-D{define}"));
    }
    let output = cmd.output().expect("running cc");
    assert!(
        output.status.success(),
        "cc failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    out
}

/// Read an exported `long` counter from a fixture. Opening the same path
/// again returns the already-loaded module, so this observes the state the
/// suite's calls produced.
pub fn counter(path: &Path, symbol: &str) -> i64 {
    let cpath = CString::new(path.as_os_str().as_bytes()).unwrap();
    let csym = CString::new(symbol).unwrap();
    // SAFETY: a NUL-terminated path and valid flags.
    let handle = unsafe {
        libc::dlopen(cpath.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL)
    };
    assert!(!handle.is_null(), "dlopen {}", path.display());
    // SAFETY: a live handle and a NUL-terminated symbol name.
    let sym = unsafe { libc::dlsym(handle, csym.as_ptr()) };
    assert!(!sym.is_null(), "{symbol} missing from {}", path.display());
    // SAFETY: the fixture exports this symbol as a C long.
    unsafe { *sym.cast::<libc::c_long>() }
}
