// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Fixture support for the suites: the C-compiler probe with its
//! skip-or-fail gate, fixture compilation, and counter readback, and the
//! namespace with an overlay on `/etc` that the suites run without the test
//! harness read their own files through.
//!
//! # Safety
//!
//! [`counter`] dlopens the fixture the suite already loaded — same path,
//! same module, refcounted — and reads a `long` the fixture exports.
//! [`overlay`] and [`leave`] pass `mount(2)`, `unshare(2)` and `umount2(2)`
//! NUL-terminated strings that outlive each call.
#![allow(unsafe_code)]
// Not every suite uses every helper.
#![allow(dead_code)]

use std::ffi::CString;
use std::fs;
use std::io;
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

fn namespace_required() -> bool {
    std::env::var_os("TRUENAS_NSS_REQUIRE_NAMESPACE").is_some_and(|v| v == "1")
}

/// `mount(2)`, with `None` data passed as null. The source and the type
/// are always strings, since memcheck reads the type as one even where the
/// kernel ignores it.
fn mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), String> {
    let c = |s: &str| CString::new(s).expect("no NUL in a mount argument");
    let (source, path, fstype) = (c(source), c(target), c(fstype));
    let data = data.map(c);
    let data = data.as_ref().map_or(std::ptr::null(), |s| s.as_ptr());
    // SAFETY: each pointer is null or a NUL-terminated string owned above,
    // which outlives the call.
    let done = unsafe {
        libc::mount(
            source.as_ptr(),
            path.as_ptr(),
            fstype.as_ptr(),
            flags,
            data.cast(),
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

/// Enter the namespaces and lay the overlay on `/etc` whose upper layer
/// holds `files`, giving back the directory that holds its layers.
fn enter(files: &[(&str, &[u8])]) -> Result<tempfile::TempDir, String> {
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
    // Nothing mounted here may reach the host's namespace. A change of
    // propagation ignores the source and the type.
    mount("none", "/", "none", libc::MS_REC | libc::MS_PRIVATE, None)?;
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir ({e})"))?;
    let (upper, work) = (dir.path().join("upper"), dir.path().join("work"));
    for layer in [&upper, &work] {
        fs::create_dir(layer).map_err(|e| format!("mkdir ({e})"))?;
    }
    // The files are laid in the upper layer before the mount, since a
    // file the host's root owns cannot be copied up for writing from a user
    // namespace.
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
    mount("overlay", "/etc", "overlay", 0, Some(&layers))?;
    // A running nscd would answer from the host's netgroups.
    if Path::new("/run/nscd").is_dir() {
        mount("tmpfs", "/run/nscd", "tmpfs", 0, None)?;
    }
    Ok(dir)
}

/// Enter a mount namespace of the suite's own, after a user namespace when
/// it is not root, and lay an overlay on `/etc` whose upper layer holds
/// `files`, each a name under `/etc` and its contents, before the suite's
/// first NSS call. A running nscd is hidden, since it would answer from the
/// host's files. `None` is a skip where a namespace cannot be made, which
/// `TRUENAS_NSS_REQUIRE_NAMESPACE=1` makes a failure. The process must have
/// one thread, since a new user namespace needs that.
pub fn overlay(
    suite: &str,
    files: &[(&str, &[u8])],
) -> Option<tempfile::TempDir> {
    match enter(files) {
        Ok(dir) => Some(dir),
        Err(why) => {
            assert!(
                !namespace_required(),
                "TRUENAS_NSS_REQUIRE_NAMESPACE=1 but {suite} could not lay \
                 its overlay, {why}"
            );
            println!("{suite} skipped, {why}");
            None
        }
    }
}

/// Take the overlay off `/etc` and remove its layers.
pub fn leave(dir: tempfile::TempDir) {
    // SAFETY: the path is a NUL-terminated literal.
    let unmounted = unsafe { libc::umount2(c"/etc".as_ptr(), 0) };
    assert_eq!(unmounted, 0, "umount /etc ({})", io::Error::last_os_error());
    dir.close().expect("remove the overlay's layers");
}
