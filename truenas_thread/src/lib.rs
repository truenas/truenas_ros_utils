// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! The state of the calling thread that a server keeps apart from the rest
//! of its process.
//!
//! The threads of a process share one `fs_struct`, which holds the umask,
//! the working folder and the root. [`unshare_fs`] gives the calling thread
//! a copy of its own, and [`umask`] then sets the umask of that thread
//! alone and of the threads it creates after, which share its copy. The
//! workers of an io_uring instance are such threads, created by the thread
//! that submits to it.
//!
//! ```
//! std::thread::spawn(|| {
//!     truenas_thread::unshare_fs().expect("a thread may unshare");
//!     let before = truenas_thread::umask(0);
//!     assert_eq!(truenas_thread::umask(before), 0);
//! })
//! .join()
//! .unwrap();
//! ```

// The two calls below are the crate's whole binding.
#![allow(unsafe_code)]

use std::io;

/// Give the calling thread an `fs_struct` of its own, a copy of the one it
/// shared, so that its umask, working folder and root no longer follow the
/// rest of the process (`unshare(2)` with `CLONE_FS`). Any thread of a
/// process may, since the kernel refuses a thread only `CLONE_THREAD`,
/// `CLONE_SIGHAND` and `CLONE_VM`. Threads it creates after share its copy.
///
/// # Errors
///
/// The error `unshare(2)` gives, which is ENOMEM when no copy can be made.
pub fn unshare_fs() -> io::Result<()> {
    // SAFETY: unshare takes its flags alone and reads or writes no memory
    // of this process.
    let rc = unsafe { libc::unshare(libc::CLONE_FS) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Set the umask of the calling thread's `fs_struct` to `mask`, of which
/// the kernel keeps the permission bits, and give back the umask before
/// (`umask(2)`). Every thread that shares that `fs_struct` takes it, so a
/// thread sets its own alone once it has called [`unshare_fs`].
pub fn umask(mask: u32) -> u32 {
    // SAFETY: umask takes a mode alone, cannot fail, and reads or writes no
    // memory of this process.
    unsafe { libc::umask(mask) }
}
