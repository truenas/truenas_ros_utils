// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Links the system PAM library.
//!
//! Nothing is compiled or generated here, so the crate has no
//! build-dependencies. Build-time requirement: `libpam0g-dev`. Runtime:
//! `libpam0g`.
//!
//! `libpam_misc` is not linked; see `Transaction`'s environment methods.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-lib=pam");
}
