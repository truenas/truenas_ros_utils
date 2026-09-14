// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Links the system GSSAPI mechanism glue (`libgssapi_krb5`).
//!
//! Nothing is compiled or generated here, so the crate has no
//! build-dependencies. Build-time requirement: `libkrb5-dev`. Runtime:
//! `libgssapi-krb5-2`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-lib=gssapi_krb5");
}
