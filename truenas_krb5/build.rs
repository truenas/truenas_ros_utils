// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Links the system MIT Kerberos libraries.
//!
//! `libkrb5` carries the API; `libk5crypto` is linked as well because
//! `krb5_c_string_to_key` lives there and `libkrb5` only imports it.
//!
//! Nothing is compiled or generated here, so the crate has no
//! build-dependencies. Build-time requirement: `libkrb5-dev`. Runtime:
//! `libkrb5-3` and `libk5crypto3`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-lib=krb5");
    println!("cargo:rustc-link-lib=k5crypto");
}
