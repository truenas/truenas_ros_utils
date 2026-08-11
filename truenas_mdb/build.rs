// SPDX-License-Identifier: MIT
//! Links the system LMDB.
//!
//! Nothing is compiled or generated here, so the crate has no
//! build-dependencies. Build-time requirement: `liblmdb-dev`. Runtime:
//! `liblmdb0`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-lib=lmdb");
}
