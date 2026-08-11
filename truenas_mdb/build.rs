//! Links the system LMDB.
//!
//! No `cc` (nothing is compiled here), no `bindgen` (the declarations are
//! hand-written in `src/ffi.rs`), and no `pkg-config` crate: liblmdb does ship
//! an `lmdb.pc`, but a bare `-llmdb` resolves on every Debian-family system we
//! target and keeps this crate's build-dependencies at zero.
//!
//! Build-time requirement: `liblmdb-dev`. Runtime: `liblmdb0`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-lib=lmdb");
}
