// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Bindings to the system MIT Kerberos library (`libkrb5`): principals,
//! key tables, credential caches, and initial-credential acquisition.
//!
//! [`Principal`] parses and renders principal names with the library's own
//! quoting rules. [`Keytab`] reads, writes, and serializes key tables —
//! including fully in-memory ones, so key material from a database column
//! never has to touch a filesystem path. [`Ccache`] reads credential
//! caches, and [`kinit_keytab`]/[`kinit_password`] acquire initial
//! credentials into one.
//!
//! ```
//! use truenas_krb5::{EncType, KeySpec, Keytab};
//!
//! let kt = Keytab::from_bytes(&[])?;
//! kt.add_entry(
//!     "HTTP/nas.example.test@EXAMPLE.TEST",
//!     EncType::ENCTYPE_AES256_CTS_HMAC_SHA1_96,
//!     3,
//!     KeySpec::Password("correct horse"),
//! )?;
//!
//! let entry = kt.entries()?.next().unwrap()?;
//! assert_eq!(entry.principal.components, ["HTTP", "nas.example.test"]);
//! assert_eq!(entry.vno, 3);
//!
//! let bytes = kt.as_bytes()?; // a FILE-format keytab, end to end
//! assert_eq!(&bytes[..2], &[0x05, 0x02]);
//! # Ok::<(), truenas_krb5::Error>(())
//! ```
//!
//! # Handles own their context
//!
//! libkrb5 requires every handle to be used with the `krb5_context` that
//! produced it, from one thread at a time. Each [`Keytab`] and [`Ccache`]
//! therefore owns a context of its own: the types are `Send` and not
//! `Sync`, handles from different values never mix, and there is no
//! context type to thread through the API. The cost is one context —
//! one configuration read — per value, which is why operations that need
//! several handles ([`kinit_keytab`]) take names and resolve them
//! internally rather than accepting handles.
//!
//! # Identity is UTF-8
//!
//! Realm and principal components round-trip into lookups and stand in
//! authorization decisions, so a stray byte in one is refused
//! (`EINVAL`), never decoded lossily. Key bytes and addresses are not
//! identity and stay `Vec<u8>`.
//!
//! # Errors
//!
//! Every failure carries the raw `krb5_error_code` and the message the
//! library gave for it at the failing call ([`Error`]); codes from the
//! krb5 com_err table classify as [`ErrCode`], whose variants keep the
//! library's own macro names. System `errno` values pass through raw, and
//! this crate's own refusals (interior NUL, non-UTF-8 identity) are
//! reported as `EINVAL`.
//!
//! # Requirements
//!
//! `libkrb5-dev` to build; `libkrb5-3` and `libk5crypto3` to run. Checked
//! against MIT Kerberos 1.21.3. Host Kerberos configuration
//! (`/etc/krb5.conf`, `KRB5_CONFIG`) is read the way every other consumer
//! reads it; only operations that need a realm or a KDC depend on it.

mod ccache;
mod context;
mod error;
mod ffi;
mod init;
mod keytab;
mod principal;
mod types;

pub use ccache::{Ccache, Credential, Credentials};
pub use error::{ErrCode, Error, Result};
pub use init::{kinit_keytab, kinit_password};
pub use keytab::{Entries, KeySpec, Keytab, KeytabEntry};
pub use principal::Principal;
pub use types::{
    Address, AuthData, EncType, KeyInfo, PrincipalType, TicketFlags,
    TicketTimes,
};
