// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! Direct passwd and group lookups against the system NSS service modules.
//!
//! The three modules a TrueNAS host resolves identities through —
//! `libnss_files`, `libnss_sss`, and `libnss_winbind` — are loaded with
//! `dlopen(3)` on first use and their `_nss_<module>_*` service functions
//! called directly. `nsswitch.conf` and the libc frontends never mediate a
//! lookup, so a caller can ask one module, or all three in a fixed order,
//! and always learns which module answered.
//!
//! ```
//! use truenas_nss::Source;
//!
//! if let Some(root) = Source::Files.getpwuid(0)? {
//!     assert_eq!(root.uid, 0);
//!     assert!(root.is_local());
//! }
//! # Ok::<(), truenas_nss::Error>(())
//! ```
//!
//! # One module or all three
//!
//! [`Source`]'s methods ask one module; `Ok(None)` is not-found. The free
//! functions ([`getpwnam`], [`getpwuid`], [`getgrnam`], [`getgrgid`]) fan
//! out over [`Source::LOOKUP_ORDER`] — `FILES`, `SSS`, `WINBIND` — taking
//! the first hit. A module that reports itself unavailable is skipped; a
//! module that fails any other way, one that cannot be loaded included,
//! surfaces as the error it raised.
//!
//! # Enumeration
//!
//! [`Source::passwd_entries`] and [`Source::group_entries`] walk one
//! module's database. There is no all-modules iterator: merging three
//! cursors would invent an ordering NSS does not define. An iterator ends
//! its enumeration when dropped. Cursors live in the module — per process
//! for `FILES`, per thread for `SSS` and `WINBIND` — so iterators are
//! `!Send`, a same-thread iterator that would share a cursor is
//! [`Error::Busy`], and a `FILES` enumeration on another thread waits.
//!
//! # What entries carry
//!
//! [`Passwd`] and [`Group`] name the module that produced them and hold
//! owned strings copied out of the module's buffers. Neither has a
//! password field: the real hash lives in the shadow database, and the
//! placeholder the passwd and group databases carry invites misuse.
//!
//! # Requirements
//!
//! Nothing at build time. At run time, glibc 2.34 or later and whichever
//! modules are asked for: `libnss_files.so.2` ships in `libc6`,
//! `libnss_sss.so.2` in `libnss-sss`, and `libnss_winbind.so.2` in
//! `libnss-winbind`. Checked against glibc 2.41.

mod error;
mod ffi;
mod grp;
mod pwd;
mod service;

pub use error::{Error, NssStatus, Result};
pub use grp::{Group, GroupIter, getgrgid, getgrnam};
pub use pwd::{Passwd, PasswdIter, getpwnam, getpwuid};
pub use service::{EntScope, Service, Source};
