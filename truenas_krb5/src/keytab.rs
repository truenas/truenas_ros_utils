// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Keytab`]: a key table, resolved by name or held entirely in memory.
//!
//! Every operation goes through libkrb5 — including the byte forms:
//! [`Keytab::from_bytes`] backs a `FILE` key table with an anonymous
//! `memfd`, and [`Keytab::as_bytes`] serializes by writing the entries into
//! a fresh one and reading the file back. The key-table format is therefore
//! always the library's own, never reimplemented here.
//!
//! Writing stamps entries: the `FILE` writer records its own write time, so
//! a serialize–deserialize round trip preserves principals, key material,
//! versions, and enctypes, but not timestamps.
#![allow(unsafe_code)]

use crate::context::{Context, cstring};
use crate::error::{Error, Result};
use crate::ffi;
use crate::principal::{Principal, RawPrincipal, read_principal};
use crate::types::{EncType, KeyInfo, widen_timestamp};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::FileExt;

/// One entry read from a key table.
#[derive(Clone, Debug)]
pub struct KeytabEntry {
    /// The principal the key belongs to.
    pub principal: Principal,
    /// When the entry was written to the table, seconds since the epoch.
    pub timestamp: i64,
    /// Key version number.
    pub vno: u32,
    /// The key itself.
    pub key: KeyInfo,
}

/// The key material for [`Keytab::add_entry`].
#[derive(Clone, Copy)]
pub enum KeySpec<'a> {
    /// Derive the key from a password with the enctype's string-to-key,
    /// salted the default way for the entry's principal — the derivation a
    /// KDC applies to the same password.
    Password(&'a str),
    /// Store these bytes as the key, verbatim. The length must fit the
    /// enctype.
    Key(&'a [u8]),
}

impl std::fmt::Debug for KeySpec<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Both arms are secret material.
        match self {
            KeySpec::Password(_) => {
                f.write_str("KeySpec::Password(<redacted>)")
            }
            KeySpec::Key(k) => write!(f, "KeySpec::Key(<{} bytes>)", k.len()),
        }
    }
}

/// A key table handle. Owns its library context, so it is `Send` but not
/// `Sync`; clone nothing, share nothing.
pub struct Keytab {
    ctx: Context,
    handle: ffi::krb5_keytab,
    /// Keeps the backing `memfd` alive for a table resolved through
    /// `/proc/self/fd`.
    mem: Option<OwnedFd>,
}

// SAFETY: the context and handle move together and are only ever used from
// the thread that holds the `Keytab`; raw-pointer fields already deny
// `Sync`.
unsafe impl Send for Keytab {}

impl Keytab {
    /// Resolve a key table by name, e.g. `FILE:/etc/krb5.keytab` (a bare
    /// path means `FILE`).
    pub fn open(name: &str) -> Result<Keytab> {
        let ctx = Context::new()?;
        let cname = cstring(name, "keytab name")?;
        let mut handle: ffi::krb5_keytab = std::ptr::null_mut();
        // SAFETY: valid context, NUL-terminated name, out-parameter.
        let code = unsafe {
            ffi::krb5_kt_resolve(ctx.raw(), cname.as_ptr(), &mut handle)
        };
        ctx.check(code)?;
        Ok(Keytab {
            ctx,
            handle,
            mem: None,
        })
    }

    /// Resolve the host default key table (`default_keytab_name` in
    /// `krb5.conf`, normally `FILE:/etc/krb5.keytab`).
    pub fn system_default() -> Result<Keytab> {
        let ctx = Context::new()?;
        let mut handle: ffi::krb5_keytab = std::ptr::null_mut();
        // SAFETY: valid context and out-parameter.
        let code = unsafe { ffi::krb5_kt_default(ctx.raw(), &mut handle) };
        ctx.check(code)?;
        Ok(Keytab {
            ctx,
            handle,
            mem: None,
        })
    }

    /// Load key-table bytes without touching the filesystem: the bytes back
    /// an anonymous `memfd`, resolved as a `FILE` key table through
    /// `/proc/self/fd`. Empty input is an empty table.
    pub fn from_bytes(data: &[u8]) -> Result<Keytab> {
        let ctx = Context::new()?;
        let (mut file, fd) = memfd()?;
        if data.is_empty() {
            file.write_all(EMPTY_KEYTAB).map_err(io_error)?;
        } else {
            file.write_all(data).map_err(io_error)?;
        }
        let handle = resolve_fd(&ctx, &fd)?;
        Ok(Keytab {
            ctx,
            handle,
            mem: Some(fd),
        })
    }

    /// The name the library reports for this table.
    pub fn name(&self) -> Result<String> {
        // MAX_KEYTAB_NAME_LEN is 1100.
        let mut buf = [0i8; 1104];
        // SAFETY: live handle on its own context; the buffer length is
        // passed and the library NUL-terminates within it.
        let code = unsafe {
            ffi::krb5_kt_get_name(
                self.ctx.raw(),
                self.handle,
                buf.as_mut_ptr().cast(),
                buf.len() as std::os::raw::c_uint,
            )
        };
        self.ctx.check(code)?;
        // SAFETY: NUL-terminated by the successful call above.
        let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr().cast()) };
        Ok(name.to_string_lossy().into_owned())
    }

    /// The key-table type, e.g. `"FILE"`.
    pub fn kt_type(&self) -> String {
        // SAFETY: live handle; the returned string is a static owned by the
        // library, copied before the borrow ends.
        unsafe {
            let ptr = ffi::krb5_kt_get_type(self.ctx.raw(), self.handle);
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }

    /// Iterate the entries. Each item is one entry or the error that entry
    /// produced; a cursor fault ends the iteration.
    pub fn entries(&self) -> Result<Entries<'_>> {
        let mut cursor: ffi::krb5_kt_cursor = std::ptr::null_mut();
        // SAFETY: live handle and out-cursor; a successful start is paired
        // with `krb5_kt_end_seq_get` in `Entries::drop`.
        let code = unsafe {
            ffi::krb5_kt_start_seq_get(self.ctx.raw(), self.handle, &mut cursor)
        };
        self.ctx.check(code)?;
        Ok(Entries {
            kt: self,
            cursor,
            done: false,
        })
    }

    /// Add an entry for `principal` (parsed with the library's quoting
    /// rules), with the given enctype and key version.
    pub fn add_entry(
        &self,
        principal: &str,
        enctype: EncType,
        vno: u32,
        key: KeySpec<'_>,
    ) -> Result<()> {
        let target = RawPrincipal::parse(&self.ctx, principal)?;
        let mut entry = ffi::krb5_keytab_entry {
            magic: 0,
            principal: target.raw(),
            // The FILE writer stamps its own write time.
            timestamp: 0,
            vno,
            key: ffi::krb5_keyblock {
                magic: 0,
                enctype: enctype.raw(),
                length: 0,
                contents: std::ptr::null_mut(),
            },
        };
        match key {
            KeySpec::Key(bytes) => {
                entry.key.length = c_uint_len(bytes.len(), "key")?;
                entry.key.contents = bytes.as_ptr().cast_mut();
                // SAFETY: live handle; the entry borrows the caller's key
                // bytes and the parsed principal only for this call — the
                // library copies what it stores.
                let code = unsafe {
                    ffi::krb5_kt_add_entry(
                        self.ctx.raw(),
                        self.handle,
                        &mut entry,
                    )
                };
                self.ctx.check(code)
            }
            KeySpec::Password(password) => {
                let salt = PrincipalSalt::derive(&self.ctx, &target)?;
                let string = ffi::krb5_data {
                    magic: 0,
                    length: c_uint_len(password.len(), "password")?,
                    data: password.as_ptr().cast_mut().cast(),
                };
                // SAFETY: string and salt describe live buffers; the out
                // keyblock is freed below on every path after a success.
                let code = unsafe {
                    ffi::krb5_c_string_to_key(
                        self.ctx.raw(),
                        enctype.raw(),
                        &string,
                        salt.data(),
                        &mut entry.key,
                    )
                };
                self.ctx.check(code)?;
                // SAFETY: as for the raw-key arm; the derived keyblock is
                // released afterwards whatever the add returned.
                let code = unsafe {
                    ffi::krb5_kt_add_entry(
                        self.ctx.raw(),
                        self.handle,
                        &mut entry,
                    )
                };
                // SAFETY: keyblock allocated by the successful
                // string-to-key above, freed exactly once.
                unsafe {
                    ffi::krb5_free_keyblock_contents(
                        self.ctx.raw(),
                        &mut entry.key,
                    )
                };
                self.ctx.check(code)
            }
        }
    }

    /// Remove every entry for `principal` that also matches the enctype
    /// and key-version filters when given. Returns how many were removed.
    ///
    /// Removal is not atomic: an error part-way leaves earlier matches
    /// already removed.
    pub fn remove_entry(
        &self,
        principal: &str,
        enctype: Option<EncType>,
        vno: Option<u32>,
    ) -> Result<usize> {
        let target = RawPrincipal::parse(&self.ctx, principal)?;

        // Snapshot the matches first: removing while a cursor is open on
        // the same table is undefined in the key-table interface. `key` is a
        // `KeyInfo` so the copied secret bytes are scrubbed when the
        // snapshot drops, like every other exposure of key material.
        struct Match {
            timestamp: ffi::krb5_timestamp,
            vno: u32,
            key: KeyInfo,
        }
        let mut matches = Vec::new();
        {
            let mut entries = self.entries()?;
            while let Some(found) = entries.next_raw()? {
                let RawEntry { entry, .. } = &found;
                // SAFETY: both principals are live for this call.
                let same = unsafe {
                    ffi::krb5_principal_compare(
                        self.ctx.raw(),
                        entry.principal,
                        target.raw(),
                    )
                } != 0;
                let want = same
                    && enctype.is_none_or(|e| e.raw() == entry.key.enctype)
                    && vno.is_none_or(|v| v == entry.vno);
                if want {
                    matches.push(Match {
                        timestamp: entry.timestamp,
                        vno: entry.vno,
                        key: KeyInfo {
                            enctype: entry.key.enctype,
                            contents: found.key_bytes().to_vec(),
                        },
                    });
                }
            }
        }

        for m in &matches {
            let mut entry = ffi::krb5_keytab_entry {
                magic: 0,
                principal: target.raw(),
                timestamp: m.timestamp,
                vno: m.vno,
                key: ffi::krb5_keyblock {
                    magic: 0,
                    enctype: m.key.enctype,
                    length: m.key.contents.len() as std::os::raw::c_uint,
                    contents: m.key.contents.as_ptr().cast_mut(),
                },
            };
            // SAFETY: live handle; the entry borrows this call's buffers
            // only, and names an entry the snapshot saw.
            let code = unsafe {
                ffi::krb5_kt_remove_entry(
                    self.ctx.raw(),
                    self.handle,
                    &mut entry,
                )
            };
            self.ctx.check(code)?;
        }
        Ok(matches.len())
    }

    /// Serialize: write every entry into a fresh `FILE` key table backed by
    /// an anonymous `memfd` and return the file's bytes. Timestamps are the
    /// write's, not the source entries' (see the module docs).
    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        let (mut file, fd) = memfd()?;
        // The library's writer requires an existing file to already carry
        // the format version — it initializes only files it creates, and a
        // `/proc/self/fd` path always exists.
        file.write_all(EMPTY_KEYTAB).map_err(io_error)?;
        let out = resolve_fd(&self.ctx, &fd)?;
        let out = KeytabGuard {
            ctx: &self.ctx,
            handle: out,
        };

        let mut entries = self.entries()?;
        while let Some(mut found) = entries.next_raw()? {
            // SAFETY: live output handle; the entry was filled by
            // `krb5_kt_next_entry` moments ago and is freed by `RawEntry`'s
            // drop after the add copies it.
            let code = unsafe {
                ffi::krb5_kt_add_entry(
                    self.ctx.raw(),
                    out.handle,
                    &mut found.entry,
                )
            };
            self.ctx.check(code)?;
        }
        drop(entries);
        drop(out);

        let len = file.metadata().map_err(io_error)?.len() as usize;
        let mut bytes = vec![0u8; len];
        file.read_exact_at(&mut bytes, 0).map_err(io_error)?;
        Ok(bytes)
    }
}

impl Drop for Keytab {
    fn drop(&mut self) {
        // SAFETY: handle from resolve/default on `self.ctx`, closed exactly
        // once, before the context it belongs to.
        unsafe { ffi::krb5_kt_close(self.ctx.raw(), self.handle) };
    }
}

impl std::fmt::Debug for Keytab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keytab")
            .field("type", &self.kt_type())
            .field("in_memory", &self.mem.is_some())
            .finish_non_exhaustive()
    }
}

/// Closes a scratch output table even on the error paths.
struct KeytabGuard<'a> {
    ctx: &'a Context,
    handle: ffi::krb5_keytab,
}

impl Drop for KeytabGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: handle resolved on `ctx`, closed exactly once.
        unsafe { ffi::krb5_kt_close(self.ctx.raw(), self.handle) };
    }
}

/// One raw entry, freed on drop.
struct RawEntry<'kt> {
    ctx: &'kt Context,
    entry: ffi::krb5_keytab_entry,
}

impl RawEntry<'_> {
    fn key_bytes(&self) -> &[u8] {
        if self.entry.key.length == 0 {
            return &[];
        }
        // SAFETY: the library filled this keyblock; contents/length
        // describe its allocation, borrowed no longer than `self`.
        unsafe {
            std::slice::from_raw_parts(
                self.entry.key.contents,
                self.entry.key.length as usize,
            )
        }
    }
}

impl Drop for RawEntry<'_> {
    fn drop(&mut self) {
        // SAFETY: filled by `krb5_kt_next_entry`, freed exactly once with
        // the paired free.
        unsafe {
            ffi::krb5_free_keytab_entry_contents(
                self.ctx.raw(),
                &mut self.entry,
            )
        };
    }
}

/// Iterator over a key table's entries.
#[derive(Debug)]
pub struct Entries<'kt> {
    kt: &'kt Keytab,
    cursor: ffi::krb5_kt_cursor,
    done: bool,
}

impl<'kt> Entries<'kt> {
    /// The raw step shared by the public iterator and the internal
    /// consumers that need the C entry itself.
    fn next_raw(&mut self) -> Result<Option<RawEntry<'kt>>> {
        if self.done {
            return Ok(None);
        }
        let mut entry =
            std::mem::MaybeUninit::<ffi::krb5_keytab_entry>::zeroed();
        // SAFETY: live handle and cursor; on 0 the entry is filled and owed
        // a free, on KRB5_KT_END nothing was written.
        let code = unsafe {
            ffi::krb5_kt_next_entry(
                self.kt.ctx.raw(),
                self.kt.handle,
                entry.as_mut_ptr(),
                &mut self.cursor,
            )
        };
        match code {
            0 => Ok(Some(RawEntry {
                ctx: &self.kt.ctx,
                // SAFETY: the successful call filled it.
                entry: unsafe { entry.assume_init() },
            })),
            ffi::KRB5_KT_END => {
                self.done = true;
                Ok(None)
            }
            _ => {
                // The cursor did not advance; a retry could only repeat the
                // fault.
                self.done = true;
                Err(self.kt.ctx.error(code))
            }
        }
    }
}

impl Iterator for Entries<'_> {
    type Item = Result<KeytabEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        let raw = match self.next_raw() {
            Ok(Some(raw)) => raw,
            Ok(None) => return None,
            Err(err) => return Some(Err(err)),
        };
        // SAFETY: the entry's principal is live until `raw` drops.
        let principal = match unsafe { read_principal(raw.entry.principal) } {
            Ok(principal) => principal,
            // An entry that will not convert is yielded as an error and the
            // walk goes on.
            Err(err) => return Some(Err(err)),
        };
        Some(Ok(KeytabEntry {
            principal,
            timestamp: widen_timestamp(raw.entry.timestamp),
            vno: raw.entry.vno,
            key: KeyInfo {
                enctype: raw.entry.key.enctype,
                contents: raw.key_bytes().to_vec(),
            },
        }))
    }
}

impl Drop for Entries<'_> {
    fn drop(&mut self) {
        // SAFETY: cursor from a successful start on this handle, released
        // exactly once.
        unsafe {
            ffi::krb5_kt_end_seq_get(
                self.kt.ctx.raw(),
                self.kt.handle,
                &mut self.cursor,
            )
        };
    }
}

/// The default salt for a principal, freed on drop.
struct PrincipalSalt<'a> {
    ctx: &'a Context,
    data: ffi::krb5_data,
}

impl<'a> PrincipalSalt<'a> {
    fn derive(
        ctx: &'a Context,
        principal: &RawPrincipal,
    ) -> Result<PrincipalSalt<'a>> {
        let mut data = ffi::krb5_data {
            magic: 0,
            length: 0,
            data: std::ptr::null_mut(),
        };
        // SAFETY: live principal; the out data is owed a
        // `krb5_free_data_contents`, done in drop.
        let code = unsafe {
            ffi::krb5_principal2salt(ctx.raw(), principal.raw(), &mut data)
        };
        ctx.check(code)?;
        Ok(PrincipalSalt { ctx, data })
    }

    fn data(&self) -> *const ffi::krb5_data {
        &self.data
    }
}

impl Drop for PrincipalSalt<'_> {
    fn drop(&mut self) {
        // SAFETY: filled by `krb5_principal2salt`, freed exactly once.
        unsafe { ffi::krb5_free_data_contents(self.ctx.raw(), &mut self.data) };
    }
}

/// An empty `FILE` key table: just the format version, from the key-table
/// format — one octet 0x05, one octet 0x02.
const EMPTY_KEYTAB: &[u8] = &[0x05, 0x02];

/// An anonymous memory-backed file, as both a `File` and the fd whose
/// `/proc/self/fd` path names it.
fn memfd() -> Result<(File, OwnedFd)> {
    // SAFETY: `memfd_create` with a static NUL-terminated debug name; the
    // returned descriptor is owned exactly once.
    let fd = unsafe {
        libc::memfd_create(c"truenas_krb5.keytab".as_ptr(), libc::MFD_CLOEXEC)
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(io_error(err));
    }
    // SAFETY: `fd` is a fresh descriptor this process owns.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let file = owned.try_clone().map(File::from).map_err(io_error)?;
    Ok((file, owned))
}

/// Resolve a `FILE` key table over an fd's `/proc/self/fd` path. Each
/// library operation reopens the path, which reaches the same memfd for as
/// long as the descriptor stays held.
fn resolve_fd(ctx: &Context, fd: &OwnedFd) -> Result<ffi::krb5_keytab> {
    let name = format!("FILE:/proc/self/fd/{}", fd.as_raw_fd());
    let cname = cstring(&name, "keytab name")?;
    let mut handle: ffi::krb5_keytab = std::ptr::null_mut();
    // SAFETY: valid context, NUL-terminated name, out-parameter.
    let code =
        unsafe { ffi::krb5_kt_resolve(ctx.raw(), cname.as_ptr(), &mut handle) };
    ctx.check(code)?;
    Ok(handle)
}

fn io_error(err: std::io::Error) -> Error {
    Error::new(
        err.raw_os_error().unwrap_or(libc::EIO),
        err.to_string().into(),
    )
}

/// A byte length narrowed to the `unsigned int` a libkrb5 field holds,
/// refusing rather than silently truncating — unreachable for real key or
/// password sizes, but a wrong length would otherwise misdescribe the buffer
/// to the library.
fn c_uint_len(len: usize, what: &str) -> Result<std::os::raw::c_uint> {
    std::os::raw::c_uint::try_from(len).map_err(|_| {
        Error::new(libc::EINVAL, format!("{what} is too large").into())
    })
}
