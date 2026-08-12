// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
//! [`Source`], [`Service`], and the machinery every operation shares:
//! loading, symbol resolution, the buffer-growth protocol, result
//! classification, and enumeration slots.
//!
//! # Safety
//!
//! - Every `dlopen`/`dlsym`/`dlerror` sequence runs under [`lock_load`]:
//!   `dlerror` reports through shared state, and serialising the whole load
//!   path is what makes reading it sound.
//! - A non-null `dlsym` result is transmuted to the function type the NSS
//!   service ABI fixes for its symbol name.
//! - A loaded module is never `dlclose`d. NSS modules keep global and
//!   thread-local state and are not built to be unloaded, so every handle
//!   and every [`Service`] lives for the process.
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use crate::ffi;
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::fmt;
use std::mem;
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// The three system NSS modules, in fan-out order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Source {
    /// `libnss_files`: `/etc/passwd` and `/etc/group`.
    Files = 0,
    /// `libnss_sss`: SSSD.
    Sss = 1,
    /// `libnss_winbind`: winbindd.
    Winbind = 2,
}

impl Source {
    /// The order the fan-out lookups try: `FILES`, `SSS`, `WINBIND`. First
    /// hit wins.
    pub const LOOKUP_ORDER: [Source; 3] =
        [Source::Files, Source::Sss, Source::Winbind];

    /// The module's name: `"FILES"`, `"SSS"`, or `"WINBIND"`.
    pub const fn name(self) -> &'static str {
        match self {
            Source::Files => "FILES",
            Source::Sss => "SSS",
            Source::Winbind => "WINBIND",
        }
    }

    /// The soname the module is loaded by. Bare, so the loader resolves it
    /// from its standard search path on any architecture.
    pub const fn soname(self) -> &'static str {
        match self {
            Source::Files => "libnss_files.so.2",
            Source::Sss => "libnss_sss.so.2",
            Source::Winbind => "libnss_winbind.so.2",
        }
    }

    /// Whether entries from this module are local to the host: true for
    /// [`Files`](Source::Files) only.
    pub const fn is_local(self) -> bool {
        matches!(self, Source::Files)
    }

    /// The symbol infix: `_nss_<prefix>_getpwnam_r` and friends.
    const fn prefix(self) -> &'static str {
        match self {
            Source::Files => "files",
            Source::Sss => "sss",
            Source::Winbind => "winbind",
        }
    }

    /// Where the module keeps its enumeration cursor.
    const fn scope(self) -> EntScope {
        match self {
            // nss_files reads a file and keeps one position per process.
            Source::Files => EntScope::Process,
            // sss and winbind keep their cursors in thread-local state.
            Source::Sss | Source::Winbind => EntScope::Thread,
        }
    }

    /// The process-lifetime service for this module, loaded on first use.
    ///
    /// A load failure is returned and not cached: the next call tries
    /// again, so a module installed after the first attempt starts working.
    pub fn service(self) -> Result<&'static Service> {
        static REGISTRY: [OnceLock<&'static Service>; 3] =
            [const { OnceLock::new() }; 3];

        let slot = &REGISTRY[self as usize];
        if let Some(svc) = slot.get() {
            return Ok(svc);
        }
        let _guard = lock_load();
        if let Some(svc) = slot.get() {
            return Ok(svc);
        }
        let soname = CString::new(self.soname()).map_err(|_| Error::NulByte)?;
        let svc = load_locked(LoadSpec {
            path: &soname,
            prefix: self.prefix(),
            name: self.name(),
            scope: self.scope(),
            source: self,
        })?;
        let _ = slot.set(svc);
        Ok(svc)
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Where an NSS module keeps its enumeration cursor. Decides how iterators
/// exclude each other; see [`Service::open`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EntScope {
    /// One cursor per process. Enumeration holds the service's lock for the
    /// iterator's whole life, so another thread's enumeration waits.
    Process,
    /// One cursor per thread per database. Threads enumerate concurrently;
    /// an iterator must stay on the thread that made it, which its `!Send`
    /// bound enforces.
    Thread,
}

/// The resolved service functions. A `None` is a symbol the module does not
/// export; using it is a per-operation [`Error::Symbol`].
#[derive(Clone, Copy)]
pub(crate) struct Fns {
    pub(crate) getpwnam_r: Option<ffi::GetpwnamRFn>,
    pub(crate) getpwuid_r: Option<ffi::GetpwuidRFn>,
    pub(crate) setpwent: Option<ffi::SetentFn>,
    pub(crate) endpwent: Option<ffi::EndentFn>,
    pub(crate) getpwent_r: Option<ffi::GetpwentRFn>,
    pub(crate) getgrnam_r: Option<ffi::GetgrnamRFn>,
    pub(crate) getgrgid_r: Option<ffi::GetgrgidRFn>,
    pub(crate) setgrent: Option<ffi::SetentFn>,
    pub(crate) endgrent: Option<ffi::EndentFn>,
    pub(crate) getgrent_r: Option<ffi::GetgrentRFn>,
}

impl Fns {
    /// Whether anything at all resolved. Nothing resolving means the module
    /// is not an NSS service for this prefix.
    fn any(&self) -> bool {
        self.getpwnam_r.is_some()
            || self.getpwuid_r.is_some()
            || self.setpwent.is_some()
            || self.endpwent.is_some()
            || self.getpwent_r.is_some()
            || self.getgrnam_r.is_some()
            || self.getgrgid_r.is_some()
            || self.setgrent.is_some()
            || self.endgrent.is_some()
            || self.getgrent_r.is_some()
    }
}

/// A loaded NSS service module. Lives for the process; obtained from
/// [`Source::service`] or [`Service::open`].
pub struct Service {
    name: &'static str,
    prefix: &'static str,
    source: Source,
    scope: EntScope,
    fns: Fns,
    /// Held for an enumeration's whole life when the cursor is
    /// process-scoped.
    iter_lock: Mutex<()>,
}

/// What [`load_locked`] needs to know.
struct LoadSpec<'a> {
    path: &'a CStr,
    prefix: &'static str,
    name: &'static str,
    scope: EntScope,
    source: Source,
}

impl Service {
    /// Load a service module from an explicit path, outside the registry
    /// [`Source::service`] keeps.
    ///
    /// `prefix` is the symbol infix — the functions resolved are
    /// `_nss_<prefix>_getpwnam_r` and friends. `scope` says where the
    /// module keeps its enumeration cursor, and `source` is the tag stamped
    /// on the entries it returns. The service and its handle live for the
    /// process; this crate's test fixtures are loaded this way.
    ///
    /// One `Service` per module: every call mints a fresh `Service` with
    /// its own enumeration lock, and the exclusion iterators rely on holds
    /// only while one lock spans a module's one cursor. Do not open a path
    /// twice, nor a module [`Source::service`] also reaches.
    pub fn open<P: AsRef<Path>>(
        path: P,
        prefix: &str,
        scope: EntScope,
        source: Source,
    ) -> Result<&'static Service> {
        let path = CString::new(path.as_ref().as_os_str().as_bytes())
            .map_err(|_| Error::NulByte)?;
        let name = intern(prefix);
        let _guard = lock_load();
        load_locked(LoadSpec {
            path: &path,
            prefix: name,
            name,
            scope,
            source,
        })
    }

    /// The module's name: [`Source::name`] for a registry service, the
    /// prefix for one opened by path.
    pub fn name(&self) -> &str {
        self.name
    }

    /// The tag stamped on entries this service returns.
    pub fn source(&self) -> Source {
        self.source
    }

    /// Where this module keeps its enumeration cursor.
    pub fn scope(&self) -> EntScope {
        self.scope
    }

    pub(crate) fn module(&self) -> &'static str {
        self.name
    }

    pub(crate) fn fns(&self) -> Fns {
        self.fns
    }

    /// The error for an operation whose symbol did not resolve.
    pub(crate) fn missing(&self, suffix: &str) -> Error {
        Error::Symbol {
            module: self.name,
            symbol: symbol_name(self.prefix, suffix).into(),
        }
    }
}

impl fmt::Debug for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Service")
            .field("name", &self.name)
            .field("source", &self.source)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// Serialises every load. `dlerror` reports through shared state, so the
/// whole dlopen-to-last-dlsym sequence holds this.
fn lock_load() -> MutexGuard<'static, ()> {
    static LOAD_LOCK: Mutex<()> = Mutex::new(());
    // A poisoned lock only means another load panicked; the dl state it
    // guards carries nothing across loads.
    LOAD_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The full symbol name for a module prefix and operation suffix.
pub(crate) fn symbol_name(prefix: &str, suffix: &str) -> String {
    format!("_nss_{prefix}_{suffix}")
}

/// dlopen and resolve. The caller holds [`lock_load`].
fn load_locked(spec: LoadSpec<'_>) -> Result<&'static Service> {
    // SAFETY: `path` is NUL-terminated and the flags are valid. The load
    // lock is held, so the dlerror read below reports this dlopen.
    let handle = unsafe {
        libc::dlopen(spec.path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL)
    };
    if handle.is_null() {
        return Err(Error::Load {
            module: spec.name,
            reason: dlerror_text(),
        });
    }

    let sym = |suffix: &str| -> Result<Option<*mut c_void>> {
        let symbol = CString::new(symbol_name(spec.prefix, suffix))
            .map_err(|_| Error::NulByte)?;
        // SAFETY: a live handle and a NUL-terminated symbol name. The
        // symbol is looked up through the handle's own dependency scope:
        // on glibc 2.34 and later the `files` functions live in
        // `libc.so.6`, which the stub `libnss_files.so.2` depends on.
        let p = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
        if p.is_null() {
            // A symbol this module does not export is a normal result, but
            // it left an error for the next `dlerror` in this thread to
            // read. Drain it, still under the load lock.
            // SAFETY: reading and discarding the pending dl error.
            unsafe { libc::dlerror() };
            return Ok(None);
        }
        Ok(Some(p))
    };

    // Each non-null address is given the type the NSS service ABI fixes
    // for its symbol name; that contract is the SAFETY basis for every
    // transmute below.
    let fns = Fns {
        getpwnam_r: sym("getpwnam_r")?.map(|p| {
            // SAFETY: the ABI's `getpwnam_r` signature.
            unsafe { mem::transmute::<*mut c_void, ffi::GetpwnamRFn>(p) }
        }),
        getpwuid_r: sym("getpwuid_r")?.map(|p| {
            // SAFETY: the ABI's `getpwuid_r` signature.
            unsafe { mem::transmute::<*mut c_void, ffi::GetpwuidRFn>(p) }
        }),
        setpwent: sym("setpwent")?.map(|p| {
            // SAFETY: the ABI's `setpwent` signature.
            unsafe { mem::transmute::<*mut c_void, ffi::SetentFn>(p) }
        }),
        endpwent: sym("endpwent")?.map(|p| {
            // SAFETY: the ABI's `endpwent` signature.
            unsafe { mem::transmute::<*mut c_void, ffi::EndentFn>(p) }
        }),
        getpwent_r: sym("getpwent_r")?.map(|p| {
            // SAFETY: the ABI's `getpwent_r` signature.
            unsafe { mem::transmute::<*mut c_void, ffi::GetpwentRFn>(p) }
        }),
        getgrnam_r: sym("getgrnam_r")?.map(|p| {
            // SAFETY: the ABI's `getgrnam_r` signature.
            unsafe { mem::transmute::<*mut c_void, ffi::GetgrnamRFn>(p) }
        }),
        getgrgid_r: sym("getgrgid_r")?.map(|p| {
            // SAFETY: the ABI's `getgrgid_r` signature.
            unsafe { mem::transmute::<*mut c_void, ffi::GetgrgidRFn>(p) }
        }),
        setgrent: sym("setgrent")?.map(|p| {
            // SAFETY: the ABI's `setgrent` signature.
            unsafe { mem::transmute::<*mut c_void, ffi::SetentFn>(p) }
        }),
        endgrent: sym("endgrent")?.map(|p| {
            // SAFETY: the ABI's `endgrent` signature.
            unsafe { mem::transmute::<*mut c_void, ffi::EndentFn>(p) }
        }),
        getgrent_r: sym("getgrent_r")?.map(|p| {
            // SAFETY: the ABI's `getgrent_r` signature.
            unsafe { mem::transmute::<*mut c_void, ffi::GetgrentRFn>(p) }
        }),
    };

    // Nothing resolving means the wrong prefix or the wrong library.
    if !fns.any() {
        return Err(Error::Symbol {
            module: spec.name,
            symbol: symbol_name(spec.prefix, "getpwnam_r").into(),
        });
    }

    let svc: &'static Service = Box::leak(Box::new(Service {
        name: spec.name,
        prefix: spec.prefix,
        source: spec.source,
        scope: spec.scope,
        fns,
        iter_lock: Mutex::new(()),
    }));
    // Every loaded service stays reachable for the life of the process: a
    // service's address keys the enumeration slots, so it must never be
    // freed and reused.
    LOADED.lock().unwrap_or_else(|e| e.into_inner()).push(svc);
    Ok(svc)
}

/// Every service ever loaded. Services live for the process; this is the
/// root that keeps each one reachable.
static LOADED: Mutex<Vec<&'static Service>> = Mutex::new(Vec::new());

/// A process-lifetime copy of `name`. The table keeps every copy
/// reachable, and an open retried with the same prefix reuses its entry
/// rather than growing the table.
fn intern(name: &str) -> &'static str {
    static NAMES: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    let mut names = NAMES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = names.iter().find(|n| **n == name) {
        return existing;
    }
    let copy: &'static str = Box::leak(name.to_owned().into_boxed_str());
    names.push(copy);
    copy
}

/// The `dlerror` text for the failure just observed. The caller holds
/// [`lock_load`].
fn dlerror_text() -> Box<str> {
    // SAFETY: the returned pointer is null or a NUL-terminated string
    // valid until the next dl call, which the load lock keeps ours.
    let p = unsafe { libc::dlerror() };
    if p.is_null() {
        return Box::from("dlopen failed without a dlerror message");
    }
    // SAFETY: non-null dlerror results are NUL-terminated.
    let text = unsafe { CStr::from_ptr(p) };
    text.to_string_lossy().into_owned().into_boxed_str()
}

// --- shared call machinery -------------------------------------------------

/// The scratch buffer every `_r` call starts with.
pub(crate) const INITIAL_BUFLEN: usize = 1024;

/// Drives one `_r` call through the buffer-growth protocol: the errno
/// out-parameter is zeroed for each attempt, and `TRYAGAIN` with `ERANGE`
/// — the service ABI's one request for a larger buffer — doubles it and
/// retries, without bound. Any other `(status, errno)` pair is a settled
/// answer and is returned as-is.
pub(crate) fn grow_and_call(
    buf: &mut Vec<u8>,
    mut call: impl FnMut(*mut c_char, libc::size_t, *mut c_int) -> c_int,
) -> (c_int, c_int) {
    loop {
        let mut errno: c_int = 0;
        let status = call(buf.as_mut_ptr().cast(), buf.len(), &mut errno);
        if status != ffi::NSS_STATUS_TRYAGAIN || errno != libc::ERANGE {
            return (status, errno);
        }
        // A fresh allocation, not a copy: the module rewrites the whole
        // result on the retry.
        *buf = vec![0; buf.len() * 2];
    }
}

/// Classify a lookup's `(status, errno)`. `Ok(true)` means the entry was
/// written and can be extracted; `Ok(false)` is not-found. An errno
/// outranks any status, including success.
pub(crate) fn classify_lookup(
    module: &'static str,
    op: &'static str,
    status: c_int,
    errno: c_int,
) -> Result<bool> {
    if errno != 0 {
        return Err(Error::Call {
            module,
            op,
            status,
            errno,
        });
    }
    match status {
        ffi::NSS_STATUS_NOTFOUND => Ok(false),
        ffi::NSS_STATUS_SUCCESS => Ok(true),
        _ => Err(Error::Call {
            module,
            op,
            status,
            errno: 0,
        }),
    }
}

/// Classify a `get*ent_r` result. `Ok(false)` is the end of the
/// enumeration: with no errno, a non-success status other than `TRYAGAIN`
/// means the cursor is done, not that the call faulted.
///
/// `TRYAGAIN` is a fault whether or not an errno came with it: a module
/// may report its reason through the thread's errno rather than the
/// out-parameter.
pub(crate) fn classify_ent(
    module: &'static str,
    op: &'static str,
    status: c_int,
    errno: c_int,
) -> Result<bool> {
    if errno != 0 || status == ffi::NSS_STATUS_TRYAGAIN {
        return Err(Error::Call {
            module,
            op,
            status,
            errno,
        });
    }
    Ok(status == ffi::NSS_STATUS_SUCCESS)
}

/// Run a `set*ent` or `end*ent` call. These have no errno out-parameter, so
/// global errno is the only channel: it is zeroed, the call made, and the
/// value read back before anything else can touch it.
pub(crate) fn call_ent(
    module: &'static str,
    op: &'static str,
    call: impl FnOnce() -> c_int,
) -> Result<()> {
    // SAFETY: `__errno_location` returns this thread's errno slot.
    unsafe { *libc::__errno_location() = 0 };
    let status = call();
    // SAFETY: as above; nothing ran between the call and this read.
    let errno = unsafe { *libc::__errno_location() };
    if status == ffi::NSS_STATUS_SUCCESS {
        Ok(())
    } else {
        Err(Error::Call {
            module,
            op,
            status,
            errno,
        })
    }
}

/// Copy an identity field out of an entry a module filled in: a login or
/// group name, or a member. Null and non-UTF-8 are refused — an identity
/// that cannot round-trip into a lookup is no identity.
///
/// # Safety
///
/// `p` is null or a NUL-terminated string live for the call.
pub(crate) unsafe fn name_field(p: *const c_char) -> Result<String> {
    if p.is_null() {
        return Err(Error::NullName);
    }
    // SAFETY: the caller's contract: non-null means NUL-terminated and
    // live.
    let s = unsafe { CStr::from_ptr(p) };
    s.to_str().map(str::to_owned).map_err(|_| Error::NotUtf8)
}

/// Copy a descriptive field out of an entry a module filled in: the GECOS,
/// home directory, or shell. A null pointer reads as the empty string and
/// bytes that are not UTF-8 are replaced — these fields describe the entry
/// rather than identify it, and a stray byte in one must not deny the
/// identity.
///
/// # Safety
///
/// `p` is null or a NUL-terminated string live for the call.
pub(crate) unsafe fn text_field(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the caller's contract: non-null means NUL-terminated and
    // live.
    let s = unsafe { CStr::from_ptr(p) };
    s.to_string_lossy().into_owned()
}

/// Try each module in [`Source::LOOKUP_ORDER`]; first hit wins. A module
/// whose failure is [`unavail`](Error::is_unavail) is skipped; any other
/// error — a load failure included — propagates.
pub(crate) fn fan_out<T>(
    mut lookup: impl FnMut(Source) -> Result<Option<T>>,
) -> Result<Option<T>> {
    for source in Source::LOOKUP_ORDER {
        match lookup(source) {
            Ok(Some(entry)) => return Ok(Some(entry)),
            Ok(None) => {}
            Err(err) if err.is_unavail() => {}
            Err(err) => return Err(err),
        }
    }
    Ok(None)
}

// --- enumeration slots -----------------------------------------------------

/// Which database an enumeration walks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Database {
    Passwd,
    Group,
}

thread_local! {
    /// The (service, database) pairs with a live enumeration on this
    /// thread. Services are leaked, so their addresses are stable keys.
    static LIVE: RefCell<Vec<(usize, Database)>> =
        const { RefCell::new(Vec::new()) };
}

/// A claim on a service's enumeration cursor, released on drop. Holding one
/// is what makes calling `set`/`get`/`end` in sequence sound.
#[derive(Debug)]
pub(crate) struct EnumSlot {
    pub(crate) svc: &'static Service,
    db: Database,
    /// Held when the cursor is process-scoped, so another thread's
    /// enumeration waits rather than interleaving.
    _guard: Option<MutexGuard<'static, ()>>,
}

impl EnumSlot {
    pub(crate) fn acquire(
        svc: &'static Service,
        db: Database,
    ) -> Result<EnumSlot> {
        let key = std::ptr::from_ref(svc) as usize;
        LIVE.with(|live| {
            let mut live = live.borrow_mut();
            // A process-scoped service has one cursor and one lock across
            // both databases, so any live enumeration of it on this thread
            // would deadlock on the lock below. A thread-scoped cursor is
            // per-database, so only the same database conflicts.
            let conflict = live.iter().any(|&(k, d)| {
                k == key && (svc.scope == EntScope::Process || d == db)
            });
            if conflict {
                return Err(Error::Busy { module: svc.name });
            }
            live.push((key, db));
            Ok(())
        })?;
        let guard = match svc.scope {
            // A poisoned lock only means an enumeration on another thread
            // panicked; `set*ent` resets everything the lock guards.
            EntScope::Process => {
                Some(svc.iter_lock.lock().unwrap_or_else(|e| e.into_inner()))
            }
            EntScope::Thread => None,
        };
        Ok(EnumSlot {
            svc,
            db,
            _guard: guard,
        })
    }
}

impl Drop for EnumSlot {
    fn drop(&mut self) {
        let key = std::ptr::from_ref(self.svc) as usize;
        // `try_with`, because an iterator held in thread-local storage is
        // dropped during this thread's teardown, when the table may already
        // be gone. Nothing can claim a slot on a dying thread, so having no
        // table to update is the same as an empty one.
        let _ = LIVE.try_with(|live| {
            live.borrow_mut()
                .retain(|&(k, d)| !(k == key && d == self.db));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A service that resolves nothing, for exercising the bookkeeping
    /// without loading anything. Statics, because slot keys are service
    /// addresses and a service never goes away.
    const fn dummy(scope: EntScope) -> Service {
        Service {
            name: "TEST",
            prefix: "test",
            source: Source::Files,
            scope,
            fns: Fns {
                getpwnam_r: None,
                getpwuid_r: None,
                setpwent: None,
                endpwent: None,
                getpwent_r: None,
                getgrnam_r: None,
                getgrgid_r: None,
                setgrent: None,
                endgrent: None,
                getgrent_r: None,
            },
            iter_lock: Mutex::new(()),
        }
    }

    static PROCESS_SVC: Service = dummy(EntScope::Process);
    static OTHER_SVC: Service = dummy(EntScope::Process);
    static THREAD_SVC: Service = dummy(EntScope::Thread);

    /// The symbol scheme is ABI; a slip here would resolve nothing.
    #[test]
    fn symbol_names_follow_the_nss_scheme() {
        assert_eq!(symbol_name("files", "getpwnam_r"), "_nss_files_getpwnam_r");
        assert_eq!(symbol_name("winbind", "endgrent"), "_nss_winbind_endgrent");
    }

    /// The fan-out order is FILES, SSS, WINBIND; local first.
    #[test]
    fn lookup_order_and_naming() {
        assert_eq!(
            Source::LOOKUP_ORDER,
            [Source::Files, Source::Sss, Source::Winbind]
        );
        assert_eq!(Source::Files.name(), "FILES");
        assert_eq!(Source::Sss.name(), "SSS");
        assert_eq!(Source::Winbind.name(), "WINBIND");
        assert_eq!(Source::Files.soname(), "libnss_files.so.2");
        assert_eq!(Source::Sss.soname(), "libnss_sss.so.2");
        assert_eq!(Source::Winbind.soname(), "libnss_winbind.so.2");
        assert!(Source::Files.is_local());
        assert!(!Source::Sss.is_local());
        assert!(!Source::Winbind.is_local());
    }

    /// An errno must outrank any status — even success. Reordering these
    /// checks would turn a reported fault into a fabricated entry.
    #[test]
    fn an_errno_outranks_success() {
        let res = classify_lookup(
            "TEST",
            "getpwnam_r",
            ffi::NSS_STATUS_SUCCESS,
            libc::EIO,
        );
        assert_eq!(
            res,
            Err(Error::Call {
                module: "TEST",
                op: "getpwnam_r",
                status: ffi::NSS_STATUS_SUCCESS,
                errno: libc::EIO,
            })
        );
    }

    #[test]
    fn lookup_classification_matches_the_contract() {
        let ok = classify_lookup("T", "op", ffi::NSS_STATUS_SUCCESS, 0);
        assert_eq!(ok, Ok(true));
        let miss = classify_lookup("T", "op", ffi::NSS_STATUS_NOTFOUND, 0);
        assert_eq!(miss, Ok(false));

        // A status-only failure keeps errno 0, which is what lets the
        // fan-out recognise UNAVAIL.
        let unavail =
            classify_lookup("T", "op", ffi::NSS_STATUS_UNAVAIL, 0).unwrap_err();
        assert!(unavail.is_unavail());
        assert_eq!(unavail.errno(), None);

        let tryagain = classify_lookup("T", "op", ffi::NSS_STATUS_TRYAGAIN, 0);
        assert!(tryagain.is_err());
    }

    /// For a cursor, a bare non-success status is the end of the data, not
    /// a fault; an errno is still a fault. TRYAGAIN is the exception: it is
    /// a fault with or without one, because a module may have reported its
    /// reason through the thread's errno, and an enumeration that stopped
    /// short must not read as one that finished.
    #[test]
    fn ent_classification_ends_cleanly() {
        assert_eq!(
            classify_ent("T", "op", ffi::NSS_STATUS_SUCCESS, 0),
            Ok(true)
        );
        assert_eq!(
            classify_ent("T", "op", ffi::NSS_STATUS_NOTFOUND, 0),
            Ok(false)
        );
        assert_eq!(
            classify_ent("T", "op", ffi::NSS_STATUS_UNAVAIL, 0),
            Ok(false)
        );
        assert_eq!(
            classify_ent("T", "op", ffi::NSS_STATUS_RETURN, 0),
            Ok(false)
        );
        assert!(
            classify_ent("T", "op", ffi::NSS_STATUS_TRYAGAIN, libc::EIO)
                .is_err()
        );
        assert_eq!(
            classify_ent("T", "op", ffi::NSS_STATUS_TRYAGAIN, 0),
            Err(Error::Call {
                module: "T",
                op: "op",
                status: ffi::NSS_STATUS_TRYAGAIN,
                errno: 0,
            })
        );
    }

    /// The driver must zero the errno slot on every attempt and keep
    /// doubling until the module stops asking; a stale ERANGE from a prior
    /// attempt would loop or misreport.
    #[test]
    fn grow_and_call_doubles_until_it_fits() {
        let mut buf = vec![0u8; INITIAL_BUFLEN];
        let mut calls = 0;
        let (status, errno) = grow_and_call(&mut buf, |_, len, errnop| {
            calls += 1;
            // SAFETY: the driver passes a live out-parameter.
            let e = unsafe { &mut *errnop };
            assert_eq!(*e, 0, "errno not zeroed on attempt {calls}");
            if len < 4096 {
                *e = libc::ERANGE;
                ffi::NSS_STATUS_TRYAGAIN
            } else {
                ffi::NSS_STATUS_SUCCESS
            }
        });
        assert_eq!((status, errno), (ffi::NSS_STATUS_SUCCESS, 0));
        assert_eq!(calls, 3);
        assert_eq!(buf.len(), 4096);
    }

    /// `ERANGE` under a status other than `TRYAGAIN` is not a request for a
    /// larger buffer. Retrying on it would throw away the status the module
    /// returned — a settled not-found could come back a hit.
    #[test]
    fn only_tryagain_with_erange_grows() {
        for status in [
            ffi::NSS_STATUS_NOTFOUND,
            ffi::NSS_STATUS_SUCCESS,
            ffi::NSS_STATUS_UNAVAIL,
            ffi::NSS_STATUS_RETURN,
        ] {
            let mut buf = vec![0u8; INITIAL_BUFLEN];
            let mut calls = 0;
            let got = grow_and_call(&mut buf, |_, _, errnop| {
                calls += 1;
                // SAFETY: the driver passes a live out-parameter.
                unsafe { *errnop = libc::ERANGE };
                status
            });
            assert_eq!(got, (status, libc::ERANGE), "status {status}");
            assert_eq!(calls, 1, "status {status} must not be retried");
            assert_eq!(buf.len(), INITIAL_BUFLEN);
        }
    }

    /// First hit wins and a miss moves on; the whole order exhausted is a
    /// clean not-found.
    #[test]
    fn fan_out_takes_the_first_hit() {
        let mut tried = Vec::new();
        let hit = fan_out(|s| {
            tried.push(s);
            match s {
                Source::Sss => Ok(Some("entry")),
                _ => Ok(None),
            }
        });
        assert_eq!(hit, Ok(Some("entry")));
        assert_eq!(tried, [Source::Files, Source::Sss]);

        let miss = fan_out::<()>(|_| Ok(None));
        assert_eq!(miss, Ok(None));
    }

    /// Only UNAVAIL is skipped. A load failure or an errno-carrying fault
    /// must stop the fan-out and surface, exactly as the deployed
    /// implementations behave.
    #[test]
    fn fan_out_skips_unavail_and_propagates_the_rest() {
        let skipped = fan_out(|s| match s {
            Source::Files => Err(Error::Call {
                module: "FILES",
                op: "getpwnam_r",
                status: ffi::NSS_STATUS_UNAVAIL,
                errno: 0,
            }),
            Source::Sss => Ok(Some("entry")),
            Source::Winbind => Ok(None),
        });
        assert_eq!(skipped, Ok(Some("entry")));

        let load = Error::Load {
            module: "SSS",
            reason: "missing".into(),
        };
        let propagated = fan_out::<()>(|s| match s {
            Source::Files => Ok(None),
            _ => Err(load.clone()),
        });
        assert_eq!(propagated, Err(load));

        let hard = Error::Call {
            module: "FILES",
            op: "getpwnam_r",
            status: ffi::NSS_STATUS_TRYAGAIN,
            errno: libc::EAGAIN,
        };
        let mut tried = Vec::new();
        let stopped = fan_out::<()>(|s| {
            tried.push(s);
            Err(hard.clone())
        });
        assert_eq!(stopped, Err(hard));
        assert_eq!(tried, [Source::Files], "a hard error must stop the walk");
    }

    /// A second same-thread claim that would share a cursor (or a lock)
    /// must fail up front, not deadlock.
    #[test]
    fn enum_slots_exclude_by_scope() {
        let process = &PROCESS_SVC;
        let first = EnumSlot::acquire(process, Database::Passwd).unwrap();
        // Same service, either database: the one lock makes both conflict.
        assert_eq!(
            EnumSlot::acquire(process, Database::Passwd).unwrap_err(),
            Error::Busy { module: "TEST" }
        );
        assert_eq!(
            EnumSlot::acquire(process, Database::Group).unwrap_err(),
            Error::Busy { module: "TEST" }
        );
        drop(first);
        // Released on drop.
        drop(EnumSlot::acquire(process, Database::Passwd).unwrap());

        let thread = &THREAD_SVC;
        let pw = EnumSlot::acquire(thread, Database::Passwd).unwrap();
        // Thread-scoped cursors are per-database: group is free while
        // passwd is live.
        let gr = EnumSlot::acquire(thread, Database::Group).unwrap();
        assert_eq!(
            EnumSlot::acquire(thread, Database::Passwd).unwrap_err(),
            Error::Busy { module: "TEST" }
        );
        drop(pw);
        drop(gr);

        // Distinct services never conflict.
        let other = &OTHER_SVC;
        let a = EnumSlot::acquire(process, Database::Passwd).unwrap();
        let b = EnumSlot::acquire(other, Database::Passwd).unwrap();
        drop(a);
        drop(b);
    }
}
