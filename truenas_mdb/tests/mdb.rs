//! Behavioral tests for the public API.
//!
//! These take LMDB's storage as given and cover this crate's own decisions:
//! copying before a transaction ends, guard drop order, transaction slot
//! accounting, error classification, scan bounds, iterator state, and handle
//! lifetimes.
//!
//! Needs only a writable temp directory and the linked `liblmdb`.

use std::ops::ControlFlow;
use std::sync::Arc;

use truenas_mdb::{Db, Env, EnvFlags, EnvOptions, Error, Iter, MdbCode};

const SMALL: EnvOptions = EnvOptions {
    map_size: 1 << 20,
    max_dbs: 8,
    max_readers: 0,
    mode: 0o600,
    dir_mode: 0o700,
    flags: EnvFlags::empty(),
};

/// A fresh environment and a named database in it. The `TempDir` is returned
/// because dropping it removes the directory.
fn scratch() -> (tempfile::TempDir, Env, Db) {
    let (dir, env) = scratch_env(SMALL);
    let db = Db::create(&env, "state").unwrap();
    (dir, env, db)
}

fn scratch_env(opts: EnvOptions) -> (tempfile::TempDir, Env) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open_with(dir.path().join("env"), &opts).unwrap();
    (dir, env)
}

/// Collect a whole iterator, failing on the first error.
fn drain(iter: Iter) -> Vec<(Vec<u8>, Vec<u8>)> {
    iter.collect::<Result<Vec<_>, _>>().unwrap()
}

/// The keys visited by a scan, in order.
fn scanned_keys(db: &Db) -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    db.scan(|k, _| {
        keys.push(k.to_vec());
        ControlFlow::<()>::Continue(())
    })
    .unwrap();
    keys
}

// --- types ---------------------------------------------------------------

#[test]
fn handles_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Env>();
    assert_send_sync::<Db>();
    assert_send_sync::<Error>();
    assert_send_sync::<MdbCode>();
}

#[test]
fn version_reports_the_linked_library() {
    let (major, minor, patch) = truenas_mdb::version();
    assert_eq!((major, minor), (0, 9));
    assert!(patch >= 0);
}

// --- environment ---------------------------------------------------------

#[test]
fn open_uses_defaults_and_creates_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("env");
    assert!(!path.exists());

    let env = Env::open(&path).unwrap();
    assert!(path.join("data.mdb").is_file());
    assert!(path.join("lock.mdb").is_file());
    // The pool key is canonical, so it may differ textually from the input.
    assert_eq!(env.path(), std::fs::canonicalize(&path).unwrap());
    assert!(format!("{env:?}").contains("env"));
}

#[test]
fn open_accepts_anything_pathlike() {
    let dir = tempfile::tempdir().unwrap();
    let owned = dir.path().join("env");
    Env::open(&owned).unwrap();
    Env::open(owned.clone()).unwrap();
    Env::open(owned.as_path()).unwrap();
    Env::open(owned.to_str().unwrap()).unwrap();
}

#[test]
fn default_options_are_the_documented_ones() {
    let d = EnvOptions::default();
    assert_eq!(d.map_size, 1024 * 1024 * 1024);
    assert_eq!(d.max_dbs, 8);
    assert_eq!(d.max_readers, 0);
    assert_eq!(d.mode, 0o600);
    assert_eq!(d.dir_mode, 0o700);
    assert_eq!(d.flags, EnvFlags::empty());
}

#[test]
fn sync_is_callable_on_both_durability_settings() {
    for flags in [EnvFlags::empty(), EnvFlags::NOSYNC] {
        let (_dir, env) = scratch_env(EnvOptions { flags, ..SMALL });
        let db = Db::create(&env, "state").unwrap();
        db.put("k", "v").unwrap();
        env.sync(false).unwrap();
        env.sync(true).unwrap();
        assert_eq!(db.get("k").unwrap().as_deref(), Some(&b"v"[..]));
    }
}

#[test]
fn the_environment_outlives_the_handle_that_opened_it() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path().join("env")).unwrap();
    let db = Db::create(&env, "state").unwrap();

    // The Db holds its own reference, so dropping the caller's does not close
    // the environment underneath it.
    drop(env);
    db.put("still", "open").unwrap();
    assert_eq!(db.get("still").unwrap().as_deref(), Some(&b"open"[..]));
    assert!(db.env().path().is_dir());
}

// --- opening databases ---------------------------------------------------

#[test]
fn main_open_and_create_select_the_right_database() {
    let (_dir, env) = scratch_env(SMALL);

    let main = Db::main(&env).unwrap();
    assert_eq!(main.name(), None);

    assert_eq!(
        Db::open(&env, "state").unwrap_err(),
        Error::Mdb(MdbCode::NotFound)
    );
    let created = Db::create(&env, "state").unwrap();
    assert_eq!(created.name(), Some("state"));
    // Now it exists, so `open` finds it and `create` is an ordinary open.
    assert_eq!(Db::open(&env, "state").unwrap().name(), Some("state"));
    assert_eq!(Db::create(&env, "state").unwrap().name(), Some("state"));
}

#[test]
fn named_databases_are_separate_namespaces() {
    let (_dir, env) = scratch_env(SMALL);
    let a = Db::create(&env, "a").unwrap();
    let b = Db::create(&env, "b").unwrap();

    a.put("k", "from-a").unwrap();
    b.put("k", "from-b").unwrap();
    assert_eq!(a.get("k").unwrap().as_deref(), Some(&b"from-a"[..]));
    assert_eq!(b.get("k").unwrap().as_deref(), Some(&b"from-b"[..]));

    a.clear().unwrap();
    assert!(a.get("k").unwrap().is_none());
    assert_eq!(b.get("k").unwrap().as_deref(), Some(&b"from-b"[..]));
}

#[test]
fn two_handles_on_one_database_see_the_same_data() {
    let (_dir, env) = scratch_env(SMALL);
    let one = Db::create(&env, "state").unwrap();
    let two = Db::open(&env, "state").unwrap();
    let cloned = one.clone();

    one.put("k", "v").unwrap();
    assert_eq!(two.get("k").unwrap().as_deref(), Some(&b"v"[..]));
    assert_eq!(cloned.get("k").unwrap().as_deref(), Some(&b"v"[..]));
}

#[test]
fn the_main_database_indexes_the_named_ones() {
    // Named databases are entries in the main database, so a scan of it also
    // yields their names.
    let (_dir, env) = scratch_env(SMALL);
    let main = Db::main(&env).unwrap();
    assert!(main.is_empty().unwrap());

    Db::create(&env, "state").unwrap();
    Db::create(&env, "stats").unwrap();
    assert_eq!(scanned_keys(&main), [b"state".to_vec(), b"stats".to_vec()]);
}

#[test]
fn exceeding_max_dbs_reports_dbs_full() {
    let (_dir, env) = scratch_env(EnvOptions {
        max_dbs: 2,
        ..SMALL
    });
    Db::create(&env, "one").unwrap();
    Db::create(&env, "two").unwrap();
    assert_eq!(
        Db::create(&env, "three").unwrap_err(),
        Error::Mdb(MdbCode::DbsFull)
    );
}

// --- reading and writing -------------------------------------------------

#[test]
fn put_get_del_round_trip() {
    let (_dir, _env, db) = scratch();

    assert_eq!(db.get("a").unwrap(), None);
    assert!(!db.contains_key("a").unwrap());
    assert!(
        !db.del("a").unwrap(),
        "deleting a missing key is not an error"
    );

    db.put("a", "one").unwrap();
    assert_eq!(db.get("a").unwrap().as_deref(), Some(&b"one"[..]));
    assert!(db.contains_key("a").unwrap());

    db.put("a", "two").unwrap();
    assert_eq!(db.get("a").unwrap().as_deref(), Some(&b"two"[..]));

    assert!(db.del("a").unwrap());
    assert_eq!(db.get("a").unwrap(), None);
    assert!(!db.del("a").unwrap());
}

#[test]
fn keys_and_values_accept_anything_byteslike() {
    let (_dir, _env, db) = scratch();
    db.put("str", "value").unwrap();
    db.put(String::from("string"), String::from("value"))
        .unwrap();
    db.put(b"bytes", b"value").unwrap();
    db.put(vec![1u8, 2, 3], vec![4u8, 5, 6]).unwrap();
    db.put(&b"slice"[..], &b"value"[..]).unwrap();

    assert_eq!(db.get("string").unwrap().as_deref(), Some(&b"value"[..]));
    assert_eq!(
        db.get([1u8, 2, 3]).unwrap().as_deref(),
        Some(&[4u8, 5, 6][..])
    );
    assert_eq!(db.len().unwrap(), 5);
}

#[test]
fn put_if_absent_stores_only_once() {
    let (_dir, _env, db) = scratch();

    assert!(db.put_if_absent("k", "first").unwrap());
    assert!(!db.put_if_absent("k", "second").unwrap());
    // The rejected write changed nothing.
    assert_eq!(db.get("k").unwrap().as_deref(), Some(&b"first"[..]));

    // ...and it is available again once the key is gone.
    db.del("k").unwrap();
    assert!(db.put_if_absent("k", "third").unwrap());
    assert_eq!(db.get("k").unwrap().as_deref(), Some(&b"third"[..]));
}

#[test]
fn values_are_stored_byte_for_byte() {
    let (dir, env, db) = scratch();

    let value: &[u8] = b"\x00\xff\x80binary\x00\n\r\xc3\x28value\x00";
    db.put(b"weird\x00key", value).unwrap();
    assert_eq!(db.get(b"weird\x00key").unwrap().as_deref(), Some(value));

    // An empty value is a value, not an absence.
    db.put("empty", "").unwrap();
    assert_eq!(db.get("empty").unwrap().as_deref(), Some(&b""[..]));
    assert!(db.contains_key("empty").unwrap());
    db.with_value("empty", |v| assert_eq!(v, Some(&b""[..])))
        .unwrap();

    // Nothing is wrapped around a stored value on disk.
    env.sync(true).unwrap();
    let raw = std::fs::read(dir.path().join("env").join("data.mdb")).unwrap();
    assert!(raw.windows(value.len()).any(|w| w == value));
}

#[test]
fn a_value_larger_than_a_page_round_trips() {
    // Overflow pages are a different LMDB path; the wrapper must copy the
    // whole thing out either way.
    let (_dir, _env, db) = scratch();
    let big: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    db.put("big", &big).unwrap();
    assert_eq!(db.get("big").unwrap().as_deref(), Some(&big[..]));
    db.with_value("big", |v| assert_eq!(v, Some(&big[..])))
        .unwrap();

    let mut buf = Vec::new();
    assert!(db.get_into("big", &mut buf).unwrap());
    assert_eq!(buf, big);
}

#[test]
fn get_into_reuses_the_callers_buffer() {
    let (_dir, _env, db) = scratch();
    db.put("k", "a longer value than the next one").unwrap();

    let mut buf = Vec::new();
    assert!(db.get_into("k", &mut buf).unwrap());
    assert_eq!(buf, b"a longer value than the next one");
    let capacity = buf.capacity();

    db.put("k", "short").unwrap();
    assert!(db.get_into("k", &mut buf).unwrap());
    assert_eq!(buf, b"short");
    assert_eq!(buf.capacity(), capacity, "the allocation was reused");

    // A miss empties the buffer and reports false rather than erroring.
    assert!(!db.get_into("absent", &mut buf).unwrap());
    assert!(buf.is_empty());
}

#[test]
fn with_value_borrows_and_returns() {
    let (_dir, _env, db) = scratch();
    db.put("k", "12345").unwrap();

    assert_eq!(db.with_value("k", |v| v.map(<[u8]>::len)).unwrap(), Some(5));
    assert!(db.with_value("absent", |v| v.is_none()).unwrap());
    // The closure's return value passes through unchanged.
    let owned: Option<String> = db
        .with_value("k", |v| v.map(|b| String::from_utf8_lossy(b).into_owned()))
        .unwrap();
    assert_eq!(owned.as_deref(), Some("12345"));
}

#[test]
fn clear_empties_but_keeps_the_database() {
    let (_dir, _env, db) = scratch();
    for i in 0..10u8 {
        db.put([i], "v").unwrap();
    }
    assert_eq!(db.len().unwrap(), 10);

    db.clear().unwrap();
    assert_eq!(db.len().unwrap(), 0);
    assert!(db.is_empty().unwrap());
    assert_eq!(scanned_keys(&db), Vec::<Vec<u8>>::new());

    db.put("after", "clear").unwrap();
    assert_eq!(db.len().unwrap(), 1);
}

#[test]
fn len_tracks_writes_and_deletes() {
    let (_dir, _env, db) = scratch();
    assert_eq!(db.len().unwrap(), 0);
    assert!(db.is_empty().unwrap());

    db.put("a", "1").unwrap();
    db.put("b", "2").unwrap();
    assert_eq!(db.len().unwrap(), 2);
    assert!(!db.is_empty().unwrap());

    db.put("a", "overwritten").unwrap();
    assert_eq!(db.len().unwrap(), 2, "an overwrite is not an insert");

    db.del("a").unwrap();
    assert_eq!(db.len().unwrap(), 1);
}

// --- scanning ------------------------------------------------------------

/// A database holding `aa ab ac ba bb ca`, each key its own value.
fn ordered() -> (tempfile::TempDir, Env, Db) {
    let (dir, env, db) = scratch();
    for key in ["ac", "bb", "aa", "ca", "ab", "ba"] {
        db.put(key, key).unwrap();
    }
    (dir, env, db)
}

#[test]
fn scan_visits_every_entry_in_key_order() {
    let (_dir, _env, db) = ordered();
    let mut seen = Vec::new();
    let stopped = db
        .scan(|k, v| {
            assert_eq!(k, v);
            seen.push(String::from_utf8_lossy(k).into_owned());
            ControlFlow::<()>::Continue(())
        })
        .unwrap();
    assert_eq!(stopped, None, "a full walk breaks nowhere");
    assert_eq!(seen, ["aa", "ab", "ac", "ba", "bb", "ca"]);
}

#[test]
fn scan_over_an_empty_database_visits_nothing() {
    let (_dir, _env, db) = scratch();
    let mut called = false;
    let stopped = db
        .scan(|_, _| {
            called = true;
            ControlFlow::Break(())
        })
        .unwrap();
    assert!(!called);
    assert_eq!(stopped, None);
}

#[test]
fn scan_can_break_early_with_a_value() {
    let (_dir, _env, db) = ordered();
    let mut visited = 0;
    let found = db
        .scan(|k, _| {
            visited += 1;
            if k == b"ac" {
                ControlFlow::Break(k.to_vec())
            } else {
                ControlFlow::Continue(())
            }
        })
        .unwrap();
    assert_eq!(found.as_deref(), Some(&b"ac"[..]));
    assert_eq!(visited, 3, "stopped at the match, not after the whole scan");
}

#[test]
fn scan_from_starts_at_the_first_key_at_or_after_the_bound() {
    let (_dir, _env, db) = ordered();

    let from = |start: &str| {
        let mut seen = Vec::new();
        db.scan_from(start, |k, _| {
            seen.push(String::from_utf8_lossy(k).into_owned());
            ControlFlow::<()>::Continue(())
        })
        .unwrap();
        seen
    };

    assert_eq!(from("ba"), ["ba", "bb", "ca"], "exact match starts there");
    assert_eq!(from("b"), ["ba", "bb", "ca"], "no match starts at the next");
    assert_eq!(from("aa"), ["aa", "ab", "ac", "ba", "bb", "ca"]);
    assert_eq!(
        from("z"),
        Vec::<String>::new(),
        "past the end yields nothing"
    );
    assert_eq!(
        from(""),
        ["aa", "ab", "ac", "ba", "bb", "ca"],
        "empty is all"
    );
}

#[test]
fn scan_prefix_stops_at_the_end_of_the_prefix() {
    let (_dir, _env, db) = ordered();

    let prefixed = |prefix: &str| {
        let mut seen = Vec::new();
        db.scan_prefix(prefix, |k, _| {
            seen.push(String::from_utf8_lossy(k).into_owned());
            ControlFlow::<()>::Continue(())
        })
        .unwrap();
        seen
    };

    assert_eq!(prefixed("a"), ["aa", "ab", "ac"]);
    assert_eq!(prefixed("b"), ["ba", "bb"]);
    assert_eq!(prefixed("c"), ["ca"]);
    assert_eq!(prefixed("aa"), ["aa"], "a prefix may be a whole key");
    assert_eq!(
        prefixed("d"),
        Vec::<String>::new(),
        "no match yields nothing"
    );
    assert_eq!(prefixed("aaa"), Vec::<String>::new(), "longer than any key");
    assert_eq!(prefixed(""), ["aa", "ab", "ac", "ba", "bb", "ca"]);
}

#[test]
fn scan_prefix_can_break_early() {
    let (_dir, _env, db) = ordered();
    let found = db
        .scan_prefix("a", |k, _| {
            if k == b"ab" {
                ControlFlow::Break(k.to_vec())
            } else {
                ControlFlow::Continue(())
            }
        })
        .unwrap();
    assert_eq!(found.as_deref(), Some(&b"ab"[..]));
}

#[test]
fn scans_handle_binary_prefixes() {
    // A prefix ending in 0xff has no "next key" to compare against, so the
    // bound has to come from the prefix check rather than arithmetic.
    let (_dir, _env, db) = scratch();
    for key in [
        &b"\xff\x00"[..],
        &b"\xff\xff"[..],
        &b"\xff\xff\x00"[..],
        &b"\xff\xff\xff"[..],
    ] {
        db.put(key, "v").unwrap();
    }
    let mut seen = Vec::new();
    db.scan_prefix(b"\xff\xff", |k, _| {
        seen.push(k.to_vec());
        ControlFlow::<()>::Continue(())
    })
    .unwrap();
    assert_eq!(
        seen,
        [
            b"\xff\xff".to_vec(),
            b"\xff\xff\x00".to_vec(),
            b"\xff\xff\xff".to_vec()
        ]
    );
}

// --- iteration -----------------------------------------------------------

#[test]
fn iter_yields_every_entry_in_key_order() {
    let (_dir, _env, db) = ordered();
    let all = drain(db.iter().unwrap());
    let keys: Vec<&[u8]> = all.iter().map(|(k, _)| &k[..]).collect();
    assert_eq!(keys, [b"aa", b"ab", b"ac", b"ba", b"bb", b"ca"]);
    assert!(all.iter().all(|(k, v)| k == v));
}

#[test]
fn iter_over_an_empty_database_yields_nothing() {
    let (_dir, _env, db) = scratch();
    assert_eq!(drain(db.iter().unwrap()), Vec::new());
}

#[test]
fn iter_from_and_iter_prefix_bound_the_same_way_as_scan() {
    let (_dir, _env, db) = ordered();

    let keys = |iter: Iter| -> Vec<String> {
        drain(iter)
            .into_iter()
            .map(|(k, _)| String::from_utf8(k).unwrap())
            .collect()
    };

    assert_eq!(keys(db.iter_from("ba").unwrap()), ["ba", "bb", "ca"]);
    assert_eq!(keys(db.iter_from("b").unwrap()), ["ba", "bb", "ca"]);
    assert_eq!(keys(db.iter_from("z").unwrap()), Vec::<String>::new());
    assert_eq!(keys(db.iter_prefix("a").unwrap()), ["aa", "ab", "ac"]);
    assert_eq!(keys(db.iter_prefix("d").unwrap()), Vec::<String>::new());
    assert_eq!(keys(db.iter_prefix("").unwrap()).len(), 6);
}

#[test]
fn iter_is_fused_and_composes() {
    let (_dir, _env, db) = ordered();

    let mut it = db.iter().unwrap();
    assert!(it.next().is_some());
    let rest = it.count();
    assert_eq!(rest, 5);

    // Exhausted iterators keep returning None.
    {
        let mut done = db.iter_prefix("zzz").unwrap();
        assert!(done.next().is_none());
        assert!(done.next().is_none());
    }

    // Ordinary Iterator adapters work.
    let bs: Vec<Vec<u8>> = db
        .iter()
        .unwrap()
        .filter_map(Result::ok)
        .map(|(k, _)| k)
        .filter(|k| k.starts_with(b"b"))
        .collect();
    assert_eq!(bs, [b"ba".to_vec(), b"bb".to_vec()]);

    assert!(format!("{:?}", db.iter().unwrap()).contains("Iter"));
    assert_eq!(db.iter().unwrap().db().name(), Some("state"));
}

#[test]
fn an_iterator_reads_a_snapshot() {
    // It holds a read transaction, so writes committed after it was created
    // are invisible to it, and it must not observe a torn view. The writes go
    // on another thread because this one's transaction slot is taken.
    let (_dir, _env, db) = ordered();
    let iter = db.iter().unwrap();

    let writer = db.clone();
    std::thread::spawn(move || {
        writer
            .put("zz", "added after the iterator started")
            .unwrap();
        writer.del("aa").unwrap();
    })
    .join()
    .unwrap();

    let keys: Vec<Vec<u8>> = drain(iter).into_iter().map(|(k, _)| k).collect();
    assert_eq!(
        keys,
        [b"aa", b"ab", b"ac", b"ba", b"bb", b"ca"].map(Vec::from)
    );

    // A fresh iterator sees the new state.
    assert_eq!(drain(db.iter().unwrap()).len(), 6);
}

#[test]
fn an_iterator_keeps_its_environment_alive() {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(dir.path().join("env")).unwrap();
    let db = Db::create(&env, "state").unwrap();
    db.put("k", "v").unwrap();

    let iter = db.iter().unwrap();
    drop(db);
    drop(env);
    // The iterator holds the last references to the database and environment;
    // draining it after both are gone must not touch freed handles.
    assert_eq!(drain(iter), [(b"k".to_vec(), b"v".to_vec())]);
}

#[test]
fn iterators_are_reusable_one_at_a_time() {
    // Sequentially is fine: each drops before the next begins, releasing this
    // thread's transaction slot and its reader lock-table entry.
    let (_dir, _env, db) = ordered();
    for _ in 0..128 {
        assert_eq!(drain(db.iter().unwrap()).len(), 6);
    }
}

// --- one transaction per thread ------------------------------------------
//
// LMDB allows a thread one transaction on an environment at a time. Left to
// LMDB, breaking that is MDB_BAD_RSLOT for a read and a self-deadlock on the
// non-recursive writer mutex for a write, so the crate refuses up front.

#[test]
fn a_second_iterator_on_one_thread_is_refused() {
    let (_dir, _env, db) = ordered();
    let first = db.iter().unwrap();
    assert_eq!(db.iter().unwrap_err(), Error::Os(libc::EDEADLK));
    assert_eq!(db.iter_prefix("a").unwrap_err(), Error::Os(libc::EDEADLK));

    // Dropping it hands the slot back.
    drop(first);
    assert_eq!(drain(db.iter().unwrap()).len(), 6);
}

#[test]
fn operations_are_refused_while_an_iterator_is_alive() {
    let (_dir, _env, db) = ordered();
    let iter = db.iter().unwrap();

    let deadlock = Error::Os(libc::EDEADLK);
    assert_eq!(db.get("aa").unwrap_err(), deadlock);
    assert_eq!(db.put("k", "v").unwrap_err(), deadlock);
    assert_eq!(db.del("aa").unwrap_err(), deadlock);
    assert_eq!(db.len().unwrap_err(), deadlock);
    assert_eq!(db.clear().unwrap_err(), deadlock);
    assert_eq!(db.contains_key("aa").unwrap_err(), deadlock);
    assert_eq!(db.put_if_absent("k", "v").unwrap_err(), deadlock);
    assert_eq!(
        db.scan(|_, _| ControlFlow::Break(())).unwrap_err(),
        deadlock
    );
    assert_eq!(db.with_value("aa", |_| ()).unwrap_err(), deadlock);

    drop(iter);
    db.put("k", "v").unwrap();
    assert_eq!(db.len().unwrap(), 7);
}

#[test]
fn operations_are_refused_inside_a_scan_callback() {
    let (_dir, _env, db) = ordered();
    let deadlock = Error::Os(libc::EDEADLK);

    let mut seen = Vec::new();
    db.scan(|k, _| {
        seen.push(k.to_vec());
        assert_eq!(db.get("aa").unwrap_err(), deadlock);
        assert_eq!(db.put("k", "v").unwrap_err(), deadlock);
        assert_eq!(db.iter().unwrap_err(), deadlock);
        ControlFlow::Break(())
    })
    .unwrap();
    assert_eq!(seen.len(), 1, "the callback still ran normally");

    // The slot is released when the scan returns, however it ended.
    db.put("k", "v").unwrap();
    assert!(db.with_value("k", |v| v.is_some()).unwrap());
}

#[test]
fn the_slot_is_released_when_a_callback_panics() {
    let (_dir, _env, db) = ordered();
    let caught = std::panic::catch_unwind({
        let db = db.clone();
        move || {
            db.scan(|_, _| -> ControlFlow<()> { panic!("from the callback") })
        }
    });
    assert!(caught.is_err(), "the panic propagated");

    // Unwinding drops the guard, so the thread is usable again.
    db.put("after", "panic").unwrap();
    assert_eq!(db.len().unwrap(), 7);
}

#[test]
fn a_second_environment_is_unaffected() {
    // The limit is per environment: separate reader tables, separate writer
    // mutexes.
    let (_dir_a, _env_a, a) = ordered();
    let (_dir_b, _env_b, b) = scratch();

    let iter = a.iter().unwrap();
    b.put("k", "v").unwrap();
    assert_eq!(b.get("k").unwrap().as_deref(), Some(&b"v"[..]));
    let inner = b.iter().unwrap();
    assert_eq!(drain(inner).len(), 1);
    assert_eq!(drain(iter).len(), 6);
}

#[test]
fn other_threads_are_unaffected() {
    let (_dir, _env, db) = ordered();
    let iter = db.iter().unwrap();

    // This thread's slot is taken, but every other thread has its own. Each
    // writes its own key, so the database grows as they go.
    let handles: Vec<_> = (0..4u8)
        .map(|t| {
            let db = db.clone();
            std::thread::spawn(move || {
                assert!(drain(db.iter().unwrap()).len() >= 6);
                db.put([b'z', t], "v").unwrap();
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(drain(iter).len(), 6, "this thread's snapshot is unchanged");
    assert_eq!(db.len().unwrap(), 10, "...but the writes all landed");
}

// --- errors --------------------------------------------------------------

#[test]
fn a_zero_length_key_is_rejected() {
    let (_dir, _env, db) = scratch();
    assert_eq!(
        db.put("", "v").unwrap_err(),
        Error::Mdb(MdbCode::BadValsize)
    );
    assert_eq!(db.get("").unwrap_err(), Error::Mdb(MdbCode::BadValsize));
    assert_eq!(db.del("").unwrap_err(), Error::Mdb(MdbCode::BadValsize));
    assert_eq!(
        db.contains_key("").unwrap_err(),
        Error::Mdb(MdbCode::BadValsize)
    );
}

#[test]
fn an_oversized_key_is_rejected() {
    // LMDB's default maximum key is 511 bytes.
    let (_dir, _env, db) = scratch();
    db.put(vec![b'k'; 511], "v").unwrap();
    assert_eq!(
        db.put(vec![b'k'; 512], "v").unwrap_err(),
        Error::Mdb(MdbCode::BadValsize)
    );
}

#[test]
fn exceeding_map_size_reports_map_full() {
    let (_dir, env) = scratch_env(EnvOptions {
        map_size: 64 * 1024,
        ..SMALL
    });
    let db = Db::create(&env, "state").unwrap();

    let value = vec![0xabu8; 4096];
    let mut err = None;
    for i in 0..64u32 {
        if let Err(e) = db.put(i.to_be_bytes(), &value) {
            err = Some(e);
            break;
        }
    }
    assert_eq!(
        err.expect("64 KiB cannot hold 256 KiB"),
        Error::Mdb(MdbCode::MapFull)
    );
    // The environment survives: earlier writes are intact and readable.
    assert_eq!(
        db.get(0u32.to_be_bytes()).unwrap().as_deref(),
        Some(&value[..])
    );
    assert!(db.len().unwrap() > 0);
}

#[test]
fn a_failed_write_leaves_no_transaction_behind() {
    // A write transaction holds the environment's single writer lock until its
    // guard drops, on the failure path as much as the success path. Repeated
    // failures must therefore leave the next write able to proceed.
    let (_dir, _env, db) = scratch();
    for _ in 0..64 {
        assert!(db.put("", "v").is_err());
        assert!(db.del("").is_err());
    }
    db.put("k", "v").unwrap();
    assert_eq!(db.get("k").unwrap().as_deref(), Some(&b"v"[..]));
}

#[test]
fn a_failed_read_leaves_no_reader_slot_behind() {
    // A read claims this thread's transaction slot and a reader lock-table
    // entry, both released when its guard drops — again on the failure path.
    // Otherwise the very next call would be refused with EDEADLK.
    let (_dir, _env, db) = scratch();
    for _ in 0..512 {
        assert!(db.get("").is_err());
    }
    assert!(db.get("absent").unwrap().is_none());
}

// --- durability and concurrency -----------------------------------------

#[test]
fn data_survives_closing_and_reopening_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("env");

    {
        let env = Env::open_with(&path, &SMALL).unwrap();
        let db = Db::create(&env, "state").unwrap();
        db.put("persisted", "yes").unwrap();
        // Dropping both closes the environment: the pool refcount reaches
        // zero, so the reopen below is genuine and not a cache hit.
    }

    let env = Env::open_with(&path, &SMALL).unwrap();
    let db = Db::open(&env, "state").unwrap();
    assert_eq!(db.get("persisted").unwrap().as_deref(), Some(&b"yes"[..]));
}

#[test]
fn concurrent_readers_and_writers_agree() {
    let (_dir, env) = scratch_env(EnvOptions {
        map_size: 16 << 20,
        ..SMALL
    });
    let db = Arc::new(Db::create(&env, "state").unwrap());

    let mut handles = Vec::new();
    for w in 0..4u32 {
        let db = Arc::clone(&db);
        handles.push(std::thread::spawn(move || {
            for i in 0..250u32 {
                let key = (w * 1000 + i).to_be_bytes();
                db.put(key, key).unwrap();
            }
        }));
    }
    for r in 0..4 {
        let db = Arc::clone(&db);
        handles.push(std::thread::spawn(move || {
            for _ in 0..50 {
                // A read transaction is a snapshot, so whatever a scan sees
                // must be self-consistent: no torn pairs, no partial writes.
                if r % 2 == 0 {
                    db.scan(|k, v| {
                        assert_eq!(k, v);
                        ControlFlow::<()>::Continue(())
                    })
                    .unwrap();
                } else {
                    for entry in db.iter().unwrap() {
                        let (k, v) = entry.unwrap();
                        assert_eq!(k, v);
                    }
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(db.len().unwrap(), 1000);
    for w in 0..4u32 {
        for i in [0u32, 249] {
            let key = (w * 1000 + i).to_be_bytes();
            assert_eq!(db.get(key).unwrap().as_deref(), Some(&key[..]));
        }
    }
}

#[test]
fn databases_opened_concurrently_on_one_environment_are_consistent() {
    // `Db::open` runs transactions under a per-environment lock; racing opens
    // must all succeed and land on the same handle.
    let (_dir, env) = scratch_env(SMALL);
    Db::create(&env, "state").unwrap();

    let mut handles = Vec::new();
    for t in 0..8u32 {
        let env = env.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..25u32 {
                let db = Db::create(&env, "state").unwrap();
                db.put((t * 100 + i).to_be_bytes(), "v").unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(Db::open(&env, "state").unwrap().len().unwrap(), 200);
}
