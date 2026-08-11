//! Behavioral tests for `truenas_mdb` against a real LMDB environment.
//!
//! These need nothing but a writable temp directory and the linked
//! `liblmdb` — no privilege, no fixture, no other process. The
//! cross-implementation half lives in `python_interop.rs`.

use std::ops::ControlFlow;
use std::sync::Arc;

use truenas_mdb::{Db, Env, EnvOptions, Error, MdbCode, PutFlags};

/// A fresh environment in its own temp directory. The `TempDir` is returned
/// alongside because dropping it removes the directory.
fn scratch(opts: EnvOptions) -> (tempfile::TempDir, Env) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::open(&dir.path().join("env"), &opts).unwrap();
    (dir, env)
}

fn small() -> EnvOptions {
    EnvOptions {
        map_size: 1 << 20,
        max_dbs: 8,
        ..Default::default()
    }
}

#[test]
fn get_put_del_and_clear() {
    let (_dir, env) = scratch(small());
    let db = Db::open(&env, Some("state"), true).unwrap();

    assert_eq!(db.get(b"a").unwrap(), None);
    assert!(!db.contains_key(b"a").unwrap());
    assert!(
        !db.del(b"a").unwrap(),
        "deleting a missing key is not an error"
    );

    db.put(b"a", b"one", PutFlags::empty()).unwrap();
    assert_eq!(db.get(b"a").unwrap().as_deref(), Some(&b"one"[..]));
    assert!(db.contains_key(b"a").unwrap());

    db.put(b"a", b"two", PutFlags::empty()).unwrap();
    assert_eq!(db.get(b"a").unwrap().as_deref(), Some(&b"two"[..]));

    assert!(db.del(b"a").unwrap());
    assert_eq!(db.get(b"a").unwrap(), None);

    for i in 0..10u8 {
        db.put(&[i], b"v", PutFlags::empty()).unwrap();
    }
    db.clear().unwrap();
    assert_eq!(count(&db), 0);
    // `clear` empties the database but keeps it usable.
    db.put(b"after", b"clear", PutFlags::empty()).unwrap();
    assert_eq!(count(&db), 1);
}

#[test]
fn no_overwrite_reports_key_exist() {
    let (_dir, env) = scratch(small());
    let db = Db::open(&env, Some("state"), true).unwrap();

    db.put(b"k", b"first", PutFlags::NO_OVERWRITE).unwrap();
    let err = db
        .put(b"k", b"second", PutFlags::NO_OVERWRITE)
        .expect_err("the key is already there");
    assert_eq!(err, Error::Mdb(MdbCode::KeyExist));
    assert_eq!(err.as_mdb(), Some(MdbCode::KeyExist));
    // The failed put changed nothing.
    assert_eq!(db.get(b"k").unwrap().as_deref(), Some(&b"first"[..]));
}

#[test]
fn values_are_stored_byte_for_byte() {
    // The crate's central promise: no envelope, no header, no encoding. A
    // value with embedded NULs and non-UTF-8 bytes must come back identical,
    // and must appear verbatim in the file another process will read.
    let (dir, env) = scratch(small());
    let db = Db::open(&env, Some("state"), true).unwrap();

    let value: &[u8] = b"\x00\xff\x80binary\x00\n\r\xc3\x28value\x00";
    db.put(b"weird\x00key", value, PutFlags::empty()).unwrap();
    assert_eq!(db.get(b"weird\x00key").unwrap().as_deref(), Some(value));

    // An empty value is a value, not an absence.
    db.put(b"empty", b"", PutFlags::empty()).unwrap();
    assert_eq!(db.get(b"empty").unwrap().as_deref(), Some(&b""[..]));
    assert!(db.contains_key(b"empty").unwrap());

    env.sync(true).unwrap();
    let raw = std::fs::read(dir.path().join("env").join("data.mdb")).unwrap();
    assert!(
        raw.windows(value.len()).any(|w| w == value),
        "the value must sit in data.mdb verbatim, with nothing wrapped \
         around it"
    );
}

#[test]
fn get_into_reuses_the_callers_buffer() {
    let (_dir, env) = scratch(small());
    let db = Db::open(&env, Some("state"), true).unwrap();
    db.put(b"k", b"a longer value than the next one", PutFlags::empty())
        .unwrap();

    let mut buf = Vec::new();
    assert!(db.get_into(b"k", &mut buf).unwrap());
    assert_eq!(buf, b"a longer value than the next one");
    let capacity = buf.capacity();

    db.put(b"k", b"short", PutFlags::empty()).unwrap();
    assert!(db.get_into(b"k", &mut buf).unwrap());
    assert_eq!(buf, b"short");
    assert_eq!(buf.capacity(), capacity, "the allocation was reused");

    // A miss empties the buffer and reports false rather than erroring.
    assert!(!db.get_into(b"absent", &mut buf).unwrap());
    assert!(buf.is_empty());
}

#[test]
fn traverse_visits_every_entry_in_key_order() {
    let (_dir, env) = scratch(small());
    let db = Db::open(&env, Some("state"), true).unwrap();
    // Inserted out of order; LMDB stores keys sorted bytewise.
    for key in [b"c", b"a", b"d", b"b"] {
        db.put(key, key, PutFlags::empty()).unwrap();
    }

    let mut seen = Vec::new();
    let stopped = db
        .traverse(|k, v| {
            assert_eq!(k, v);
            seen.push(k.to_vec());
            ControlFlow::<()>::Continue(())
        })
        .unwrap();
    assert_eq!(stopped, None, "a full walk breaks nowhere");
    assert_eq!(seen, [b"a", b"b", b"c", b"d"].map(|k| k.to_vec()));
}

#[test]
fn traverse_can_break_early_with_a_value() {
    let (_dir, env) = scratch(small());
    let db = Db::open(&env, Some("state"), true).unwrap();
    for i in 0..100u32 {
        db.put(&i.to_be_bytes(), b"v", PutFlags::empty()).unwrap();
    }

    let mut visited = 0;
    let found = db
        .traverse(|k, _| {
            visited += 1;
            if k == 5u32.to_be_bytes() {
                ControlFlow::Break(k.to_vec())
            } else {
                ControlFlow::Continue(())
            }
        })
        .unwrap();
    assert_eq!(found.as_deref(), Some(&5u32.to_be_bytes()[..]));
    assert_eq!(visited, 6, "stopped at the match, not after the whole scan");
}

#[test]
fn named_and_unnamed_databases_are_separate_namespaces() {
    let (_dir, env) = scratch(small());
    let main = Db::open(&env, None, false).unwrap();
    let named = Db::open(&env, Some("state"), true).unwrap();

    main.put(b"k", b"from-main", PutFlags::empty()).unwrap();
    named.put(b"k", b"from-named", PutFlags::empty()).unwrap();

    assert_eq!(main.get(b"k").unwrap().as_deref(), Some(&b"from-main"[..]));
    assert_eq!(
        named.get(b"k").unwrap().as_deref(),
        Some(&b"from-named"[..])
    );

    // Clearing one leaves the other alone.
    named.clear().unwrap();
    assert_eq!(named.get(b"k").unwrap(), None);
    assert_eq!(main.get(b"k").unwrap().as_deref(), Some(&b"from-main"[..]));
}

#[test]
fn one_environment_holds_the_five_databases_zfstierd_uses() {
    // The shape of truenas_zfsrewrited's per-dataset state environment:
    // five named databases opened from one env (zw_module.h:22-28).
    let (_dir, env) = scratch(small());
    let names = ["state", "error", "stats", "stack", "failures"];
    let dbs: Vec<Db> = names
        .iter()
        .map(|n| Db::open(&env, Some(n), true).unwrap())
        .collect();

    for (db, name) in dbs.iter().zip(names) {
        db.put(b"key", name.as_bytes(), PutFlags::empty()).unwrap();
    }
    for (db, name) in dbs.iter().zip(names) {
        assert_eq!(db.get(b"key").unwrap().as_deref(), Some(name.as_bytes()));
    }

    // Reopening a database that already exists yields the same contents (and
    // takes the read-only lookup path).
    let again = Db::open(&env, Some("stats"), false).unwrap();
    assert_eq!(again.get(b"key").unwrap().as_deref(), Some(&b"stats"[..]));
}

#[test]
fn exceeding_max_dbs_reports_dbs_full() {
    let (_dir, env) = scratch(EnvOptions {
        map_size: 1 << 20,
        max_dbs: 2,
        ..Default::default()
    });
    Db::open(&env, Some("one"), true).unwrap();
    Db::open(&env, Some("two"), true).unwrap();
    assert_eq!(
        Db::open(&env, Some("three"), true).unwrap_err(),
        Error::Mdb(MdbCode::DbsFull)
    );
}

#[test]
fn exceeding_map_size_reports_map_full() {
    // 64 KiB of map, then write past it. This is the error a caller is most
    // likely to hit in production, and the one whose fix (raise map_size) is
    // in the message.
    let (_dir, env) = scratch(EnvOptions {
        map_size: 64 * 1024,
        max_dbs: 2,
        ..Default::default()
    });
    let db = Db::open(&env, Some("state"), true).unwrap();

    let value = vec![0xabu8; 4096];
    let mut err = None;
    for i in 0..64u32 {
        if let Err(e) = db.put(&i.to_be_bytes(), &value, PutFlags::empty()) {
            err = Some(e);
            break;
        }
    }
    assert_eq!(
        err.expect("64 KiB cannot hold 256 KiB"),
        Error::Mdb(MdbCode::MapFull)
    );
    // The environment survives it: earlier writes are intact and readable.
    assert_eq!(
        db.get(&0u32.to_be_bytes()).unwrap().as_deref(),
        Some(&value[..])
    );
}

#[test]
fn a_zero_length_key_is_rejected() {
    let (_dir, env) = scratch(small());
    let db = Db::open(&env, Some("state"), true).unwrap();
    assert_eq!(
        db.put(b"", b"v", PutFlags::empty()).unwrap_err(),
        Error::Mdb(MdbCode::BadValsize)
    );
}

#[test]
fn data_survives_closing_and_reopening_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("env");

    {
        let env = Env::open(&path, &small()).unwrap();
        let db = Db::open(&env, Some("state"), true).unwrap();
        db.put(b"persisted", b"yes", PutFlags::empty()).unwrap();
        // Dropping both closes the environment for real: the pool refcount
        // reaches zero, so this is a genuine reopen below, not a cache hit.
    }

    let env = Env::open(&path, &small()).unwrap();
    let db = Db::open(&env, Some("state"), false).unwrap();
    assert_eq!(db.get(b"persisted").unwrap().as_deref(), Some(&b"yes"[..]));
}

#[test]
fn a_database_handle_shares_the_environment_with_its_openers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("env");
    let env = Env::open(&path, &small()).unwrap();
    let db = Db::open(&env, Some("state"), true).unwrap();

    assert_eq!(db.env().path(), env.path());
    // The Db holds its own handle on the environment, so dropping the caller's
    // does not close it underneath.
    drop(env);
    db.put(b"still", b"open", PutFlags::empty()).unwrap();
    assert_eq!(db.get(b"still").unwrap().as_deref(), Some(&b"open"[..]));
}

#[test]
fn concurrent_readers_and_writers_agree() {
    // LMDB serializes writers itself and readers never block, so a shared
    // `Db` across threads must just work. Four writers with disjoint key
    // ranges, four readers scanning throughout.
    let (_dir, env) = scratch(EnvOptions {
        map_size: 16 << 20,
        max_dbs: 4,
        ..Default::default()
    });
    let db = Arc::new(Db::open(&env, Some("state"), true).unwrap());

    let mut handles = Vec::new();
    for w in 0..4u32 {
        let db = Arc::clone(&db);
        handles.push(std::thread::spawn(move || {
            for i in 0..250u32 {
                let key = (w * 1000 + i).to_be_bytes();
                db.put(&key, &key, PutFlags::empty()).unwrap();
            }
        }));
    }
    for _ in 0..4 {
        let db = Arc::clone(&db);
        handles.push(std::thread::spawn(move || {
            for _ in 0..50 {
                // Whatever a scan sees must be self-consistent: a read
                // transaction is a snapshot, so no torn key/value pairs.
                db.traverse(|k, v| {
                    assert_eq!(k, v);
                    ControlFlow::<()>::Continue(())
                })
                .unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(count(&db), 1000);
    for w in 0..4u32 {
        for i in [0u32, 249] {
            let key = (w * 1000 + i).to_be_bytes();
            assert_eq!(db.get(&key).unwrap().as_deref(), Some(&key[..]));
        }
    }
}

/// Entries in `db`, by walking it.
fn count(db: &Db) -> usize {
    let mut n = 0;
    db.traverse(|_, _| {
        n += 1;
        ControlFlow::<()>::Continue(())
    })
    .unwrap();
    n
}
