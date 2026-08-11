//! Cross-implementation tests: this crate and Python's `lmdb` module over one
//! shared environment.
//!
//! This is the suite that justifies linking the system `liblmdb` instead of
//! vendoring one. `truenas_zfsrewrited`'s C extension is not available here (or
//! in CI), so Debian's `python3-lmdb` — which links the same `liblmdb0` —
//! stands in for it, exercising the same on-disk contract: the directory
//! layout, named sub-databases, byte-exact values, and the shared `map_size`.
//!
//! Skips when `python3` or its `lmdb` module is missing. Set
//! `TRUENAS_MDB_REQUIRE_PYTHON=1` (as CI does) to turn that skip into a
//! failure, so the suite cannot go green by quietly doing nothing.

use std::ops::ControlFlow;
use std::path::Path;
use std::process::Command;

use truenas_mdb::{Db, Env, EnvOptions, PutFlags};

/// Map size used on both sides. Well above py-lmdb's 10 MiB default so the
/// number has to be passed across deliberately rather than coinciding.
const MAP_SIZE: usize = 64 * 1024 * 1024;

/// Whether a missing `python3-lmdb` should fail rather than skip.
fn python_required() -> bool {
    std::env::var_os("TRUENAS_MDB_REQUIRE_PYTHON").is_some_and(|v| v == "1")
}

/// `Some(())` when the suite can run; `None` to skip (unless required).
fn python_lmdb() -> Option<()> {
    let ok = Command::new("python3")
        .args(["-c", "import lmdb"])
        .status()
        .is_ok_and(|s| s.success());
    if ok {
        return Some(());
    }
    assert!(
        !python_required(),
        "TRUENAS_MDB_REQUIRE_PYTHON=1 but `python3 -c 'import lmdb'` failed \
         (install python3-lmdb; note that `pip install lmdb` bundles its own \
         LMDB and is not a substitute)"
    );
    None
}

/// Run a Python snippet, returning its stdout. A failure prints the script and
/// the interpreter's stderr, because a traceback is the whole diagnostic here.
fn py(script: &str) -> String {
    let out = Command::new("python3")
        .arg("-c")
        .arg(script)
        .output()
        .expect("python3 must be spawnable");
    assert!(
        out.status.success(),
        "python failed ({}):\n--- script ---\n{script}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The preamble every snippet shares: open the same environment the Rust side
/// does, with the flags the interop contract requires.
fn preamble(path: &Path, readonly: bool) -> String {
    format!(
        "import lmdb\n\
         env = lmdb.open({path:?}, subdir=True, max_dbs=8, \
         map_size={MAP_SIZE}, readonly={readonly}, writemap=False, \
         mode=0o600)\n",
        path = path.to_str().unwrap(),
        readonly = if readonly { "True" } else { "False" },
    )
}

fn options() -> EnvOptions {
    EnvOptions {
        map_size: MAP_SIZE,
        max_dbs: 8,
        ..Default::default()
    }
}

#[test]
fn both_sides_link_the_same_liblmdb() {
    let Some(()) = python_lmdb() else { return };
    let ours = truenas_mdb::version();
    let theirs = py("import lmdb; print('%d %d %d' % lmdb.version())");
    let theirs: Vec<i32> = theirs
        .split_whitespace()
        .map(|n| n.parse().unwrap())
        .collect();

    assert_eq!(
        vec![ours.0, ours.1, ours.2],
        theirs,
        "this crate and python3-lmdb report different LMDB versions, so they \
         are not the same library — two copies of LMDB over one environment \
         is exactly what not vendoring is meant to prevent"
    );
}

#[test]
fn rust_writes_and_python_reads() {
    let Some(()) = python_lmdb() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("env");

    {
        let env = Env::open(&path, &options()).unwrap();
        let state = Db::open(&env, Some("state"), true).unwrap();
        let main = Db::open(&env, None, false).unwrap();
        state.put(b"job", b"RUNNING", PutFlags::empty()).unwrap();
        state.put(b"count", b"42", PutFlags::empty()).unwrap();
        main.put(b"top", b"level", PutFlags::empty()).unwrap();
    } // closed, so Python is not racing a live writer

    let out = py(&format!(
        "{}\
         state = env.open_db(b'state', create=False)\n\
         with env.begin(db=state) as txn:\n\
         \x20   assert txn.get(b'job') == b'RUNNING', txn.get(b'job')\n\
         \x20   assert txn.get(b'count') == b'42'\n\
         \x20   assert txn.get(b'absent') is None\n\
         main = env.open_db(None, create=False)\n\
         with env.begin(db=main) as txn:\n\
         \x20   assert txn.get(b'top') == b'level'\n\
         \x20   assert txn.get(b'job') is None, 'namespaces must not bleed'\n\
         print('ok')\n",
        preamble(&path, true)
    ));
    assert_eq!(out.trim(), "ok");
}

#[test]
fn python_writes_and_rust_reads() {
    let Some(()) = python_lmdb() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("env");
    // LMDB requires the directory to exist; let Python create the environment
    // outright, so this direction proves we can adopt a database we did not
    // make.
    std::fs::create_dir_all(&path).unwrap();

    py(&format!(
        "{}\
         state = env.open_db(b'state')\n\
         with env.begin(db=state, write=True) as txn:\n\
         \x20   txn.put(b'from-python', b'hello')\n\
         \x20   txn.put(b'n', b'7')\n\
         env.sync(True)\n",
        preamble(&path, false)
    ));

    let env = Env::open(&path, &options()).unwrap();
    let state = Db::open(&env, Some("state"), false).unwrap();
    assert_eq!(
        state.get(b"from-python").unwrap().as_deref(),
        Some(&b"hello"[..])
    );
    assert_eq!(state.get(b"n").unwrap().as_deref(), Some(&b"7"[..]));

    let mut seen = Vec::new();
    state
        .traverse(|k, v| {
            seen.push((k.to_vec(), v.to_vec()));
            ControlFlow::<()>::Continue(())
        })
        .unwrap();
    assert_eq!(
        seen,
        [
            (b"from-python".to_vec(), b"hello".to_vec()),
            (b"n".to_vec(), b"7".to_vec()),
        ]
    );
}

#[test]
fn binary_keys_and_values_cross_unchanged() {
    let Some(()) = python_lmdb() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("env");

    // Embedded NULs, high bytes, and an invalid UTF-8 sequence — anything that
    // an envelope, a string conversion, or a C `strlen` would mangle.
    let key: &[u8] = b"k\x00ey\xff";
    let value: &[u8] = b"\x00\xff\x80\xc3\x28bin\x00ary\n\r\x7f";

    {
        let env = Env::open(&path, &options()).unwrap();
        let db = Db::open(&env, Some("bin"), true).unwrap();
        db.put(key, value, PutFlags::empty()).unwrap();
        db.put(b"empty", b"", PutFlags::empty()).unwrap();
    }

    // Round-trip through Python: read what Rust wrote, and write it back under
    // a second key so the Rust side can check the return leg too.
    let out = py(&format!(
        "{}\
         db = env.open_db(b'bin', create=False)\n\
         key = {key:?}\n\
         want = {value:?}\n\
         with env.begin(db=db, write=True) as txn:\n\
         \x20   got = txn.get(key)\n\
         \x20   assert got == want, (got, want)\n\
         \x20   assert txn.get(b'empty') == b'', repr(txn.get(b'empty'))\n\
         \x20   txn.put(b'roundtrip', got)\n\
         print('ok')\n",
        preamble(&path, false),
        key = PyBytes(key),
        value = PyBytes(value),
    ));
    assert_eq!(out.trim(), "ok");

    let env = Env::open(&path, &options()).unwrap();
    let db = Db::open(&env, Some("bin"), false).unwrap();
    assert_eq!(db.get(b"roundtrip").unwrap().as_deref(), Some(value));
}

#[test]
fn python_reads_a_database_past_its_own_default_map_size() {
    let Some(()) = python_lmdb() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("env");

    // 12 MiB, comfortably past py-lmdb's 10 MiB default map_size. Opening
    // still succeeds — LMDB raises an undersized map to at least the committed
    // data size — which is precisely why the hazard is a *write*-side one and
    // worth documenting rather than assuming.
    {
        let env = Env::open(&path, &options()).unwrap();
        let db = Db::open(&env, Some("bulk"), true).unwrap();
        let chunk = vec![0x5au8; 1024 * 1024];
        for i in 0..12u32 {
            db.put(&i.to_be_bytes(), &chunk, PutFlags::empty()).unwrap();
        }
    }

    let out = py(&format!(
        "import lmdb\n\
         # No map_size argument at all: py-lmdb's 10 MiB default.\n\
         env = lmdb.open({path:?}, subdir=True, max_dbs=8, readonly=True)\n\
         db = env.open_db(b'bulk', create=False)\n\
         with env.begin(db=db) as txn:\n\
         \x20   total = sum(len(v) for _, v in txn.cursor())\n\
         \x20   assert total == 12 * 1024 * 1024, total\n\
         \x20   assert txn.get((3).to_bytes(4, 'big')) == b'\\x5a' * 1024*1024\n\
         print('ok')\n",
        path = path.to_str().unwrap(),
    ));
    assert_eq!(out.trim(), "ok");
}

#[test]
fn a_live_rust_environment_sees_a_python_write() {
    let Some(()) = python_lmdb() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("env");

    // The realistic shape: a long-lived Rust process holding the environment
    // open while another process writes to it.
    let env = Env::open(&path, &options()).unwrap();
    let db = Db::open(&env, Some("state"), true).unwrap();
    db.put(b"before", b"1", PutFlags::empty()).unwrap();
    assert_eq!(db.get(b"later").unwrap(), None);

    py(&format!(
        "{}\
         state = env.open_db(b'state')\n\
         with env.begin(db=state, write=True) as txn:\n\
         \x20   txn.put(b'later', b'2')\n\
         \x20   assert txn.get(b'before') == b'1'\n",
        preamble(&path, false)
    ));

    // Every read here opens a fresh transaction, so it sees the new commit
    // rather than a stale snapshot.
    assert_eq!(db.get(b"later").unwrap().as_deref(), Some(&b"2"[..]));
    assert_eq!(db.get(b"before").unwrap().as_deref(), Some(&b"1"[..]));
}

/// Render bytes as a Python `bytes` literal, escaping everything — the only
/// safe way to get arbitrary bytes into a `python3 -c` script.
struct PyBytes<'a>(&'a [u8]);

impl std::fmt::Debug for PyBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("b'")?;
        for b in self.0 {
            write!(f, "\\x{b:02x}")?;
        }
        f.write_str("'")
    }
}
