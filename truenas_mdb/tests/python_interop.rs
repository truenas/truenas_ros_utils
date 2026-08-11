//! Cross-implementation tests against Python's `lmdb` module over one shared
//! environment.
//!
//! These check that this crate's on-disk behaviour is plain LMDB and nothing
//! else: an independent implementation, linking the same `liblmdb`, must read
//! and write the same databases with byte-identical results. Value framing,
//! key handling, and the environment flags all have to agree for that to
//! hold.
//!
//! Skips when `python3` or its `lmdb` module is missing. Set
//! `TRUENAS_MDB_REQUIRE_PYTHON=1` to turn that skip into a failure, so the
//! suite cannot go green by doing nothing.
//!
//! Debian's `python3-lmdb` links the system `liblmdb0` and is what this
//! expects. `pip install lmdb` bundles its own copy and would test something
//! else.

use std::path::Path;
use std::process::Command;

use truenas_mdb::{Db, Env, EnvFlags, EnvOptions};

/// Map size used on both sides, well above py-lmdb's 10 MiB default so the
/// value has to be passed across deliberately rather than coinciding.
const MAP_SIZE: usize = 64 * 1024 * 1024;

const OPTS: EnvOptions = EnvOptions {
    map_size: MAP_SIZE,
    max_dbs: 8,
    max_readers: 0,
    mode: 0o600,
    dir_mode: 0o700,
    flags: EnvFlags::empty(),
};

/// Whether a missing `python3-lmdb` should fail rather than skip.
fn python_required() -> bool {
    std::env::var_os("TRUENAS_MDB_REQUIRE_PYTHON").is_some_and(|v| v == "1")
}

/// `Some(())` when the suite can run; `None` to skip.
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
        "TRUENAS_MDB_REQUIRE_PYTHON=1 but `python3 -c 'import lmdb'` failed; \
         install python3-lmdb"
    );
    None
}

/// Run a Python snippet and return its stdout, printing the script and stderr
/// on failure.
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

/// Open the same environment the Rust side does, with the flags the shared
/// layout requires.
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
        "different LMDB versions means two copies of the library, which is \
         unsound over one environment"
    );
}

#[test]
fn rust_writes_and_python_reads() {
    let Some(()) = python_lmdb() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("env");

    {
        let env = Env::open_with(&path, &OPTS).unwrap();
        let state = Db::create(&env, "state").unwrap();
        let main = Db::main(&env).unwrap();
        state.put("job", "RUNNING").unwrap();
        state.put("count", "42").unwrap();
        main.put("top", "level").unwrap();
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
    // Let Python create the environment outright, so this direction proves a
    // database made elsewhere can be adopted unchanged.
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

    let env = Env::open_with(&path, &OPTS).unwrap();
    let state = Db::open(&env, "state").unwrap();
    assert_eq!(
        state.get("from-python").unwrap().as_deref(),
        Some(&b"hello"[..])
    );
    assert_eq!(state.get("n").unwrap().as_deref(), Some(&b"7"[..]));
    assert_eq!(state.len().unwrap(), 2);

    let all: Vec<(Vec<u8>, Vec<u8>)> =
        state.iter().unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(
        all,
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

    // Embedded NULs, high bytes, and invalid UTF-8: anything an envelope, a
    // string conversion, or a C `strlen` would mangle.
    let key: &[u8] = b"k\x00ey\xff";
    let value: &[u8] = b"\x00\xff\x80\xc3\x28bin\x00ary\n\r\x7f";

    {
        let env = Env::open_with(&path, &OPTS).unwrap();
        let db = Db::create(&env, "bin").unwrap();
        db.put(key, value).unwrap();
        db.put("empty", "").unwrap();
    }

    // Read what Rust wrote, and write it back under a second key so the return
    // leg can be checked too.
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

    let env = Env::open_with(&path, &OPTS).unwrap();
    let db = Db::open(&env, "bin").unwrap();
    assert_eq!(db.get("roundtrip").unwrap().as_deref(), Some(value));
    assert_eq!(db.get(key).unwrap().as_deref(), Some(value));
}

#[test]
fn python_reads_a_database_past_its_own_default_map_size() {
    let Some(()) = python_lmdb() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("env");

    // 12 MiB, past py-lmdb's 10 MiB default map_size. Opening still succeeds,
    // because LMDB raises an undersized map to the committed data size — which
    // is why the map_size hazard is a write-side one.
    {
        let env = Env::open_with(&path, &OPTS).unwrap();
        let db = Db::create(&env, "bulk").unwrap();
        let chunk = vec![0x5au8; 1024 * 1024];
        for i in 0..12u32 {
            db.put(i.to_be_bytes(), &chunk).unwrap();
        }
    }

    let out = py(&format!(
        "import lmdb\n\
         # No map_size argument: py-lmdb's 10 MiB default.\n\
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
fn a_live_environment_sees_the_other_processs_write() {
    let Some(()) = python_lmdb() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("env");

    // A long-lived process holding the environment open while another writes.
    let env = Env::open_with(&path, &OPTS).unwrap();
    let db = Db::create(&env, "state").unwrap();
    db.put("before", "1").unwrap();
    assert_eq!(db.get("later").unwrap(), None);

    py(&format!(
        "{}\
         state = env.open_db(b'state')\n\
         with env.begin(db=state, write=True) as txn:\n\
         \x20   txn.put(b'later', b'2')\n\
         \x20   assert txn.get(b'before') == b'1'\n",
        preamble(&path, false)
    ));

    // Each read opens a fresh transaction, so it sees the new commit rather
    // than a stale snapshot.
    assert_eq!(db.get("later").unwrap().as_deref(), Some(&b"2"[..]));
    assert_eq!(db.get("before").unwrap().as_deref(), Some(&b"1"[..]));
    assert_eq!(db.len().unwrap(), 2);
}

#[test]
fn an_iterator_holds_its_snapshot_against_another_process() {
    let Some(()) = python_lmdb() else { return };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("env");

    let env = Env::open_with(&path, &OPTS).unwrap();
    let db = Db::create(&env, "state").unwrap();
    for key in ["a", "b", "c"] {
        db.put(key, key).unwrap();
    }

    // The read transaction is opened here and outlives the Python write.
    let iter = db.iter().unwrap();
    py(&format!(
        "{}\
         state = env.open_db(b'state')\n\
         with env.begin(db=state, write=True) as txn:\n\
         \x20   txn.put(b'd', b'd')\n\
         \x20   txn.delete(b'a')\n",
        preamble(&path, false)
    ));

    let keys: Vec<Vec<u8>> = iter
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(keys, [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);

    // A new read sees the other process's changes.
    assert_eq!(db.len().unwrap(), 3);
    assert!(db.contains_key("d").unwrap());
    assert!(!db.contains_key("a").unwrap());
}

/// Render bytes as a fully escaped Python `bytes` literal — the only safe way
/// to get arbitrary bytes into a `python3 -c` script.
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
