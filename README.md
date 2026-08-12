# truenas_ros_utils

Crates that accompany [`truenas_ros`](https://github.com/truenas/truenas_ros)
but cannot live in it, because that crate depends only on `libc` and
`bitflags` and links no C library.

A virtual workspace with no umbrella crate. The members are unrelated to each
other; depend on the one you need.

| Crate | Contents |
|---|---|
| [`truenas_mdb`](truenas_mdb/) | Bindings to the system LMDB (`liblmdb`): a pooled environment and a byte-oriented key/value store |
| [`truenas_nss`](truenas_nss/) | Direct passwd and group lookups against the system NSS service modules (`libnss_files`, `libnss_sss`, `libnss_winbind`), bypassing `nsswitch.conf` |
| [`truenas_pam`](truenas_pam/) | A PAM client over the system `libpam`: transactions, and a login sequence driven one round at a time |
| [`truenas_xdr`](truenas_xdr/) | A serde codec for XDR (RFC 4506) |
| [`truenas_xdr_derive`](truenas_xdr_derive/) | `XdrEnum` and `XdrUnion` derive macros, used through `truenas_xdr`'s `derive` feature |

## Requirements

- Rust 1.97.1 or newer, edition 2024
- `liblmdb-dev` to build `truenas_mdb`, `liblmdb0` to run it
- `libpam0g-dev` to build `truenas_pam`, `libpam0g` to run it
- Nothing extra to build `truenas_nss`; it loads the modules a lookup names
  at run time (glibc 2.34 or newer; `libnss_files.so.2` ships in `libc6`)

Optional, for the full test suite:

- `python3-lmdb` for `truenas_mdb`'s interop tests
- `libpam-modules` for `truenas_pam`'s suites
- a C compiler (`cc`) for `truenas_nss`'s fixture suites
- `valgrind` for the memcheck run

## Building and testing

```sh
cargo build --workspace
cargo test --workspace
```

`truenas_mdb`'s interop suite drives Python's `lmdb` module over the same
environment and checks both implementations agree byte for byte. It skips when
`python3-lmdb` is absent; `TRUENAS_MDB_REQUIRE_PYTHON=1`, which CI sets, makes
that a failure instead.

`truenas_pam`'s suites run their own service files out of `truenas_pam/tests`,
through `pam_start_confdir(3)`, so they need neither privilege nor anything in
`/etc/pam.d`. They do need the modules those files name, all of which ship in
`libpam-modules`; they skip when one is missing, and
`TRUENAS_PAM_REQUIRE_MODULES=1`, which CI sets, makes that a failure instead.

`truenas_nss`'s behavioral suites compile a fixture service module from
`truenas_nss/tests/fixture` at test time and load it by path, so nothing on
the host is touched; they skip when no C compiler is present, and
`TRUENAS_NSS_REQUIRE_CC=1`, which CI sets, makes that a failure instead. Its
smoke tests drive the system's own `files` module and skip when it cannot be
loaded; `TRUENAS_NSS_REQUIRE_SYSTEM=1`, which CI sets, makes that a failure
instead.

`truenas_xdr`'s `derive` feature is on by default. To check the codec without
the proc-macro crate:

```sh
cargo test -p truenas_xdr --no-default-features
```

To run the suites under valgrind, as CI does:

```sh
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=99 \
    --leak-check=full --errors-for-leak-kinds=definite --keep-debuginfo=yes \
    --quiet" \
    cargo test --workspace
```

`--keep-debuginfo=yes` is for `truenas_pam`: libpam loads each module with
`dlopen(3)` and unloads it at the end of the transaction, and without this a
report from inside one has no symbols left to name.

## License

MIT — see [`LICENSE`](LICENSE).
