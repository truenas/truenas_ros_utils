# truenas_ros_utils

Crates that accompany [`truenas_ros`](https://github.com/truenas/truenas_ros)
but cannot live in it, because that crate depends only on `libc` and
`bitflags` and links no C library.

A virtual workspace with no umbrella crate. The members are unrelated to each
other; depend on the one you need.

| Crate | Contents |
|---|---|
| [`truenas_gssapi`](truenas_gssapi/) | A GSSAPI acceptor over the system `libgssapi_krb5`: names, key-table credentials, and the accept-side security-context loop, for SPNEGO and Kerberos |
| [`truenas_jsonrpc`](truenas_jsonrpc/) | JSON-RPC 2.0 for both roles, doing no I/O: framing a byte stream, reading a call or an answer, and building either |
| [`truenas_krb5`](truenas_krb5/) | Bindings to the system MIT Kerberos (`libkrb5`): principals, key tables (including fully in-memory ones), credential caches, and initial-credential acquisition |
| [`truenas_ktls`](truenas_ktls/) | Kernel TLS for accepted sockets: the system libssl runs the handshake, the kernel carries the connection from then on |
| [`truenas_mdb`](truenas_mdb/) | Bindings to the system LMDB (`liblmdb`): a pooled environment and a byte-oriented key/value store |
| [`truenas_nss`](truenas_nss/) | Direct passwd, group, and group-membership lookups against the system NSS service modules (`libnss_files`, `libnss_sss`, `libnss_winbind`), bypassing `nsswitch.conf` |
| [`truenas_pam`](truenas_pam/) | A PAM client over the system `libpam`: transactions, and a login sequence driven one round at a time |
| [`truenas_xdr`](truenas_xdr/) | A serde codec for XDR (RFC 4506) |
| [`truenas_xdr_derive`](truenas_xdr_derive/) | `XdrEnum` and `XdrUnion` derive macros, used through `truenas_xdr`'s `derive` feature |

## Requirements

- Rust 1.97.1 or newer, edition 2024
- `libkrb5-dev` to build `truenas_krb5` (`libkrb5-3`, `libk5crypto3` to run
  it) and `truenas_gssapi` (`libgssapi-krb5-2` to run it)
- `liblmdb-dev` to build `truenas_mdb`, `liblmdb0` to run it
- `libpam0g-dev` to build `truenas_pam`, `libpam0g` to run it
- `libssl-dev` to build `truenas_ktls`; engaging a connection at run time
  needs a kernel with the `tls` upper-layer protocol and a libssl (3.0 or
  newer) built with kTLS support
- Nothing extra to build `truenas_nss`; it loads the modules a lookup names
  at run time (glibc 2.34 or newer; `libnss_files.so.2` ships in `libc6`)
- Nothing extra to build `truenas_jsonrpc` or `truenas_xdr`; neither links a
  C library and neither needs anything at run time

Optional, for the full test suite:

- `python3-lmdb` for `truenas_mdb`'s interop tests
- `libpam-modules` for `truenas_pam`'s suites
- a C compiler (`cc`) for `truenas_nss`'s fixture suites
- the MIT KDC tools (`krb5-kdc`, `krb5-admin-server`, `krb5-user`) for
  `truenas_krb5`'s and `truenas_gssapi`'s KDC-backed suites
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

`truenas_ktls`'s suite generates certificate material in-process and drives
accepts against a userspace TLS client over loopback TCP. The cases that
prove engagement probe once with a real loopback handshake and skip where
the kernel or libssl cannot install TLS on a socket;
`TRUENAS_KTLS_REQUIRE_SYSTEM=1` makes that a failure instead. CI's stock
runners build OpenSSL without kTLS, so CI cannot set it; the variable is for
hosts whose stack can engage, where the full battery runs.

`truenas_krb5`'s and `truenas_gssapi`'s behavioral suites are hermetic: each
case re-executes the test binary with `KRB5_CONFIG` pointing at a generated
configuration, so the host's Kerberos state never reaches an assertion. Their
KDC-backed suites stand up a throwaway MIT KDC in a temporary directory and
drive a real AS exchange — `truenas_gssapi` additionally runs an initiator
against its own acceptor over Kerberos and SPNEGO. They skip when the KDC
tools are absent; `TRUENAS_KRB5_REQUIRE_KDC=1` and
`TRUENAS_GSSAPI_REQUIRE_KDC=1`, which CI sets on hosts that carry them, make
that a failure instead.

`truenas_xdr`'s `derive` feature is on by default. To check the codec without
the proc-macro crate:

```sh
cargo test -p truenas_xdr --no-default-features
```

To run the suites under valgrind, as CI does:

```sh
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=99 \
    --leak-check=full --errors-for-leak-kinds=definite --keep-debuginfo=yes \
    --quiet --suppressions=$PWD/valgrind.supp --trace-children=yes \
    --trace-children-skip=*/cc,*/python3*,*/krb5kdc,*/kadmin.local,*/kdb5_util,*/kinit" \
    cargo test --workspace
```

`valgrind.supp` suppresses leaks inside a bound system library on paths the
binding cannot release (currently one, in MIT libgssapi_krb5's credential
acquisition); each entry is scoped to the library so it can never mask a leak
in this workspace's own code.

`--keep-debuginfo=yes` is for `truenas_pam`: libpam loads each module with
`dlopen(3)` and unloads it at the end of the transaction, and without this a
report from inside one has no symbols left to name.

`--trace-children=yes` is for `truenas_nss`: its fan-out suite drives the
module registry only in a re-executed child. `cc` and `python3` are skipped —
they are not under test and are not memcheck-clean.

## License

MIT — see [`LICENSE`](LICENSE).
