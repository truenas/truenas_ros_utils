# truenas_ros_utils

Crates that accompany [`truenas_ros`](https://github.com/truenas/truenas_ros)
but cannot live in it, because that crate depends only on `libc` and
`bitflags` and links no C library.

A virtual workspace with no umbrella crate. The members are unrelated to each
other; depend on the one you need.

| Crate | Contents |
|---|---|
| [`truenas_mdb`](truenas_mdb/) | Bindings to the system LMDB (`liblmdb`): a pooled environment and a byte-oriented key/value store |
| [`truenas_xdr`](truenas_xdr/) | A serde codec for XDR (RFC 4506) |
| [`truenas_xdr_derive`](truenas_xdr_derive/) | `XdrEnum` and `XdrUnion` derive macros, used through `truenas_xdr`'s `derive` feature |

## Requirements

- Rust 1.97.1 or newer, edition 2024
- `liblmdb-dev` to build `truenas_mdb`, `liblmdb0` to run it

Optional, for the full test suite:

- `python3-lmdb` for `truenas_mdb`'s interop tests
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

`truenas_xdr`'s `derive` feature is on by default. To check the codec without
the proc-macro crate:

```sh
cargo test -p truenas_xdr --no-default-features
```

To run the suites under valgrind, as CI does:

```sh
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=99 \
    --leak-check=full --errors-for-leak-kinds=definite --quiet" \
    cargo test --workspace
```

## License

MIT — see [`LICENSE`](LICENSE).
