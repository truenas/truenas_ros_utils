# truenas_ros_utils

Satellite crates for [`truenas_ros`](https://github.com/truenas/truenas_ros): pieces
that belong with it but cannot live inside it, because `truenas_ros` depends only on
`libc` and `bitflags` and links no C library.

A virtual workspace with no umbrella crate — the members are unrelated to each
other. Depend on the one you want.

| Crate | Contents |
|---|---|
| [`truenas_mdb`](truenas_mdb/) | Bindings to the system LMDB (`liblmdb`): a pooled environment and a byte-oriented key/value store |

## Requirements

- Rust 1.97.1 or newer (edition 2024)
- `liblmdb-dev` to build `truenas_mdb`, `liblmdb0` to run it

## Testing

`cargo test --workspace`.

`truenas_mdb` also has an interop suite that drives Python's `lmdb` module over the
same environment and checks both implementations agree byte for byte. It skips when
`python3-lmdb` is unavailable; `TRUENAS_MDB_REQUIRE_PYTHON=1` (which CI sets) makes
that a failure instead.

## License

MIT — see [`LICENSE`](LICENSE).
