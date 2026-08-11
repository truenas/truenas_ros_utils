# truenas_ros_utils

Satellite crates for [`truenas_ros`](https://github.com/truenas/truenas_ros) — pieces
that belong with it but cannot live inside it. `truenas_ros` depends only on `libc`
and `bitflags` and links no C library; each crate here breaks exactly one of those
rules, for a reason stated in its own manifest.

This is a virtual workspace: there is no umbrella crate, and members are unrelated
to each other. Depend on the one you want.

| Crate | Contents |
|---|---|
| [`truenas_mdb`](truenas_mdb/) | Bindings to the system LMDB (`liblmdb`) — a refcounted per-path environment pool and a flat, raw-bytes key/value op-set |

## Requirements

- Rust 1.97 or newer
- `liblmdb-dev` to build `truenas_mdb`, `liblmdb0` to run it

## Testing

`cargo test --workspace`. `truenas_mdb`'s interop suite spawns Python's `lmdb`
module and asserts both implementations agree byte-for-byte on the same
environment; it skips when `python3-lmdb` is unavailable, and
`TRUENAS_MDB_REQUIRE_PYTHON=1` (as CI sets) makes that a hard failure instead.

## License

MIT — see [`LICENSE`](LICENSE).
