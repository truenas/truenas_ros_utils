# CLAUDE.md

## Workspace

Virtual workspace, no umbrella crate. Members are independent of each other; a
consumer depends on the one it wants. Crate names use underscores.

Edition 2024 and `rust-version = "1.97.1"` are set once in
`[workspace.package]`; members inherit both. Lints come from
`[workspace.lints.rust]`, with `lints.workspace = true` in each member.
`Cargo.lock` is committed. rustfmt uses `max_width = 80`.

`unsafe_code` is `deny`, not `forbid`, so an FFI crate can lift it per module
with `#![allow(unsafe_code)]`. Every `unsafe` block carries a `// SAFETY:` note
naming the invariant it relies on. A crate with no FFI sets
`#![forbid(unsafe_code)]` at its own root instead.

## Licensing

MIT throughout. [`LICENSE`](LICENSE) holds the text and every member inherits
`license.workspace = true`.

Each source file, manifest, and workflow opens with a two-line SPDX header, so
the license and its holder travel with the file rather than only with the
repository:

```rust
// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
```

`#` replaces `//` in TOML and YAML. The copyright line matches `LICENSE`
verbatim; keep the two in step. A new file gets the header when it is created.
Prose files (`README.md`, `CLAUDE.md`) and `LICENSE` itself do not carry one.

## Documentation and comments

Terse and factual. No marketing, no persuasion, no weighing the design against
alternatives that were not chosen.

- State a constraint as a requirement, not as the consequence of violating it.
- Do not reference other repositories, earlier implementations, or defects in
  them. This is green-field code and reads as such.
- A comment says what invariant holds, or why something non-obvious is the way
  it is. It does not argue for the design.
- A test comment says what the test would catch.

## Testing

Cover the public API surface as closely as is reasonable. Test this
workspace's own decisions — copying, lifetimes, locking, error classification,
wire layout — and take the correctness of what it binds to or depends on as
given.

Expected values come from the specification, written out by hand. Do not
capture them from a run of the implementation: a test built that way only
proves the code still does what it did, not that it does the right thing.

A suite that can skip must be able to fail instead, under an environment
variable CI sets. A skip must never be able to read as a pass.

## Memory safety

A crate with an FFI boundary runs its whole suite under valgrind memcheck in
CI, through `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER`. Only `definite`
leak kinds count as errors: a process-lifetime static is reported as possibly
lost and is not one.

## Implementing a published standard

When a crate implements a specification:

- Fetch the specification and test against it clause by clause, with each test
  naming the section it comes from.
- Reproduce any worked example the document gives, byte for byte.
- Read the reference implementations for behaviour the document leaves open and
  for the error conventions they use. Record what they establish in the crate's
  documentation, not what they are called or where they live.

## `truenas_mdb`

Links the system `liblmdb`. It is never vendored: exactly one copy of LMDB may
mediate an environment within a process, and these databases are shared with
other processes that link `liblmdb0`.

`MDB_NOTLS` is neither set nor offered, so LMDB's default applies — one
transaction per thread per environment. [`src/txn.rs`](truenas_mdb/src/txn.rs)
enforces that with `EDEADLK` rather than leaving a second transaction to
deadlock on the writer mutex or fail with `MDB_BAD_RSLOT`.

One environment per path per process, reference counted through the pool in
[`src/env.rs`](truenas_mdb/src/env.rs).

Values are stored byte for byte. No header, envelope, or encoding is added, so
another reader of the database sees what was written. `EnvFlags` exposes
durability and readahead only; `MDB_WRITEMAP`, `MDB_MAPASYNC`, `MDB_NOSUBDIR`,
and `MDB_NOLOCK` stay out, each omission documented where the type is defined.

Interoperability is held to account against `python3-lmdb` over one shared
environment ([`tests/python_interop.rs`](truenas_mdb/tests/python_interop.rs)).
It must be the distro package, which links `liblmdb0`; `pip install lmdb`
bundles its own copy and would test nothing.

## `truenas_xdr`

Conforms to RFC 4506 (STD 67).
[`tests/rfc4506.rs`](truenas_xdr/tests/rfc4506.rs) follows the document section
by section and ends with the §7 worked example taken from its hex dump. Any
change to encoding or decoding is checked against the standard first.

`serde` is a traits-only dependency: the crate implements `Serializer` and
`Deserializer` and hand-writes its wrapper impls, so it pulls no
`serde_derive`. The `derive` feature is the separate `truenas_xdr_derive`
crate, and the codec builds and passes without it.

Decoding entry points are explicit about the input they expect: `from_bytes`
consumes it exactly and reports what is left over, `from_prefix` returns the
unread tail. Silently ignoring trailing input is not an option — it hides
truncation and framing errors.

`Strictness` is a decode-time choice because encoding is identical either way.
`Strict` holds input to what the standard permits an encoder to emit; `Lenient`
accepts what real encoders send.

Strings and opaque data decode as borrows of the input. A wire format has to
round-trip through itself, which `&[u8]` does not — serde encodes it as a
sequence and decodes it as opaque — so `VarOpaqueRef` exists for that.

The codec knows about RFC 4506 and nothing above it. No framing, no envelopes,
no transport or protocol vocabulary belongs in this crate.

## Verification

Everything below must pass before a change lands. CI runs all of it.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
TRUENAS_MDB_REQUIRE_PYTHON=1 cargo test --workspace
cargo test -p truenas_xdr --no-default-features
cargo doc --workspace --no-deps          # must be warning-free
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=99 \
    --leak-check=full --errors-for-leak-kinds=definite --quiet" \
    TRUENAS_MDB_REQUIRE_PYTHON=1 cargo test --workspace
```

Build needs `liblmdb-dev`; the interop suite needs `python3-lmdb`; the memcheck
run needs `valgrind`.
