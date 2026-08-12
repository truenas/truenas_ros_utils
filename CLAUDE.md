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

## `truenas_nss`

Consumes the system NSS service modules directly: `libnss_files.so.2`,
`libnss_sss.so.2`, and `libnss_winbind.so.2` are dlopened by bare soname on
first use and their `_nss_<module>_*` service functions called, so
`nsswitch.conf` and the libc frontends never mediate a lookup. Nothing is
linked at build time. It needs glibc 2.34: from there `dlopen` lives in
`libc.so.6`, and `libnss_files.so.2` is a stub whose `_nss_files_*` functions
are reached through the handle's dependency scope — `dlsym` therefore always
goes through the handle, never `RTLD_DEFAULT`.

A loaded module is never dlclosed: NSS modules keep global and thread-local
state and are not built to be unloaded, so every handle and `Service` lives
for the process. Every dlopen/dlsym/dlerror sequence runs under one lock,
because `dlerror` reports through shared state.

Entries name the module that produced them. The password fields
(`pw_passwd`, `gr_passwd`) are omitted: the hash lives in the shadow
database, and the placeholder invites misuse. The fan-out lookups skip a
module that reports UNAVAIL and propagate every other failure, a module that
cannot be loaded included.

Enumeration is per module — no all-modules iterator, which would invent an
ordering NSS does not define. `FILES` keeps one cursor per process, so its
iterator holds a per-service lock for its whole life and another thread's
enumeration waits; `SSS` and `WINBIND` cursors are per thread, so iterators
are `!Send`. A same-thread iterator that would share a cursor (or the lock)
is refused with `Error::Busy` in [`src/service.rs`](truenas_nss/src/service.rs)
rather than left to deadlock.

`Service::open` points the crate at a module by explicit path.
[`tests/`](truenas_nss/tests/) compile deterministic fixture modules from
[`tests/fixture/nss_fixture.c`](truenas_nss/tests/fixture/nss_fixture.c) and
load them that way — built without a soname, so a fixture can never satisfy
the registry's bare-soname lookups. [`tests/fanout.rs`](truenas_nss/tests/fanout.rs)
re-executes itself with `LD_LIBRARY_PATH` pointing at fixtures named as the
three modules, so a child process drives the real registry end to end.

## `truenas_pam`

Links the system `libpam`. A PAM transaction is only meaningful against the
modules and configuration the host has installed, so there is nothing to
vendor.

`pam_start_confdir` is the entry point rather than `pam_start`, so a
transaction may be pointed at service files of its own.
[`tests/`](truenas_pam/tests/) run their own stacks out of the source tree that
way, without privilege and without touching `/etc/pam.d`. It needs libpam 1.4.

`libpam_misc` is not linked, so `pam_misc_setenv`'s read-only variables are not
offered; `pam_putenv` covers set, replace, and delete.

Items are a partial set. `PAM_AUTHTOK` and `PAM_OLDAUTHTOK` are omitted because
a password reaches a module through the conversation, and writing one into the
handle leaves it there for every later module to read; `PAM_CONV` because the
crate owns it; the `PAM_FAIL_DELAY` function pointer in favour of
`pam_fail_delay()`; and the X and prompt-text items as having no bearing on a
network service. Each omission is documented where the accessors are defined.

The conversation is the crate's only C callback, and
[`src/conv.rs`](truenas_pam/src/conv.rs) is where the conventions for one live:
responses are allocated with `malloc` because the module stack frees them with
`free`; every array the stack will not see is scrubbed before release; and the
body runs under `catch_unwind`, since unwinding into C is undefined and
aborting would skip `pam_end`. A panic is held until libpam has unwound its own
frames, then resumed on the thread that drove the call.

One thread at a time per handle, stated in the types: every operation takes
`&mut self`, and [`src/step.rs`](truenas_pam/src/step.rs) moves the whole
transaction onto its worker, so the caller cannot reach it mid-exchange.
Cancellation is cooperative — a module cannot be stopped mid-call — so a step
timeout bounds the round trip and teardown still waits for the module.

The crate knows PAM and nothing above it. Which service to run, what a prompt
means, and what to make of a refusal are policy and belong to the consumer.

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

Decoding bounds its own nesting (`Deserializer::DEFAULT_MAX_DEPTH`, raised
with `with_max_depth`), so a hostile chain of §4.19 optionals is
`Error::RecursionLimit`, not a stack overflow.
[`tests/robustness.rs`](truenas_xdr/tests/robustness.rs) holds every decode
path to Ok-or-Err over a hostile corpus.

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
TRUENAS_MDB_REQUIRE_PYTHON=1 TRUENAS_PAM_REQUIRE_MODULES=1 \
    TRUENAS_NSS_REQUIRE_CC=1 TRUENAS_NSS_REQUIRE_SYSTEM=1 \
    cargo test --workspace
cargo test -p truenas_xdr --no-default-features
cargo doc --workspace --no-deps          # must be warning-free
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="valgrind --error-exitcode=99 \
    --leak-check=full --errors-for-leak-kinds=definite \
    --keep-debuginfo=yes --quiet" \
    TRUENAS_MDB_REQUIRE_PYTHON=1 TRUENAS_PAM_REQUIRE_MODULES=1 \
    TRUENAS_NSS_REQUIRE_CC=1 TRUENAS_NSS_REQUIRE_SYSTEM=1 \
    cargo test --workspace
```

Build needs `liblmdb-dev` and `libpam0g-dev`; the interop suite needs
`python3-lmdb`, the PAM suites need `libpam-modules`, and the NSS fixture
suites need a C compiler (`cc`); the memcheck run needs `valgrind`, and
`--keep-debuginfo=yes` because libpam unloads each module before the process
ends.
