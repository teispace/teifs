# Conventions

How code in TeiFS is written. Follow the existing pattern; a new pattern needs a reason
in the pull request.

## Rust

- **Edition 2024**, the toolchain in `rust-toolchain.toml`. `cargo fmt` formats
  everything; `cargo clippy --workspace --all-targets -- -D warnings` must be clean with
  the workspace lints (pedantic on).
- **No `unsafe`** anywhere (`unsafe_code = "forbid"`). System calls the standard library
  lacks go through a safe wrapper crate.
- **No `unwrap`** outside tests (denied by lint). `expect` only for real invariants, with
  a message that says which (`.expect("the format serializes")`). Anything that depends on
  input returns an error.
- **Errors** are `thiserror` enums named after their crate (`StoreError`, `MetaError`,
  `NameError`) with messages a person can act on. No `anyhow` in library crates.
- **Docs**: every public item has a doc comment (`missing_docs`). Module comments say
  what the module is for and the rules it keeps.
- **Blocking work** (files, SQLite) runs in `spawn_blocking`, never on an async worker.
- **Logging** uses `tracing` with fields (`tracing::warn!(error = %err, "…")`), never
  `println!` in libraries. Secrets are never logged.
- **Dependencies**: add one only when it earns its place; prefer crates already in the
  tree. Versions live in the workspace `Cargo.toml`.

## Cryptography

- Only in `teifs-crypto`, only with aws-lc-rs (AES-256-GCM, HKDF-SHA256, HMAC-SHA256,
  randomness). No hand-rolled primitives, no second crypto library.
- Key material lives in `zeroize` types, has a `Debug` that prints nothing, and is
  compared in constant time.
- The byte format is specified in [ENCRYPTION_FORMAT.md](ENCRYPTION_FORMAT.md) first,
  then implemented; tests cover tampering, reordering, truncation and wrong keys.

## Crates and boundaries

- `types` has no I/O. `meta` owns all SQL. `store` owns the disk layout. `s3` owns the S3
  semantics and is the only crate besides `server` that knows about s3s. `server` owns
  networking and startup. The command only parses, calls and prints.
- The command prints only through `apps/cli/src/ui.rs`: results on standard output
  (`ui::item`, `ui::done`, `ui::rows`, `ui::details`), with a JSON record for `--json`
  alongside each; notes, warnings, errors and progress on standard error. Errors carry a
  `Kind` (the exit code) and, when there's something to do, a hint. Questions are asked
  only on a terminal, and every one has a flag that answers it.
- A new crate is added only for a boundary that's needed now (another crate must use
  the code without the rest, or it must be embeddable on its own).

## On-disk format

Anything that changes what's written in `.teifs/` or how files are laid out is a format
change: bump the version in `crates/store/src/format.rs`, add the upgrade, update
[ON_DISK_FORMAT.md](ON_DISK_FORMAT.md), and add a fixture drive written by the release
before the change. Database schema changes add a migration at the end of the list; never
edit a released migration.

## S3 behaviour

- Match AWS. When AWS and other S3 servers disagree, AWS wins unless the difference is
  forced by storing plain files; then it's documented in the README's limits and
  [COMPATIBILITY.md](COMPATIBILITY.md).
- TeiFS-specific error codes start with `XTeiFS` (`XTeiFSKeyConflict`).

## Tests

- Every change comes with tests; a bug fix includes a test that fails without it.
- Unit tests beside the code; tests that need a running server go in
  `crates/server/tests/` and use the official AWS SDK.
- Tests never depend on the network, the clock's exact value, or the test machine's disk
  type, except where they check that behaviour (and then they detect it).
- Code that reads what a client sends (keys, prefixes, escapes, policies) also gets a
  property test: `proptest` with a strategy built from the pieces that matter (`..`,
  `/`, the names of what lies beside it), checked to catch a broken guard before it's
  kept. Examples: `crates/store/src/property_tests.rs`, `crates/types/src/names.rs`.
  A failing case proptest saves under `proptest-regressions/` is committed with its fix.
- A change to how a write reaches the disk keeps `crates/store/tests/crash.rs` passing:
  a child process writes until it's killed, and every acknowledged write must be there
  after. The nightly run kills it 200 times (`TEIFS_CRASH_ROUNDS`).

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/): `feat(store): …`,
  `fix(s3): …`, `docs: …`. The scope is the crate or area.
- No AI or assistant attribution in commits or pull requests.
- One logical change per pull request; squash-merged, so the title is the commit.

## Writing

Docs and messages are plain, direct English: say what happens and what to do. Errors name
the thing and the fix ("this drive was formatted by a newer TeiFS (format 2); upgrade
TeiFS, or restore a backup made by this version").
