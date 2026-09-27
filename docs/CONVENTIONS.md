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

## Crates and boundaries

- `types` has no I/O. `meta` owns all SQL. `store` owns the disk layout. `s3` owns the S3
  semantics and is the only crate besides `server` that knows about s3s. `server` owns
  networking and startup. The command only parses, calls and prints.
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

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/): `feat(store): …`,
  `fix(s3): …`, `docs: …`. The scope is the crate or area.
- No AI or assistant attribution in commits or pull requests.
- One logical change per pull request; squash-merged, so the title is the commit.

## Writing

Docs and messages are plain, direct English: say what happens and what to do. Errors name
the thing and the fix ("this drive was formatted by a newer TeiFS (format 2); upgrade
TeiFS, or restore a backup made by this version").
