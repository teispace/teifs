# AGENTS.md

Guidance for AI coding agents working on TeiFS. Human contributors: start with
[CONTRIBUTING.md](CONTRIBUTING.md); everything here applies to you too.

TeiFS is an S3 server that stores objects as plain files, and a command line to run and
manage it. People trust it with their files, so correctness, durability and security come
before speed.

## Rules that are never broken

- **No `unsafe`** in any crate (`unsafe_code = "forbid"`), and **no `unwrap`** outside
  tests. `expect` only for real invariants, with a message saying which.
- **The on-disk format is a contract** ([docs/ON_DISK_FORMAT.md](docs/ON_DISK_FORMAT.md)).
  Changing what's written in `.teifs/` or the file layout needs a format version bump in
  `crates/store/src/format.rs`, an upgrade, and a fixture drive in
  `crates/store/tests/fixtures/` proving old drives still open. Never edit a released
  database migration; add a new one.
- **Keys never escape their bucket.** Every key goes through `ObjectKey::parse`; paths are
  built only from checked parts and compared with their canonical form before use.
- **Writes are atomic**: stage in `.teifs/tmp`, sync, rename, sync the folder, record the
  row, all under the commit lock.
- **Secrets never reach logs, command lines or test fixtures.**
- **S3 behaviour matches AWS**, except where plain files make it impossible; those
  differences are listed in [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).
- **Tests with every change.** A bug fix includes a test that fails without it.
- **Commits and pull requests** use Conventional Commits and contain no AI or assistant
  attribution (no `Co-Authored-By` trailers, no "Generated with" lines).

## Layout

```
crates/types    shared types with no I/O: names, keys, attributes, stamps, ETags
crates/meta     SQLite: the object index and the system database (all SQL lives here)
crates/store    the storage engine: drive format, buckets, writes, reads, listing, multipart
crates/s3       the S3 operations over a store (s3s's `S3` trait)
crates/server   credentials, the HTTP listener, Server::bind / run
apps/cli        the `teifs` command
xtask           project tasks (`cargo xtask verify`)
docs/           ARCHITECTURE, CONVENTIONS, SECURITY_MODEL, ON_DISK_FORMAT, COMPATIBILITY
```

## Commands

- `cargo xtask verify`: everything CI checks (rustfmt, clippy, tests with cargo-nextest,
  doc tests, cargo-deny, and a check that every path the docs name exists). **Must pass
  before every commit.** Needs `cargo install cargo-nextest cargo-deny --locked`.
- `cargo test --workspace`: every test, including the AWS SDK end-to-end suite
  (`crates/server/tests/sdk.rs`) and the format fixtures (`crates/store/tests/format.rs`).
- `cargo xtask docs`: only the docs path check.
- `cargo test -p <crate> <name>`: a subset. Crates: `teifs-types`, `teifs-meta`,
  `teifs-store`, `teifs-s3`, `teifs-server`, `teifs`.
- `cargo run -p teifs -- serve <dir>`: run a server; drive it with the AWS CLI
  (`AWS_ENDPOINT_URL=http://127.0.0.1:9000`) to check a change end to end.

## How to work

1. Read the relevant part of [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
   [docs/CONVENTIONS.md](docs/CONVENTIONS.md).
2. Find the existing pattern and follow it.
3. Make the smallest change that solves the problem completely, with tests. For an S3
   operation, add an SDK test in `crates/server/tests/sdk.rs` next to the store test.
4. Update the docs the change affects, in the same pull request: COMPATIBILITY for S3
   behaviour, ON_DISK_FORMAT for anything on disk, SECURITY_MODEL for a security rule,
   ARCHITECTURE when the structure changes, the README for commands.
5. Run `cargo xtask verify` and fix everything it reports.

## Keep this guidance current

This file and the contributor docs describe how the code works now. Whoever changes the
code updates them in the same pull request: a moved file, a renamed function, a new rule
or a pitfall you had to discover.
