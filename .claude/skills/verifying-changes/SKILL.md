---
name: verifying-changes
description: Chooses and runs the right checks for a change in the TeiFS repository (targeted tests while iterating, a real S3 client for S3 behaviour, the format fixtures for anything on disk, then the full cargo xtask verify) and fixes what they report before committing. Use before every commit or pull request, and when asked to test, check or validate a change.
allowed-tools: Bash(git status *)
---

# Verifying changes

Files changed in the working tree:

!`git status --short`

## While iterating: run what the change touches

| Changed | Run |
|---|---|
| A crate | `cargo nextest run -p <package> -E 'test(<name>)'` (or `cargo test -p <package> <name>`) |
| An S3 operation (`crates/s3/src/drive.rs`) | `cargo test -p teifs-server --test sdk`, then a real client against `cargo run -p teifs -- serve <dir>` (see below) |
| Anything in `.teifs/` or the file layout | `cargo test -p teifs-store --test format`; follow the `changing-on-disk-format` skill |
| Key or bucket name rules (`crates/types/src/names.rs`) | `cargo test -p teifs-types` and `cargo test -p teifs-store` |
| Docs | `cargo xtask docs` (every path named in the docs must exist) |

Packages: `teifs-types`, `teifs-meta`, `teifs-store`, `teifs-s3`, `teifs-server`, `teifs`,
`xtask`.

### A real S3 client

```sh
TEIFS_ACCESS_KEY=dev TEIFS_SECRET_KEY=dev-secret-not-real \
  cargo run -p teifs -- serve /tmp/teifs-drive --listen 127.0.0.1:9000 &
export AWS_ACCESS_KEY_ID=dev AWS_SECRET_ACCESS_KEY=dev-secret-not-real \
       AWS_DEFAULT_REGION=us-east-1 AWS_ENDPOINT_URL=http://127.0.0.1:9000
aws s3 mb s3://check && aws s3 cp ./somefile s3://check/a/b && aws s3 ls s3://check --recursive
```

Stop the server afterwards and delete the drive folder.

## Before committing: everything

```sh
cargo fmt --all
cargo xtask verify
```

It runs rustfmt, clippy with `-D warnings`, the whole test suite with cargo-nextest, doc
tests, cargo-deny and the docs path check. It must exit 0.

## When something fails

1. Read the first error, not the last. Fix the cause, not the symptom.
2. Clippy: fix the code; `#[allow]` only with a `reason = "…"` saying why it's right here.
3. A failing test you didn't touch: find out why before changing it. A test changes only
   when the behaviour it pins was meant to change.
4. A format fixture fails: the change broke drives written by an earlier release. Never
   change or delete a fixture to make it pass.
5. cargo-deny: a new advisory needs a dependency update, not an `ignore`, unless the
   vulnerable code isn't reachable; then add the ignore with the reason.

Don't report a change as done while any check fails; say which check fails and why.
