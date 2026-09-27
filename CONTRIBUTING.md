# Contributing to TeiFS

Thank you for your interest in TeiFS. Every contribution helps, whether it's a bug
report, a test against another S3 client, a docs fix or a new feature.

## Ways to contribute

- **Report a bug** with the [bug form](https://github.com/teispace/teifs/issues/new?template=bug_report.yml):
  the version, your OS and disk type, the S3 client and the exact steps.
- **Test a client**: run your favourite S3 tool or app against TeiFS and tell us what
  worked and what didn't.
- **Suggest an idea** in [Discussions ▸ Ideas](https://github.com/teispace/teifs/discussions/categories/ideas).
- **Improve the docs** in the README or `docs/`.
- **Write code**: issues labelled
  [`good first issue`](https://github.com/teispace/teifs/labels/good%20first%20issue) and
  [`help wanted`](https://github.com/teispace/teifs/labels/help%20wanted) are a good start.

Security vulnerabilities are never reported in public: see [SECURITY.md](SECURITY.md).

## Before you start

- **Small fixes** (typos, obvious bugs, docs): open a pull request directly.
- **Anything larger** (a feature, a behaviour change, a new dependency, a change to the
  on-disk format): open an issue first so we can agree on the approach.
- Read [ARCHITECTURE](docs/ARCHITECTURE.md), [CONVENTIONS](docs/CONVENTIONS.md) and the
  [security model](docs/SECURITY_MODEL.md).

A few rules aren't negotiable, because people trust TeiFS with their files:

- **No `unsafe` code**, and no `unwrap` outside tests.
- **The on-disk format is a contract.** Changing what's written to disk means a new format
  version, an upgrade, and a fixture proving old drives still open
  ([ON_DISK_FORMAT.md](docs/ON_DISK_FORMAT.md)).
- **S3 behaviour matches AWS** unless plain files make that impossible, and then it's
  documented.
- **Tests with every change.**

## Development setup

You need [Rust](https://rustup.rs); the toolchain in `rust-toolchain.toml` installs itself.
For the S3 client tests you may also want the [AWS CLI](https://aws.amazon.com/cli/) and
[rclone](https://rclone.org).

```sh
git clone https://github.com/teispace/teifs.git
cd teifs
cargo test --workspace
cargo run -p teifs -- serve /tmp/drive
```

Before every commit, run everything CI checks:

```sh
cargo install cargo-nextest cargo-deny --locked   # once
cargo fmt --all
cargo xtask verify
```

## Pull requests

- Branch from `main`; one logical change per pull request.
- Title and commits follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat(store): …`, `fix(s3): …`). Pull requests are squash-merged, so the title becomes
  the commit and the changelog entry.
- Describe what changed, why, and how you tested it (including the S3 client, if any).
- CI must be green. A maintainer reviews every pull request.

## License

By contributing, you agree that your contribution is licensed under both the MIT and the
Apache-2.0 licenses, like the rest of TeiFS.
