---
name: writing-docs
description: Writes or updates TeiFS documentation (README, docs/COMPATIBILITY, ON_DISK_FORMAT, SECURITY_MODEL, ADMIN_API, ARCHITECTURE, CONVENTIONS, AGENTS.md, CHANGELOG) so it's true, specific and in the project's plain style. Use whenever a change affects what users or contributors read, and when asked to write or fix docs.
---

# Writing docs

## Which doc

| The change affects | Update |
|---|---|
| What S3 clients see | `docs/COMPATIBILITY.md`, and the README's support table for headline features |
| Anything written to disk | `docs/ON_DISK_FORMAT.md` |
| A security rule or what an attacker can reach | `docs/SECURITY_MODEL.md` |
| Crates, modules, how a request flows | `docs/ARCHITECTURE.md`, and the layout in `AGENTS.md` |
| How code is written | `docs/CONVENTIONS.md` |
| Commands or flags | the README's command table |
| The admin API, S3 Control, or the IAM/STS route | `docs/ADMIN_API.md`: its prose by hand; its endpoint tables are generated from `ENDPOINTS` in `crates/s3/src/routes.rs` (each entry's `about`), rewritten with `UPDATE_DOCS=1 cargo nextest run -p teifs-s3 -E 'test(admin_api_reference)'`, never edited |
| Anything users notice | `CHANGELOG.md` under "Unreleased" |

## Rules

- **True now.** Describe the code as it is. Planned behaviour is marked as planned, and
  only in docs that already track plans (COMPATIBILITY, SECURITY_MODEL).
- **Claims need evidence.** "Supported" in COMPATIBILITY means a test proves it; say
  which.
- **Answer first.** Lead with what the reader needs; details after.
- **Plain, direct English.** Short sentences, active voice, no marketing words. Say what
  happens and what to do.
- **Name real things.** Paths in backticks (`crates/store/src/format.rs`); `cargo xtask
  docs` fails if a named path doesn't exist, so fix the doc when code moves.
- **No private references**: no internal plan or decision ids, no links to anything
  outside the repository that readers can't open.
