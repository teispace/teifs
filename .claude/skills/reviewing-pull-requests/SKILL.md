---
name: reviewing-pull-requests
description: Reviews a TeiFS pull request against the project's bar (S3 correctness against AWS, atomic and durable writes, key safety, the on-disk format contract, security rules, tests and docs) and reports findings ranked by severity. Use when asked to review a pull request, a branch or a diff.
allowed-tools: Bash(gh pr view *) Bash(gh pr diff *) Bash(gh pr checks *) Bash(git diff *) Bash(git log *)
---

# Reviewing a pull request

Read the description, the diff and the CI results (`gh pr view`, `gh pr diff`,
`gh pr checks`). Then check, in this order:

1. **Data safety.** Every change to a file happens stage → sync → rename → sync folder →
   index row, under the commit lock (`inner.lock()`). No path is built from an unchecked
   key. No new way for a crash to leave a half-written object or a row that doesn't match
   its file.
2. **On-disk format.** Anything new in `.teifs/` or a schema change follows the
   `changing-on-disk-format` skill: migration appended (never edited), fixture from the
   previous release, `docs/ON_DISK_FORMAT.md` updated. Existing fixtures untouched.
3. **Security.** The rules in `docs/SECURITY_MODEL.md`: authorization before anything
   else, no secrets in logs or `Debug`, bounded input, no `unsafe`, no `unwrap` outside
   tests.
4. **S3 behaviour.** Matches AWS's API reference (status codes, error codes, headers,
   XML). Deviations are forced by plain files and documented in
   `docs/COMPATIBILITY.md`.
5. **Tests.** Store tests plus an AWS SDK test in `crates/server/tests/sdk.rs` for S3
   behaviour; a bug fix has a test that fails without it.
6. **Docs and changelog** match the change (the `writing-docs` skill).
7. **Code.** Follows `docs/CONVENTIONS.md` and the surrounding code; no dead code, no new
   dependency without a reason.

Report findings most severe first, each with the file and line, what's wrong, and a
concrete failure scenario. Say plainly when there are none.
