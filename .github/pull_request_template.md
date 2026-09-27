## What and why

<!-- What does this change, and why? Link the issue: "Closes #123". -->

## How it was tested

<!-- Tests added, commands run (`cargo xtask verify`), S3 clients used, on which systems. -->

## Checklist

- [ ] The title is a [Conventional Commit](https://www.conventionalcommits.org/) (`feat(store): …`, `fix(s3): …`, `docs: …`).
- [ ] `cargo xtask verify` passes.
- [ ] Tests cover the change; a bug fix has a test that fails without it.
- [ ] Docs are updated where the change affects them (README, `docs/COMPATIBILITY.md`, `docs/ON_DISK_FORMAT.md`, `docs/SECURITY_MODEL.md`, `docs/ARCHITECTURE.md`, `AGENTS.md`).
- [ ] If anything written to disk changed: new format version, an upgrade, and a fixture drive.
- [ ] No secrets in logs, command-line arguments or fixtures.
