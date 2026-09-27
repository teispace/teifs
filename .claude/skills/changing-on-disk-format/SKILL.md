---
name: changing-on-disk-format
description: Changes what TeiFS writes to disk (the .teifs folder, index.db or system.db schemas, the file layout) safely, with a format version bump or a schema migration, an upgrade, a fixture drive from the previous release and the ON_DISK_FORMAT spec. Use for any new table or column, new file in .teifs, or change to how objects map to files.
---

# Changing the on-disk format

Every release must open every drive any earlier release wrote. The rules are in
`docs/ON_DISK_FORMAT.md`; `crates/store/src/format.rs` enforces them and
`crates/store/tests/format.rs` proves them.

## Which kind of change is it?

| Change | What it needs |
|---|---|
| A new table or column in `index.db` or `system.db` that old releases can ignore | A schema migration only (step 2). A newer schema makes older releases refuse the database, which is the safe outcome |
| Anything that changes the meaning of existing data, the file layout, or files in `.teifs/` | A new format version (steps 1–5) |

## Checklist

1. **Fixture first.** Before changing code, write a drive with the current release (the
   AWS CLI against `cargo run -p teifs -- serve <dir>`: buckets, a multipart object, a
   folder marker, user metadata, an unfinished upload). Package it as
   `crates/store/tests/fixtures/format-<current>.tar.gz` with a
   `format-<current>.json` manifest (objects, uploads and each file's `mtime_ns`, like
   `format-0.json`). Never modify an existing fixture.
2. **Schema migration**: append a new entry to `MIGRATIONS` in
   `crates/meta/src/index.rs` or `crates/meta/src/system.rs`. Never edit a released entry.
   Migrations run in one transaction.
3. **Format version**: bump `FORMAT` in `crates/store/src/format.rs` and add an
   `upgrade_from_<n>` step. Copy the metadata to `.teifs/backups/pre-format-<new>/` first
   (`teifs_meta::backup`), make the change, and write `format.json` last: it's the commit
   point. An upgrade must be safe to run again after a crash at any step.
4. **Tests** in `crates/store/tests/format.rs`: the new fixture upgrades with everything
   intact (`assert_intact`), an interrupted upgrade is redone, and the previous fixtures
   still pass.
5. **Spec**: update `docs/ON_DISK_FORMAT.md` (the layout, the tables, the upgrade table
   and how to go back) in the same pull request.
6. Run the `verifying-changes` skill.
