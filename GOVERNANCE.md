# Governance

TeiFS is an open-source project maintained by [Teispace](https://github.com/teispace).
This document describes how the project is run and how decisions are made.

## Roles

- **Users** use TeiFS and help by reporting bugs, asking and answering questions, and
  sharing ideas.
- **Contributors** have had a pull request merged, or help regularly in issues, discussions,
  docs or translations.
- **Triagers** label and route issues, reproduce bugs and help keep discussions useful. They
  have the GitHub Triage role.
- **Maintainers** review and merge pull requests, cut releases, set the direction and enforce
  the [Code of Conduct](CODE_OF_CONDUCT.md). They have write access to the repository.

## Maintainers

| Name | GitHub |
|---|---|
| Krishna Adhikari (lead) | [@TheKAdhikari](https://github.com/TheKAdhikari) |

## Decision making

Most decisions are made in the open, on GitHub, by consensus:

- **Everyday changes** are decided in the pull request. A maintainer's approval and green CI
  are enough to merge.
- **Larger changes** (a new feature area, a change to the architecture, the security model,
  the on-disk format, or a new runtime dependency) start as an
  issue labelled `proposal`. It describes the problem, the options considered and the
  proposed design. Anyone can comment. A maintainer records the outcome in the issue, which
  the implementing pull requests link to.
- **Ideas** that aren't ready for a proposal live in
  [Discussions ▸ Ideas](https://github.com/teispace/teifs/discussions/categories/ideas).

When consensus isn't reached, the lead maintainer decides, and explains why in the issue.

## Planning

What's being worked on for upcoming releases is tracked with
[milestones](https://github.com/teispace/teifs/milestones). An issue without a
milestone is welcome but not scheduled; a pull request for it is still welcome after the
approach is agreed.

## Becoming a triager or maintainer

Contributors who help consistently and constructively over time, and show good judgement
about the project's quality and security bar, may be invited by the maintainers to become
triagers, and later maintainers. You can also ask. Maintainers who are no longer active may
step down, or be moved to emeritus status after six months without activity.

## Changes to this document

Changes to governance are proposed in a pull request and need approval from the lead
maintainer.
