# Security Policy

TeiFS stores people's files and answers requests from the network, so we take every
report seriously and are grateful to the people who make them.

## Supported versions

| Version | Supported |
|---|---|
| The latest release | Yes |
| Anything older | No: update to the latest release |

Before 1.0, fixes ship only in a new release.

## Reporting a vulnerability

**Please don't report security issues in public issues, discussions or pull requests.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/teispace/teifs/security/advisories/new).
If you can't use GitHub, email **info@teispace.com** with "Security" in the subject.

A helpful report includes:

- the affected version and operating system;
- what an attacker can do, and what they need first (for example, network access to the
  endpoint, or credentials with limited rights);
- steps to reproduce, or a proof of concept;
- any idea you have for a fix.

Never include real credentials or someone else's data.

## What happens next

1. We acknowledge your report within **3 business days**.
2. We confirm and assess it within **10 business days**, and keep you updated as we work
   on a fix.
3. We agree on a disclosure date with you. We aim to release a fix within **90 days**,
   much sooner for severe issues.
4. We publish a GitHub security advisory, with a CVE where it applies, and credit you
   unless you'd rather stay anonymous. Every fix comes with a regression test.

## Scope

In scope: the `teifs` server and command, its crates, the release artifacts and container
images, and the on-disk format (anything that lets a request read, change or destroy
data it shouldn't, or corrupt a drive).

Out of scope:

- attacks that need an already-compromised machine or the account TeiFS runs as;
- volumetric denial of service, spam and social engineering;
- reports from automated scanners without a demonstrated impact;
- vulnerabilities in third-party S3 clients.

## Safe harbor

We won't pursue legal action against anyone who researches and reports a vulnerability in
good faith under this policy: who avoids privacy violations, data destruction and service
disruption, tests only against their own installations and data, and gives us reasonable
time to fix the issue before disclosing it.

## How TeiFS protects users

The design is documented in [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).
