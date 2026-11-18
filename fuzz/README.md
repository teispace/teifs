# Fuzz targets

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets (libFuzzer) for the code
that reads what clients and identity providers send. Each calls a parser as the server
does, so a crash, a hang or a runaway allocation here is one a request could cause.

| Target | What it reads |
|---|---|
| `object_key` | `ObjectKey::parse`; a key it takes must map to plain names inside the bucket |
| `policy_json` | bucket, identity and trust policies, then evaluates them |
| `bucket_config_xml` | lifecycle, CORS, replication, tagging, Object Lock, inventory, logging and notification bodies, read by s3s and checked by TeiFS |
| `create_job_xml` | S3 Batch Operations' `CreateJobRequest` |
| `manifest_csv` | Batch Operations' CSV manifests |
| `aws_chunked` | `aws-chunked` upload bodies, signed and unsigned, as s3s decodes them |
| `saml_xml` | TeiFS's XML reader for SAML responses and metadata, and exclusive canonicalization |
| `config_kv` | MinIO-style configuration text |

The targets live in their own workspace (nightly Rust): `cargo xtask verify`, the
workspace's lock file and cargo-deny don't cover them. The parsers they call are reached
through the `fuzzing` feature of `teifs-s3` and `teifs-iam` (`crates/s3/src/fuzzing.rs`,
`crates/iam/src/fuzzing.rs`), which nothing else turns on.

## Running

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
fuzz/run.sh 60 object_key        # one target for a minute
fuzz/run.sh 600                  # every target, ten minutes each
```

`fuzz/run.sh` copies the workspace's `Cargo.lock` so the targets build the same
dependencies as the server, starts each target from its seeds (`fuzz/seeds`, a few
valid inputs) and grows its corpus under `fuzz/corpus/<target>/`. The XML targets use
`fuzz/xml.dict`.

CI (`.github/workflows/fuzz.yml`) runs every target for ten minutes each night, keeping
the corpus between nights, and for ten seconds each on a pull request that changes a
target or a parser one calls.

## A crash

The failing input is in `fuzz/artifacts/<target>/` (in CI, the run's `fuzz-crashes`
artifact). Reproduce and shrink it with

```sh
cargo +nightly fuzz run -O <target> fuzz/artifacts/<target>/crash-…
cargo +nightly fuzz tmin -O <target> fuzz/artifacts/<target>/crash-…
```

then fix it with a unit test beside the parser that fails without the fix, and add the
input to `fuzz/seeds/<target>/` so the target keeps trying it.
