---
name: adding-s3-operations
description: Adds or changes an S3 operation in TeiFS (the s3s S3 trait in crates/s3/src/drive.rs, the store method behind it, error mapping, an AWS SDK end-to-end test and the compatibility docs). Use when implementing an S3 API such as tagging, CORS or GetObjectAttributes, or when changing how an existing one behaves.
---

# Adding an S3 operation

TeiFS implements the `S3` trait from s3s. s3s parses the request, checks the signature and
builds the typed input (`dto::<Operation>Input`); TeiFS returns `dto::<Operation>Output`.
An operation TeiFS doesn't implement answers `NotImplemented` automatically.

## Checklist

1. **Read AWS's API reference** for the operation (request, response, errors). Match it.
   Where plain files make that impossible, the difference goes into
   `docs/COMPATIBILITY.md` ("Differences from AWS, by design").
2. **Store first** (`crates/store/src/lib.rs`, or a new module next to `multipart.rs`
   for a larger feature): a method on `Store` that takes plain Rust types, runs file and
   database work inside `self.blocking(…)`, and changes a file and its index row only while
   holding the commit lock (`inner.lock()`). New SQL goes in `crates/meta/src/index.rs`
   (per object) or `crates/meta/src/system.rs` (per bucket or drive).
3. **Errors**: a new failure is a `StoreError` variant (`crates/store/src/error.rs`) and
   gets its S3 error in `from_store` (`crates/s3/src/errors.rs`). TeiFS-only codes start
   with `XTeiFS`.
4. **The S3 method** in `impl S3 for Drive` (`crates/s3/src/drive.rs`), in the order the
   file already uses (buckets, objects, listings, multipart). Keep it thin: read the
   input, call the store with `.s3()?`, build the output. The smallest example:

   ```rust
   async fn get_bucket_versioning(
       &self,
       req: S3Request<dto::GetBucketVersioningInput>,
   ) -> S3Result<S3Response<dto::GetBucketVersioningOutput>> {
       // Versioning was never enabled: an empty answer, as S3 gives.
       self.store.head_bucket(&req.input.bucket).await.s3()?;
       Ok(S3Response::new(dto::GetBucketVersioningOutput::default()))
   }
   ```

5. **Tests**:
   - store behaviour in `crates/store/src/tests.rs`;
   - the operation end to end with the official AWS SDK in `crates/server/tests/sdk.rs`
     (use `start()` and `client(&server, SECRET_KEY)`; check the error code with
     `err.code()`, and check the file on disk through `server.dir` when it matters).
6. **Anything new on disk** (a column, a table, a file in `.teifs/`): follow the
   `changing-on-disk-format` skill.
7. **Docs**: the operation's row in `docs/COMPATIBILITY.md`, the README's support table
   if it's a headline feature, `CHANGELOG.md` under "Unreleased".
8. Run the `verifying-changes` skill, including a real client (AWS CLI or rclone).
