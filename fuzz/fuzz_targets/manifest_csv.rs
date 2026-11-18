//! S3 Batch Operations' CSV manifests: lines, quoted columns, URL-encoded keys.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| teifs_s3::fuzzing::manifest_csv(data));
