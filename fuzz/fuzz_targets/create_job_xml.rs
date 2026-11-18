//! S3 Batch Operations' `CreateJobRequest` bodies (S3 Control), read and checked.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| teifs_s3::fuzzing::create_job_xml(data));
