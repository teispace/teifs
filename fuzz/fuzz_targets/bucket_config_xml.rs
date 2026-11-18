//! Bucket configuration bodies (lifecycle, CORS, replication, tagging, Object Lock,
//! inventory, logging, notifications), read by s3s and checked as TeiFS checks them.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| teifs_s3::fuzzing::bucket_config_xml(data));
