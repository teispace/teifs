//! MinIO-style server configuration text (`mc admin config set` and imports).
#![no_main]

use libfuzzer_sys::fuzz_target;
use teifs_types::config_kv::ConfigKv;

fuzz_target!(|text: &str| {
    let _ = ConfigKv::parse(text);
});
