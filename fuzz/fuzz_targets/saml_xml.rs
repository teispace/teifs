//! TeiFS's own XML reader for SAML responses and metadata, and the canonicalization a
//! signature check applies to what it reads.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| teifs_iam::fuzzing::saml_xml(text));
