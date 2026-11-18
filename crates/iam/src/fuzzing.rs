//! Entry points for the fuzz targets in `fuzz/` (the `fuzzing` feature): the SAML parser,
//! which reads what an identity provider's user brings. Not an API: nothing but the fuzz
//! targets uses it, and it may change with them.

use crate::saml::{c14n, metadata, xml};

/// A document read as a SAML response or metadata is, then canonicalized as a signature
/// check does (with and without comments).
pub fn saml_xml(text: &str) {
    if let Ok(root) = xml::parse(text) {
        for comments in [false, true] {
            let options = c14n::Options {
                comments,
                ..c14n::Options::default()
            };
            let _ = c14n::canonicalize(&root, &options);
        }
    }
    let _ = metadata::parse(text);
}
