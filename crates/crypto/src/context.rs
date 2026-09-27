//! Encryption contexts: key-value pairs a sealed key is bound to.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The pairs a data key is sealed under; unsealing needs the same pairs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Context(BTreeMap<String, String>);

impl Context {
    /// The context of an object's data key: its drive, bucket and object ids.
    #[must_use]
    pub fn object(drive: &str, bucket_id: &str, object_id: &str) -> Self {
        Self(BTreeMap::from([
            ("teifs:drive".to_owned(), drive.to_owned()),
            ("teifs:bucket".to_owned(), bucket_id.to_owned()),
            ("teifs:object".to_owned(), object_id.to_owned()),
        ]))
    }

    /// Adds a pair (a client's SSE-KMS context). TeiFS's own pairs can't be replaced.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        if !key.starts_with("teifs:") {
            self.0.insert(key, value.into());
        }
        self
    }

    /// The pairs.
    #[must_use]
    pub fn pairs(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    /// The canonical bytes: pairs in key order, each as length-prefixed key and value.
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (key, value) in &self.0 {
            for part in [key, value] {
                let len = u32::try_from(part.len()).expect("context values are short");
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(part.as_bytes());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bytes_are_ordered_and_unambiguous() {
        let a = Context::object("d", "b", "o").with("z", "1").with("a", "2");
        let b = Context::object("d", "b", "o").with("a", "2").with("z", "1");
        assert_eq!(a.canonical(), b.canonical());
        // Length prefixes keep ("ab", "c") and ("a", "bc") apart.
        let x = Context::default().with("ab", "c");
        let y = Context::default().with("a", "bc");
        assert_ne!(x.canonical(), y.canonical());
    }

    #[test]
    fn own_pairs_cant_be_overridden() {
        let ctx = Context::object("d", "b", "o").with("teifs:object", "other");
        assert_eq!(ctx.pairs()["teifs:object"], "o");
    }
}
