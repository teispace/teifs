//! `ObjectKey::parse`: every key a request names. A key it takes must stay inside its
//! bucket: a relative path of plain names, none of them TeiFS's staging folder at the top.
#![no_main]

use std::path::Component;

use libfuzzer_sys::fuzz_target;
use teifs_types::ObjectKey;

fuzz_target!(|key: &str| {
    let Ok(parsed) = ObjectKey::parse(key) else {
        return;
    };
    assert_eq!(parsed.as_str(), key);
    let rel = parsed.rel();
    assert!(rel.is_relative(), "{key:?} maps to {rel:?}");
    assert!(rel.components().next().is_some(), "{key:?} maps to nothing");
    for (i, part) in rel.components().enumerate() {
        let Component::Normal(name) = part else {
            panic!("{key:?} maps to {rel:?}, with {part:?}");
        };
        assert!(
            i > 0 || name != ".teifs-tmp",
            "{key:?} names the staging folder"
        );
    }
    assert_eq!(parsed.is_folder(), key.ends_with('/'));
    let _ = parsed.check_portable();
});
