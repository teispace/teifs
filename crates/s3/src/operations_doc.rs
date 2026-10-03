//! COMPATIBILITY.md's list of every S3 operation, generated from the operations AWS's
//! Service Authorization Reference lists and the ones `Drive` serves (the `S3` methods
//! it implements; s3s answers the rest `501 NotImplemented`).

use std::{collections::BTreeSet, fmt::Write as _};

/// The `S3` methods `Drive` implements, as S3 operation names (`list_objects_v2`:
/// `ListObjectsV2`).
fn served() -> BTreeSet<String> {
    let source = include_str!("drive.rs");
    let (_, body) = source
        .split_once("\nimpl S3 for Drive {\n")
        .expect("Drive's S3 implementation");
    let body = &body[..body.find("\n}\n").expect("its end")];
    body.lines()
        .filter_map(|line| line.strip_prefix("    async fn "))
        .filter_map(|rest| rest.split_once('('))
        .map(|(name, _)| {
            name.split('_')
                .map(|word| {
                    let mut chars = word.chars();
                    chars.next().map_or_else(String::new, |first| {
                        first.to_ascii_uppercase().to_string() + chars.as_str()
                    })
                })
                .collect()
        })
        .collect()
}

/// The operations AWS lists.
fn listed() -> BTreeSet<String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../policy/tests/fixtures/s3-reference.json"
    );
    let reference: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    reference["operations"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect()
}

fn reference() -> String {
    let served = served();
    let mut out = String::from("| Operation | TeiFS |\n|---|---|\n");
    for operation in listed().union(&served) {
        let status = if served.contains(operation) {
            "Served"
        } else {
            "Not served"
        };
        let _ = writeln!(out, "| {operation} | {status} |");
    }
    out
}

#[test]
fn every_served_operation_is_a_real_one() {
    let served = served();
    assert!(served.len() > 80, "{served:?}");
    // PostObject is a browser's form upload: AWS's reference lists it as PutObject.
    let listed = listed();
    let unknown: Vec<_> = served
        .difference(&listed)
        .filter(|op| *op != "PostObject")
        .collect();
    assert!(unknown.is_empty(), "not S3 operations: {unknown:?}");
}

#[test]
fn the_operations_list_is_current() {
    const START: &str = "<!-- generated: operations -->\n";
    const END: &str = "<!-- end generated -->";
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/COMPATIBILITY.md");
    let doc = std::fs::read_to_string(path).unwrap();
    let (before, rest) = doc.split_once(START).expect("the start marker");
    let (_, after) = rest.split_once(END).expect("the end marker");
    let current = format!("{before}{START}{}{END}{after}", reference());
    if std::env::var_os("UPDATE_DOCS").is_some() {
        std::fs::write(path, &current).unwrap();
        return;
    }
    assert!(
        doc == current,
        "docs/COMPATIBILITY.md's operations are out of date: run this test with UPDATE_DOCS=1"
    );
}
