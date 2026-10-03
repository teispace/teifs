//! The tables against AWS's Service Authorization Reference for S3
//! (`https://servicereference.us-east-1.amazonaws.com/v1/s3/s3.json`), trimmed to what
//! matters here in `fixtures/s3-reference.json`: actions and their resource types,
//! each SDK operation's authorized actions, and the condition keys.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use teifs_policy::{ACTIONS, Facts, MINIO_ACTIONS, S3Key, TagKind, Target, authorizations};

fn reference() -> Value {
    serde_json::from_str(include_str!("fixtures/s3-reference.json")).expect("the fixture is JSON")
}

/// Operations the reference lists no S3 action for, which TeiFS still maps (why: in
/// `actions.rs`).
const OWN_MAPPINGS: &[&str] = &["RenameObject"];

/// Actions an operation's API page requires that the reference leaves out.
const DOCUMENTED: &[(&str, &str)] = &[
    // "You need the relevant read object (or version) permission."
    ("HeadObject", "s3:GetObjectVersion"),
    // x-amz-tagging-count: "when you have the relevant permission to read object tags".
    ("HeadObject", "s3:GetObjectTagging"),
    // "You must have s3:PutBucketABAC permission to perform this action."
    ("PutBucketAbac", "s3:PutBucketAbac"),
    ("GetBucketAbac", "s3:GetBucketAbac"),
    // CreateBucketConfiguration's Tags: "You must have the s3:TagResource permission".
    ("CreateBucket", "s3:TagResource"),
];

#[test]
fn actions_are_exactly_the_references() {
    let reference = reference();
    let expected: BTreeMap<String, Target> = reference["actions"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, resources)| {
            let resources: Vec<&str> = resources
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_str().unwrap())
                .collect();
            let target = if resources.contains(&"object") {
                Target::Object
            } else if resources.contains(&"bucket") {
                Target::Bucket
            } else if resources.is_empty() {
                Target::Account
            } else {
                Target::Other
            };
            (format!("s3:{name}"), target)
        })
        .collect();
    let ours: BTreeMap<String, Target> = ACTIONS
        .iter()
        .map(|(name, target)| ((*name).to_owned(), *target))
        .collect();
    assert_eq!(ours, expected);
    assert!(
        ACTIONS.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "sorted, for binary search"
    );
    for (action, _) in MINIO_ACTIONS {
        assert!(!ours.contains_key(*action), "{action} is S3's own");
    }
}

/// Every combination of the facts that change what an operation needs.
fn every_facts() -> impl Iterator<Item = Facts> {
    (0..1_u32 << 10).map(|bits| {
        let bit = |n: u32| bits & (1 << n) != 0;
        Facts {
            version_id: bit(0),
            source_version_id: bit(1),
            tagging: bit(2),
            acl: bit(3),
            retention: bit(4),
            legal_hold: bit(5),
            bypass_governance: bit(6),
            object_lock: bit(7),
            ownership: bit(8),
            bucket_tags: bit(9),
            // MinIO's replication requests (not S3's), checked on their own below.
            replication: false,
            replica_marker: false,
        }
    })
}

#[test]
fn every_operation_needs_what_the_reference_lists() {
    let reference = reference();
    let operations = reference["operations"].as_object().unwrap();
    assert!(operations.len() >= 116, "the SDK's S3 operations");
    let known: BTreeSet<&str> = ACTIONS.iter().map(|(name, _)| *name).collect();
    for (operation, listed) in operations {
        let listed: BTreeSet<String> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|a| format!("s3:{}", a.as_str().unwrap()))
            .chain(
                DOCUMENTED
                    .iter()
                    .filter(|(op, _)| op == operation)
                    .map(|(_, action)| (*action).to_owned()),
            )
            .collect();
        let mapped = authorizations(operation, &Facts::default());
        if listed.is_empty() && !OWN_MAPPINGS.contains(&operation.as_str()) {
            assert!(
                mapped.is_none(),
                "{operation}: nothing to grant, so only the root user may"
            );
            continue;
        }
        assert!(mapped.is_some(), "{operation} has no mapping");
        let mut used = BTreeSet::new();
        for facts in every_facts() {
            let needs = authorizations(operation, &facts).unwrap();
            assert!(!needs.is_empty(), "{operation}");
            assert!(
                needs.iter().any(|a| a.required),
                "{operation}: something is required"
            );
            for need in needs.iter() {
                assert!(
                    known.contains(need.action),
                    "{operation}: {} isn't an S3 action",
                    need.action
                );
                assert_ne!(need.target, Target::Other, "{operation}: {}", need.action);
                if !OWN_MAPPINGS.contains(&operation.as_str()) {
                    assert!(
                        listed.contains(need.action),
                        "{operation} needs {}, which the reference doesn't list",
                        need.action
                    );
                }
                used.insert(need.action.to_owned());
            }
        }
        if !OWN_MAPPINGS.contains(&operation.as_str()) {
            assert_eq!(
                used, listed,
                "{operation}: every listed action applies to some request"
            );
        }
    }
    assert!(authorizations("NoSuchOperation", &Facts::default()).is_none());
}

/// What `operation` needs: action, target, required.
fn actions(operation: &str, facts: Facts) -> Vec<(&'static str, Target, bool)> {
    authorizations(operation, &facts)
        .unwrap()
        .iter()
        .map(|a| (a.action, a.target, a.required))
        .collect()
}

#[test]
fn versions_tags_and_locks_change_the_action() {
    let none = Facts::default();
    let version = Facts {
        version_id: true,
        ..none
    };
    assert_eq!(
        actions("GetObject", none)[0],
        ("s3:GetObject", Target::Object, true)
    );
    assert_eq!(
        actions("GetObject", version)[0],
        ("s3:GetObjectVersion", Target::Object, true)
    );
    assert_eq!(
        actions("DeleteObject", version),
        [("s3:DeleteObjectVersion", Target::Object, true)]
    );
    assert_eq!(
        actions("GetObjectTagging", version),
        [("s3:GetObjectVersionTagging", Target::Object, true)]
    );
    assert_eq!(
        actions(
            "PutObject",
            Facts {
                tagging: true,
                retention: true,
                ..none
            }
        ),
        [
            ("s3:PutObject", Target::Object, true),
            ("s3:PutObjectTagging", Target::Object, true),
            ("s3:PutObjectRetention", Target::Object, true),
        ]
    );
    assert_eq!(
        actions(
            "CopyObject",
            Facts {
                source_version_id: true,
                ..none
            }
        ),
        [
            ("s3:GetObjectVersion", Target::Source, true),
            ("s3:PutObject", Target::Object, true)
        ]
    );
    assert_eq!(
        actions(
            "DeleteObjects",
            Facts {
                bypass_governance: true,
                ..none
            }
        ),
        [
            ("s3:DeleteObject", Target::Object, true),
            ("s3:BypassGovernanceRetention", Target::Object, true)
        ]
    );
}

#[test]
fn replicas_from_another_server_need_minios_replication_actions() {
    let none = Facts::default();
    let replication = Facts {
        replication: true,
        ..none
    };
    assert_eq!(
        actions("PutObject", replication),
        [
            ("s3:PutObject", Target::Object, true),
            ("s3:ReplicateObject", Target::Object, true)
        ]
    );
    // A replicated delete marker names its id, but removes no version.
    assert_eq!(
        actions(
            "DeleteObject",
            Facts {
                version_id: true,
                replica_marker: true,
                ..replication
            }
        ),
        [
            ("s3:DeleteObject", Target::Object, true),
            ("s3:ReplicateDelete", Target::Object, true)
        ]
    );
    // The marker header alone, from anyone else, changes nothing.
    assert_eq!(
        actions(
            "DeleteObject",
            Facts {
                version_id: true,
                replica_marker: true,
                ..none
            }
        ),
        [("s3:DeleteObjectVersion", Target::Object, true)]
    );
}

#[test]
fn buckets_the_account_and_renames() {
    let none = Facts::default();
    assert_eq!(
        actions("ListBuckets", none),
        [("s3:ListAllMyBuckets", Target::Account, true)]
    );
    assert_eq!(
        actions("HeadBucket", none),
        [("s3:ListBucket", Target::Bucket, true)]
    );
    assert_eq!(
        actions("RenameObject", none),
        [
            ("s3:GetObject", Target::Source, true),
            ("s3:DeleteObject", Target::Source, true),
            ("s3:PutObject", Target::Object, true),
        ]
    );
    assert_eq!(
        actions(
            "CreateBucket",
            Facts {
                object_lock: true,
                ..none
            }
        ),
        [
            ("s3:CreateBucket", Target::Bucket, true),
            ("s3:PutBucketObjectLockConfiguration", Target::Bucket, true),
            ("s3:PutBucketVersioning", Target::Bucket, true),
        ]
    );
    // Only adds headers: not required.
    assert!(
        actions("HeadObject", none)
            .iter()
            .skip(1)
            .all(|(_, _, required)| !required)
    );
}

#[test]
fn condition_keys_are_the_references() {
    let reference = reference();
    let listed: BTreeSet<String> = reference["conditionKeys"]
        .as_object()
        .unwrap()
        .keys()
        .map(|name| name.split('/').next().unwrap().to_owned())
        .collect();
    let ours: BTreeSet<String> = S3Key::ALL
        .iter()
        .map(|k| k.name().to_owned())
        .chain(TagKind::ALL.iter().map(|k| k.name().to_owned()))
        .chain(["aws:TagKeys".to_owned()])
        .filter(|name| name.starts_with("s3:") || listed.contains(name))
        .collect();
    assert_eq!(ours, listed);
}

#[test]
fn a_browser_upload_needs_what_a_put_does() {
    for facts in every_facts() {
        assert_eq!(
            actions("PostObject", facts),
            actions("PutObject", facts),
            "{facts:?}"
        );
    }
}
