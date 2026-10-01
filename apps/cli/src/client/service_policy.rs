//! Letting one of S3's services (log delivery, S3 Inventory) write into a bucket, with a
//! statement in its bucket policy as the S3 console adds it.

use aws_sdk_s3::{Client, error::ProvideErrorMetadata};
use serde_json::{Value, json};

use super::Error;

/// What a service may write, and for which bucket.
pub(super) struct Grant<'a> {
    /// The statement's id: one per service and source bucket.
    pub sid: String,
    /// The service's principal.
    pub service: &'static str,
    /// The bucket written for (`aws:SourceArn`).
    pub source: &'a str,
    /// The bucket written into, and the prefix of what's written.
    pub target: (&'a str, &'a str),
    /// The account (`aws:SourceAccount`).
    pub account: &'a str,
    /// The canned ACL the service writes with (`s3:x-amz-acl`), if it sends one.
    pub acl: Option<&'static str>,
}

/// Adds `grant`'s statement to its target's bucket policy, unless it has one of that id
/// already.
pub(super) async fn let_in(client: &Client, grant: &Grant<'_>) -> Result<(), Error> {
    let target = grant.target.0;
    let current = match client.get_bucket_policy().bucket(target).send().await {
        Ok(out) => out.policy().map(str::to_owned),
        Err(e)
            if e.as_service_error().and_then(ProvideErrorMetadata::code)
                == Some("NoSuchBucketPolicy") =>
        {
            None
        }
        Err(e) => {
            return Err(Error::s3(
                format!("can't read the bucket policy of {target}"),
                &e,
            ));
        }
    };
    let Some(policy) = with_statement(current.as_deref(), grant)? else {
        return Ok(());
    };
    client
        .put_bucket_policy()
        .bucket(target)
        .policy(policy)
        .send()
        .await
        .map_err(|e| Error::s3(format!("can't let {} into {target}", grant.service), &e))?;
    Ok(())
}

/// The policy `current` with `grant`'s statement added; `None` when it has one already.
fn with_statement(current: Option<&str>, grant: &Grant<'_>) -> Result<Option<String>, Error> {
    let (target, prefix) = grant.target;
    let mut equals = json!({"aws:SourceAccount": grant.account});
    if let Some(acl) = grant.acl {
        equals["s3:x-amz-acl"] = json!(acl);
    }
    let statement = json!({
        "Sid": grant.sid,
        "Effect": "Allow",
        "Principal": {"Service": grant.service},
        "Action": "s3:PutObject",
        "Resource": format!("arn:aws:s3:::{target}/{prefix}*"),
        "Condition": {
            "ArnLike": {"aws:SourceArn": format!("arn:aws:s3:::{}", grant.source)},
            "StringEquals": equals,
        },
    });
    let mut policy: Value = match current {
        None => json!({"Version": "2012-10-17", "Statement": []}),
        Some(text) => serde_json::from_str(text)
            .map_err(|e| Error::usage(format!("the bucket policy of {target} isn't JSON: {e}")))?,
    };
    let statements = match policy.get_mut("Statement") {
        Some(Value::Array(statements)) => statements,
        Some(one) => {
            let one = one.take();
            policy["Statement"] = Value::Array(vec![one]);
            policy["Statement"]
                .as_array_mut()
                .expect("just made an array")
        }
        None => {
            policy["Statement"] = json!([]);
            policy["Statement"]
                .as_array_mut()
                .expect("just made an array")
        }
    };
    if statements
        .iter()
        .any(|s| s.get("Sid") == Some(&json!(grant.sid)))
    {
        return Ok(None);
    }
    statements.push(statement);
    Ok(Some(policy.to_string()))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;

    fn grant<'a>(source: &'a str, target: (&'a str, &'a str)) -> Grant<'a> {
        Grant {
            sid: format!("TeiFSAccessLogs-{source}"),
            service: "logging.s3.amazonaws.com",
            source,
            target,
            account: "123456789012",
            acl: None,
        }
    }

    #[test]
    fn the_services_statement_is_added_once() {
        let added = with_statement(None, &grant("app", ("logs", "app/")))
            .unwrap()
            .unwrap();
        let policy: Value = serde_json::from_str(&added).unwrap();
        let statement = &policy["Statement"][0];
        assert_eq!(
            statement["Principal"]["Service"],
            "logging.s3.amazonaws.com"
        );
        assert_eq!(statement["Resource"], "arn:aws:s3:::logs/app/*");
        assert_eq!(
            statement["Condition"]["ArnLike"]["aws:SourceArn"],
            "arn:aws:s3:::app"
        );
        assert_eq!(
            statement["Condition"]["StringEquals"],
            json!({"aws:SourceAccount": "123456789012"})
        );
        assert_eq!(
            with_statement(Some(&added), &grant("app", ("logs", "app/"))).unwrap(),
            None
        );
        // Another source's goes next to it; a lone statement becomes a list.
        let lone = r#"{"Version":"2012-10-17","Statement":{"Sid":"x","Effect":"Deny","Principal":"*","Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::logs"}}"#;
        let both = with_statement(Some(lone), &grant("web", ("logs", "")))
            .unwrap()
            .unwrap();
        let both: Value = serde_json::from_str(&both).unwrap();
        assert_eq!(both["Statement"][0]["Sid"], "x");
        assert_eq!(both["Statement"][1]["Sid"], "TeiFSAccessLogs-web");
        assert_eq!(both["Statement"][1]["Resource"], "arn:aws:s3:::logs/*");
        assert!(with_statement(Some("{"), &grant("a", ("b", ""))).is_err());
        let none = r#"{"Version":"2012-10-17"}"#;
        let added = with_statement(Some(none), &grant("a", ("b", "")))
            .unwrap()
            .unwrap();
        let added: Value = serde_json::from_str(&added).unwrap();
        assert_eq!(added["Statement"][0]["Sid"], "TeiFSAccessLogs-a");
    }

    #[test]
    fn a_canned_acl_is_a_condition() {
        let mut inventory = grant("app", ("reports", ""));
        inventory.acl = Some("bucket-owner-full-control");
        let added = with_statement(None, &inventory).unwrap().unwrap();
        let policy: Value = serde_json::from_str(&added).unwrap();
        assert_eq!(
            policy["Statement"][0]["Condition"]["StringEquals"],
            json!({
                "aws:SourceAccount": "123456789012",
                "s3:x-amz-acl": "bucket-owner-full-control",
            })
        );
    }
}
