//! The policies `teifs admin user` and `teifs admin role` give: a preset for one or
//! more buckets, or a file.

use clap::Args;
use serde_json::{Value, json};

use crate::error::{Error, Kind};

/// The inline policy `user add`, `user policy`, `role add` and `role policy` set.
pub const POLICY_NAME: &str = "teifs-access";

/// What a user or role may do.
#[derive(Args)]
pub struct PolicyArgs {
    /// `readonly` (read and list), `readwrite` (all of S3), `admin` (everything: IAM
    /// and the admin API too), or a file with an IAM policy document.
    #[arg(long)]
    pub policy: String,
    /// Only this bucket, for `readonly` and `readwrite` (repeatable).
    #[arg(long = "bucket", value_name = "BUCKET")]
    buckets: Vec<String>,
}

impl PolicyArgs {
    /// The policy document: a preset's, or the file's.
    pub fn document(&self) -> Result<String, Error> {
        let preset = |actions: Value| {
            let statements = if self.buckets.is_empty() {
                json!([{"Effect": "Allow", "Action": actions, "Resource": "*"}])
            } else {
                let resources: Vec<String> = self
                    .buckets
                    .iter()
                    .flat_map(|b| [format!("arn:aws:s3:::{b}"), format!("arn:aws:s3:::{b}/*")])
                    .collect();
                json!([
                    {"Effect": "Allow", "Action": actions, "Resource": resources},
                    // So listing buckets works: it shows the names, never their contents.
                    {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
                ])
            };
            json!({"Version": "2012-10-17", "Statement": statements}).to_string()
        };
        match (self.policy.as_str(), self.buckets.is_empty()) {
            ("readonly", _) => Ok(preset(json!(["s3:Get*", "s3:List*"]))),
            ("readwrite", _) => Ok(preset(json!("s3:*"))),
            ("admin", true) => Ok(preset(json!("*"))),
            ("admin", false) => Err(Error::usage("an admin can't be limited to buckets")
                .with_hint("use --policy readwrite with --bucket")),
            (_, false) => Err(Error::usage("--bucket is for readonly and readwrite")
                .with_hint("name the buckets in the policy file")),
            (file, true) => std::fs::read_to_string(file).map_err(|e| {
                let kind = if e.kind() == std::io::ErrorKind::NotFound {
                    Kind::NotFound
                } else {
                    Kind::General
                };
                Error::new(
                    kind,
                    format!("`{file}` isn't readonly, readwrite, admin or a policy file: {e}"),
                )
            }),
        }
    }
}
