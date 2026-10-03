//! Bucket replication, as `mc replicate` drives it: the bucket's targets on other
//! services (`MinIO`'s admin API, secret keys sent encrypted with the caller's), its
//! configuration as S3's XML, and `MinIO`'s metrics, resync and check calls.

use std::time::Duration;

use reqwest::Method;
use serde::Deserialize;
use teifs_types::admin::{
    MINIO_LIST_REMOTE_TARGETS, MINIO_REMOVE_REMOTE_TARGET, MINIO_SET_REMOTE_TARGET,
};
use zeroize::Zeroizing;

use crate::{Client, ClientError, api_error};

/// A bucket on another service to replicate to, as [`Client::add_replication_target`]
/// sends it (`madmin.BucketTarget`). No `Debug`: it holds the secret key.
pub struct NewReplicationTarget<'a> {
    /// The service's host and port, without a scheme (`backup.example.com:9000`).
    pub endpoint: &'a str,
    /// Whether it's reached over HTTPS.
    pub secure: bool,
    /// The bucket there.
    pub bucket: &'a str,
    /// Its region (empty: the service's default).
    pub region: &'a str,
    /// The access key that signs there.
    pub access_key: &'a str,
    /// Its secret key.
    pub secret_key: &'a str,
    /// A session token, with temporary credentials.
    pub session_token: Option<&'a str>,
    /// The storage class replicas get there (empty: the source's).
    pub storage_class: &'a str,
    /// The most bytes a second sent there (0: no limit).
    pub bandwidth_limit: u64,
    /// Whether writes wait until the replica is made.
    pub sync: bool,
}

/// A bucket's replication target, as [`Client::replication_targets`] lists it, without
/// its secret key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReplicationTarget {
    /// Its ARN, which rules name.
    pub arn: String,
    /// The service's host and port.
    pub endpoint: String,
    /// Whether it's reached over HTTPS.
    #[serde(default)]
    pub secure: bool,
    /// The bucket there.
    #[serde(rename = "targetbucket")]
    pub bucket: String,
    /// Whether the last attempt reached it.
    #[serde(default = "yes", rename = "isOnline")]
    pub online: bool,
}

const fn yes() -> bool {
    true
}

/// What replication did for a bucket, as [`Client::replication_metrics`] answers it
/// (`MinIO`'s `currStats`).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct ReplicationMetrics {
    /// Each destination's, by ARN.
    #[serde(default, rename = "Stats")]
    pub targets: std::collections::BTreeMap<String, ReplicationCounts>,
    /// Versions other buckets replicated here.
    #[serde(default, rename = "replicaCount")]
    pub replica_count: u64,
    /// Their bytes.
    #[serde(default, rename = "replicaSize")]
    pub replica_size: u64,
}

/// What replication did for one destination.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub struct ReplicationCounts {
    /// Versions replicated.
    #[serde(default, rename = "replicationCount")]
    pub replicated: u64,
    /// Their bytes.
    #[serde(default, rename = "completedReplicationSize")]
    pub replicated_size: u64,
    /// Versions waiting.
    #[serde(default, rename = "pendingReplicationCount")]
    pub pending: u64,
    /// Their bytes.
    #[serde(default, rename = "pendingReplicationSize")]
    pub pending_size: u64,
    /// Versions that failed.
    #[serde(default, rename = "failedReplicationCount")]
    pub failed: u64,
    /// Their bytes.
    #[serde(default, rename = "failedReplicationSize")]
    pub failed_size: u64,
}

#[derive(Deserialize)]
struct CurrentStats {
    #[serde(default, rename = "currStats")]
    current: ReplicationMetrics,
}

/// A resync of one destination (`MinIO`'s `ResyncTarget`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resync {
    /// The destination's ARN.
    pub arn: String,
    /// Its id.
    #[serde(rename = "resetid")]
    pub id: String,
    /// Where it stands: `Pending`, `Ongoing`, `Completed`, `Failed` or `Canceled`
    /// (empty for one just started).
    #[serde(default)]
    pub resync_status: String,
    /// Versions sent again.
    #[serde(default, rename = "replicationCount")]
    pub replicated: u64,
    /// Their bytes.
    #[serde(default, rename = "completedReplicationSize")]
    pub replicated_size: u64,
    /// Versions that failed.
    #[serde(default, rename = "failedReplicationCount")]
    pub failed: u64,
}

#[derive(Deserialize)]
struct Resyncs {
    #[serde(default, rename = "target")]
    targets: Vec<Resync>,
}

impl Client {
    /// Adds a target on another service to `bucket` (`admin:SetBucketTarget`), its
    /// secret key encrypted with this client's: its ARN, for rules to name.
    ///
    /// # Errors
    ///
    /// The server's refusal, or why it couldn't be reached.
    pub async fn add_replication_target(
        &self,
        bucket: &str,
        target: &NewReplicationTarget<'_>,
    ) -> Result<String, ClientError> {
        let body = Zeroizing::new(
            serde_json::json!({
                "sourcebucket": bucket,
                "endpoint": target.endpoint,
                "credentials": {
                    "accessKey": target.access_key,
                    "secretKey": target.secret_key,
                    "sessionToken": target.session_token.unwrap_or_default(),
                },
                "targetbucket": target.bucket,
                "secure": target.secure,
                "type": "replication",
                "region": target.region,
                "bandwidthlimit": target.bandwidth_limit,
                "replicationSync": target.sync,
                "storageclass": target.storage_class,
            })
            .to_string(),
        );
        let sealed = teifs_crypto::madmin::encrypt(self.secret.as_str(), body.as_bytes());
        self.call(
            Method::PUT,
            MINIO_SET_REMOTE_TARGET,
            Some(&query(&[("bucket", bucket)])),
            sealed,
        )
        .await
    }

    /// `bucket`'s targets on other services (`admin:GetBucketTarget`).
    ///
    /// # Errors
    ///
    /// The server's refusal, or why it couldn't be reached.
    pub async fn replication_targets(
        &self,
        bucket: &str,
    ) -> Result<Vec<ReplicationTarget>, ClientError> {
        let targets: Option<Vec<ReplicationTarget>> = self
            .call(
                Method::GET,
                MINIO_LIST_REMOTE_TARGETS,
                Some(&query(&[("bucket", bucket), ("type", "replication")])),
                Vec::new(),
            )
            .await?;
        Ok(targets.unwrap_or_default())
    }

    /// Removes a target of `bucket` no rule names any more (`admin:SetBucketTarget`).
    ///
    /// # Errors
    ///
    /// The server's refusal, or why it couldn't be reached.
    pub async fn remove_replication_target(
        &self,
        bucket: &str,
        arn: &str,
    ) -> Result<(), ClientError> {
        self.empty(
            Method::DELETE,
            MINIO_REMOVE_REMOTE_TARGET,
            &query(&[("bucket", bucket), ("arn", arn)]),
            Vec::new(),
        )
        .await
        .map(drop)
    }

    /// `bucket`'s replication configuration, as S3's XML; `None` when it has none.
    ///
    /// # Errors
    ///
    /// The server's refusal, or why it couldn't be reached.
    pub async fn bucket_replication(&self, bucket: &str) -> Result<Option<Vec<u8>>, ClientError> {
        match self
            .empty(Method::GET, &path(bucket), "replication", Vec::new())
            .await
        {
            Ok(xml) => Ok(Some(xml)),
            Err(ClientError::Api { code, .. })
                if code == "ReplicationConfigurationNotFoundError" =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Sets `bucket`'s replication configuration from S3's XML.
    ///
    /// # Errors
    ///
    /// The server's refusal, or why it couldn't be reached.
    pub async fn set_bucket_replication(
        &self,
        bucket: &str,
        xml: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.empty(Method::PUT, &path(bucket), "replication", xml)
            .await
            .map(drop)
    }

    /// Removes `bucket`'s replication configuration.
    ///
    /// # Errors
    ///
    /// The server's refusal, or why it couldn't be reached.
    pub async fn delete_bucket_replication(&self, bucket: &str) -> Result<(), ClientError> {
        self.empty(Method::DELETE, &path(bucket), "replication", Vec::new())
            .await
            .map(drop)
    }

    /// What `bucket`'s replication did (`?replication-metrics=2`).
    ///
    /// # Errors
    ///
    /// The server's refusal, or why it couldn't be reached.
    pub async fn replication_metrics(
        &self,
        bucket: &str,
    ) -> Result<ReplicationMetrics, ClientError> {
        let stats: CurrentStats = self
            .call(
                Method::GET,
                &path(bucket),
                Some("replication-metrics=2"),
                Vec::new(),
            )
            .await?;
        Ok(stats.current)
    }

    /// Sends every version from before `older_than` ago that `bucket`'s rules send to
    /// `arn` again (the only destination when `None`).
    ///
    /// # Errors
    ///
    /// The server's refusal, or why it couldn't be reached.
    pub async fn start_resync(
        &self,
        bucket: &str,
        arn: Option<&str>,
        older_than: Option<Duration>,
    ) -> Result<Vec<Resync>, ClientError> {
        let older = older_than.map(|d| format!("{}s", d.as_secs()));
        let mut pairs = vec![("replication-reset", "")];
        pairs.extend(arn.map(|arn| ("arn", arn)));
        pairs.extend(older.as_deref().map(|older| ("older-than", older)));
        let resyncs: Resyncs = self
            .call(Method::PUT, &path(bucket), Some(&query(&pairs)), Vec::new())
            .await?;
        Ok(resyncs.targets)
    }

    /// Where `bucket`'s resyncs stand, of `arn` or every destination.
    ///
    /// # Errors
    ///
    /// The server's refusal, or why it couldn't be reached.
    pub async fn resyncs(
        &self,
        bucket: &str,
        arn: Option<&str>,
    ) -> Result<Vec<Resync>, ClientError> {
        let mut pairs = vec![("replication-reset-status", "")];
        pairs.extend(arn.map(|arn| ("arn", arn)));
        let resyncs: Resyncs = self
            .call(Method::GET, &path(bucket), Some(&query(&pairs)), Vec::new())
            .await?;
        Ok(resyncs.targets)
    }

    /// Cancels the resync of `arn` (the only destination when `None`): its id.
    ///
    /// # Errors
    ///
    /// The server's refusal, or why it couldn't be reached.
    pub async fn cancel_resync(
        &self,
        bucket: &str,
        arn: Option<&str>,
    ) -> Result<String, ClientError> {
        let mut pairs = vec![("replication-reset-cancel", "")];
        pairs.extend(arn.map(|arn| ("arn", arn)));
        let id = self
            .empty(Method::PUT, &path(bucket), &query(&pairs), Vec::new())
            .await?;
        Ok(String::from_utf8_lossy(&id).into_owned())
    }

    /// Checks that `bucket`'s replication can work: each destination is there, keeps
    /// versions, and takes the replicator's writes (`?replication-check`).
    ///
    /// # Errors
    ///
    /// Why it can't, as the server says it.
    pub async fn check_replication(&self, bucket: &str) -> Result<(), ClientError> {
        self.empty(Method::GET, &path(bucket), "replication-check", Vec::new())
            .await
            .map(drop)
    }

    /// A call whose answer isn't JSON: its body.
    async fn empty(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, ClientError> {
        let response = self.send(method, path, Some(query), body).await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        if !status.is_success() {
            return Err(api_error(status, &bytes));
        }
        Ok(bytes.to_vec())
    }
}

/// A bucket's path.
fn path(bucket: &str) -> String {
    format!("/{bucket}")
}

/// A query from names and values, encoded.
fn query(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| {
            let value: String = form_urlencoded::byte_serialize(value.as_bytes()).collect();
            if value.is_empty() {
                (*name).to_owned()
            } else {
                format!("{name}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_are_encoded_and_bare_names_stay_bare() {
        assert_eq!(
            query(&[
                ("replication-reset", ""),
                ("arn", "arn:minio:replication::1:b")
            ]),
            "replication-reset&arn=arn%3Aminio%3Areplication%3A%3A1%3Ab"
        );
    }

    #[test]
    fn metrics_and_targets_are_read_as_minio_writes_them() {
        let stats: CurrentStats = serde_json::from_str(
            r#"{"uptime":3,"currStats":{"Stats":{"arn:1":{"replicationCount":2,"completedReplicationSize":10,"failedReplicationCount":1,"pendingReplicationCount":4}},"replicaCount":5,"replicaSize":50}}"#,
        )
        .unwrap();
        let target = stats.current.targets["arn:1"];
        assert_eq!((target.replicated, target.replicated_size), (2, 10));
        assert_eq!((target.failed, target.pending), (1, 4));
        assert_eq!(stats.current.replica_count, 5);
        let targets: Vec<ReplicationTarget> = serde_json::from_str(
            r#"[{"sourcebucket":"a","endpoint":"h:9000","credentials":{"accessKey":"k"},"targetbucket":"b","secure":false,"arn":"arn:1","type":"replication","isOnline":false}]"#,
        )
        .unwrap();
        assert_eq!(targets[0].bucket, "b");
        assert!(!targets[0].online);
    }
}
