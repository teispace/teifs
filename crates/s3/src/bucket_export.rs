//! `GET` and `PUT buckets`: buckets and their settings exported, and imported onto
//! another drive (MinIO's `mc admin cluster bucket export|import`). An import creates
//! missing buckets and applies each setting it's given with the checks S3's own calls
//! make, reporting item by item; settings it isn't given are left as they are.

use std::collections::BTreeMap;

use s3s::{Body, S3Error, S3Request, S3Response, S3Result, dto};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use teifs_notify::Notifier;
use teifs_store::{
    BucketEncryption, CorsRule, Layout, Lifecycle, NewBucket, ObjectLock, ObjectOwnership,
    PublicAccessBlock, Store, Versioning,
};
use teifs_types::{
    Acl,
    admin::{
        BUCKETS_EXPORT_FORMAT, BucketImportItem, BucketsExport, BucketsImportReport, ExportedBucket,
    },
    configs::Configurations,
    logging::LoggingConfig,
    notify::NotificationConfig,
    replication::ReplicationConfig,
    website::WebsiteConfig,
};

use crate::{
    access_log::AccessLog,
    acl, admin,
    bucket_access::{Rules, parse_policy, public_policy_blocked},
    configs, cors,
    errors::StoreResultExt,
    lifecycle, logging, object_lock, quota, replication,
    request_metrics::RequestMetrics,
    routes::{s3_refusal, signed_body},
    tagging, website,
};

/// The settings an import knows, in the order it applies them: Block Public Access
/// before what it refuses, Object Ownership with the ACL, tags before ABAC. Logging and
/// replication go last, once every bucket is there: their targets may come later in the
/// export.
const SETTINGS: &[&str] = &[
    "objectLock",
    "publicAccessBlock",
    "ownership",
    "acl",
    "tags",
    "abac",
    "policy",
    "cors",
    "lifecycle",
    "encryption",
    "notifications",
    "website",
    "quota",
    "configurations",
    "logging",
    "replication",
];

/// `GET buckets`: every bucket, or `?bucket=NAME`'s alone.
pub(crate) async fn export(store: &Store, query: Option<&str>) -> S3Result<S3Response<Body>> {
    let only = admin::only_bucket(query)?;
    let mut buckets = Vec::new();
    for info in store.list_buckets().await.s3()? {
        if only.as_ref().is_some_and(|only| *only != info.name) {
            continue;
        }
        let versioning = store.bucket_versioning(&info.name).await.s3()?;
        let settings = store.bucket_settings(&info.name).await.s3()?;
        let Value::Object(settings) =
            serde_json::to_value(settings).expect("bucket settings serialize")
        else {
            unreachable!("bucket settings serialize as an object")
        };
        buckets.push(ExportedBucket {
            name: info.name,
            layout: layout_name(info.layout).to_owned(),
            versioning: versioning_name(versioning).to_owned(),
            settings,
        });
    }
    if let Some(only) = only
        && buckets.is_empty()
    {
        return Err(no_such_bucket(&only));
    }
    Ok(admin::json(&BucketsExport {
        format: BUCKETS_EXPORT_FORMAT,
        exported_ms: admin::millis(std::time::SystemTime::now()),
        buckets,
    }))
}

/// `?bucket=NAME`, the only parameter.
pub(crate) fn no_such_bucket(name: &str) -> S3Error {
    admin::error(
        http::StatusCode::NOT_FOUND,
        "NoSuchBucket",
        format!("There's no bucket {name}."),
    )
}

/// `PUT buckets`.
pub(crate) async fn import(
    store: &Store,
    rules: &Rules,
    notifier: &Notifier,
    (account, (access_log, request_metrics)): (&str, (&AccessLog, &RequestMetrics)),
    mut req: S3Request<Body>,
) -> S3Result<S3Response<Body>> {
    let body = signed_body(&mut req, admin::MAX_IMPORT_BYTES)
        .await
        .map_err(s3_refusal)?;
    let export: BucketsExport = serde_json::from_slice(&body).map_err(|e| {
        admin::error(
            http::StatusCode::BAD_REQUEST,
            "MalformedJSON",
            format!("The body isn't a bucket export: {e}"),
        )
    })?;
    if export.format != BUCKETS_EXPORT_FORMAT {
        return Err(admin::error(
            http::StatusCode::BAD_REQUEST,
            "UnsupportedFormat",
            format!(
                "This server reads bucket exports in format {BUCKETS_EXPORT_FORMAT}, not {}.",
                export.format
            ),
        ));
    }
    let report = apply(
        store,
        rules,
        notifier,
        (account, (access_log, request_metrics)),
        &export.buckets,
    )
    .await;
    Ok(admin::json(&report))
}

/// Creates the buckets that aren't there and applies their settings, item by item.
pub(crate) async fn apply(
    store: &Store,
    rules: &Rules,
    notifier: &Notifier,
    (account, (access_log, request_metrics)): (&str, (&AccessLog, &RequestMetrics)),
    buckets: &[ExportedBucket],
) -> BucketsImportReport {
    let mut report = BucketsImportReport::default();
    for bucket in buckets {
        let mut import = Import {
            store,
            rules,
            notifier,
            bucket: &bucket.name,
            items: &mut report.items,
        };
        import.bucket(bucket).await;
        rules.forget(&bucket.name);
        if store
            .bucket_configurations(&bucket.name)
            .await
            .is_ok_and(|configurations| configurations.counts_requests())
        {
            request_metrics.turn_on();
        }
    }
    for bucket in buckets {
        let Some(value) = bucket.settings.get("logging") else {
            continue;
        };
        let mut import = Import {
            store,
            rules,
            notifier,
            bucket: &bucket.name,
            items: &mut report.items,
        };
        let result = import.logging(value, account).await;
        if result.is_ok() {
            access_log.turn_on();
        }
        import.report("logging", result.map(|()| APPLIED));
    }
    for bucket in buckets {
        let Some(value) = bucket.settings.get("replication") else {
            continue;
        };
        let mut import = Import {
            store,
            rules,
            notifier,
            bucket: &bucket.name,
            items: &mut report.items,
        };
        let result = import.replication(value).await;
        import.report("replication", result.map(|()| APPLIED));
    }
    tracing::info!(
        items = report.items.len(),
        failed = report.items.iter().filter(|i| i.outcome == FAILED).count(),
        "buckets were imported"
    );
    report
}

const CREATED: &str = "created";
const APPLIED: &str = "applied";
const FAILED: &str = "failed";

/// One bucket's import, and what it reports.
struct Import<'a> {
    store: &'a Store,
    rules: &'a Rules,
    notifier: &'a Notifier,
    bucket: &'a str,
    items: &'a mut Vec<BucketImportItem>,
}

impl Import<'_> {
    fn report(&mut self, item: &str, result: S3Result<&str>) {
        self.report_as(item, result.map_err(|err| message(&err)));
    }

    fn report_as(&mut self, item: &str, result: Result<&str, String>) {
        let (outcome, error) = match result {
            Ok(outcome) => (outcome, None),
            Err(message) => (FAILED, Some(message)),
        };
        self.items.push(BucketImportItem {
            bucket: self.bucket.to_owned(),
            item: item.to_owned(),
            outcome: outcome.to_owned(),
            error,
        });
    }

    /// A bucket: one with no layout is an object bucket if it's made, and one with no
    /// versioning keeps its own (`MinIO`'s export has no layout, and versioning only if set).
    async fn bucket(&mut self, bucket: &ExportedBucket) {
        let layout = if bucket.layout.is_empty() {
            None
        } else if let Some(layout) = parse_layout(&bucket.layout) {
            Some(layout)
        } else {
            let err = invalid(format!(
                "the layout {:?} isn't object or folder",
                bucket.layout
            ));
            return self.report("bucket", Err(err));
        };
        let settings = &bucket.settings;
        match self.existing_layout().await {
            Ok(Some(existing)) => {
                if layout.is_some_and(|layout| layout != existing) {
                    let err = invalid(format!(
                        "the bucket is a {} bucket here",
                        layout_name(existing)
                    ));
                    self.report("layout", Err(err));
                }
            }
            Ok(None) => {
                let created = self.create(layout.unwrap_or(Layout::Object)).await;
                let failed = created.is_err();
                self.report("bucket", created.map(|()| CREATED));
                if failed {
                    return;
                }
            }
            Err(err) => return self.report("bucket", Err(err)),
        }
        if !bucket.versioning.is_empty() {
            let versioning = self.versioning(&bucket.versioning).await;
            self.report("versioning", versioning.map(|()| APPLIED));
        }
        self.settings(settings).await;
        for name in settings.keys() {
            if !SETTINGS.contains(&name.as_str()) {
                let err = invalid("this server has no such setting".to_owned());
                self.report(name, Err(err));
            }
        }
    }

    async fn existing_layout(&self) -> S3Result<Option<Layout>> {
        let buckets = self.store.list_buckets().await.s3()?;
        Ok(buckets
            .into_iter()
            .find(|b| b.name == self.bucket)
            .map(|b| b.layout))
    }

    /// Creates the bucket bare: its versioning and settings come next, as the export
    /// has them (no Block Public Access, say, unless it has some).
    async fn create(&self, layout: Layout) -> S3Result<()> {
        let new = NewBucket {
            ownership: None,
            block_public_access: false,
            acl: None,
            tags: None,
            object_lock: false,
        };
        self.store
            .create_bucket_with(self.bucket, layout, new)
            .await
            .s3()
    }

    async fn versioning(&self, name: &str) -> S3Result<()> {
        let wanted = parse_versioning(name).ok_or_else(|| {
            invalid(format!(
                "the versioning {name:?} isn't unversioned, enabled or suspended"
            ))
        })?;
        if self.store.bucket_versioning(self.bucket).await.s3()? == wanted {
            return Ok(());
        }
        // The store refuses going back to unversioned, as S3 does.
        self.store
            .set_bucket_versioning(self.bucket, wanted)
            .await
            .s3()
    }

    async fn settings(&mut self, settings: &Map<String, Value>) {
        if let Some(value) = settings.get("objectLock") {
            let result = self.object_lock(value).await;
            self.report("objectLock", result.map(|()| APPLIED));
        }
        if let Some(value) = settings.get("publicAccessBlock") {
            let result = self.public_access_block(value).await;
            self.report("publicAccessBlock", result.map(|()| APPLIED));
        }
        if settings.contains_key("ownership") || settings.contains_key("acl") {
            let result = self.access_controls(settings).await;
            let result = result.map(|()| APPLIED).map_err(|err| message(&err));
            for item in ["ownership", "acl"] {
                if settings.contains_key(item) {
                    self.report_as(item, result.clone());
                }
            }
        }
        if settings.contains_key("tags") || settings.contains_key("abac") {
            let (tags, abac) = self.tags_and_abac(settings).await;
            if let Some(result) = tags {
                self.report("tags", result.map(|()| APPLIED));
            }
            if let Some(result) = abac {
                self.report("abac", result.map(|()| APPLIED));
            }
        }
        if let Some(value) = settings.get("policy") {
            let result = self.policy(value).await;
            self.report("policy", result.map(|()| APPLIED));
        }
        if let Some(value) = settings.get("cors") {
            let result = self.cors(value).await;
            self.report("cors", result.map(|()| APPLIED));
        }
        if let Some(value) = settings.get("lifecycle") {
            let result = self.lifecycle(value).await;
            self.report("lifecycle", result.map(|()| APPLIED));
        }
        if let Some(value) = settings.get("encryption") {
            let result = self.encryption(value).await;
            self.report("encryption", result.map(|()| APPLIED));
        }
        if let Some(value) = settings.get("notifications") {
            let result = self.notifications(value).await;
            self.report("notifications", result.map(|()| APPLIED));
        }
        if let Some(value) = settings.get("website") {
            let result = self.website(value).await;
            self.report("website", result.map(|()| APPLIED));
        }
        if let Some(value) = settings.get("quota") {
            let result = self.quota(value).await;
            self.report("quota", result.map(|()| APPLIED));
        }
        if let Some(value) = settings.get("configurations") {
            let result = self.configurations(value).await;
            self.report("configurations", result.map(|()| APPLIED));
        }
    }

    async fn object_lock(&self, value: &Value) -> S3Result<()> {
        let lock: ObjectLock = parse("objectLock", value)?;
        // Checked as PutObjectLockConfiguration checks it.
        let lock = object_lock::config_from_dto(Some(object_lock::config_to_dto(&lock)))?;
        self.store
            .set_bucket_object_lock(self.bucket, lock)
            .await
            .s3()
    }

    async fn public_access_block(&self, value: &Value) -> S3Result<()> {
        let block: PublicAccessBlock = parse("publicAccessBlock", value)?;
        self.store
            .set_bucket_public_access_block(self.bucket, Some(block))
            .await
            .s3()?;
        self.rules.forget(self.bucket);
        Ok(())
    }

    /// Object Ownership and the ACL, set together: each decides what the other may be
    /// (the store refuses an ACL granting others where ACLs are disabled).
    async fn access_controls(&self, settings: &Map<String, Value>) -> S3Result<()> {
        let current = self.store.bucket_access(self.bucket).await.s3()?;
        let ownership: Option<ObjectOwnership> = match settings.get("ownership") {
            Some(value) => Some(parse("ownership", value)?),
            None => current.ownership,
        };
        let acl: Option<Acl> = match settings.get("acl") {
            Some(value) => Some(parse("acl", value)?),
            None => current.acl,
        };
        let block = self.rules.of(self.bucket).await?.block;
        if block.block_public_acls && acl.as_ref().is_some_and(Acl::is_public) {
            return Err(acl::public_blocked());
        }
        self.store
            .set_bucket_ownership_and_acl(self.bucket, ownership, acl)
            .await
            .s3()?;
        self.rules.forget(self.bucket);
        Ok(())
    }

    /// Tags, then ABAC: while ABAC is on only `TagResource` changes tags, so it's off
    /// while they're replaced, and back as the export (or the bucket) had it.
    async fn tags_and_abac(
        &self,
        settings: &Map<String, Value>,
    ) -> (Option<S3Result<()>>, Option<S3Result<()>>) {
        let abac: Option<S3Result<bool>> = settings.get("abac").map(|v| parse("abac", v));
        let tags = match settings.get("tags") {
            None => None,
            Some(value) => Some(self.tags(value).await),
        };
        let abac = match abac {
            Some(Ok(enabled)) => Some(self.store.set_bucket_abac(self.bucket, enabled).await.s3()),
            Some(Err(err)) => Some(Err(err)),
            None => None,
        };
        self.rules.forget(self.bucket);
        (tags, abac)
    }

    async fn tags(&self, value: &Value) -> S3Result<()> {
        let tags: BTreeMap<String, String> = parse("tags", value)?;
        let tags = tagging::check(tags.into_iter().collect(), tagging::MAX_BUCKET_TAGS)?;
        let was = self.store.bucket_abac(self.bucket).await.s3()?;
        if was {
            self.store.set_bucket_abac(self.bucket, false).await.s3()?;
        }
        let set = self
            .store
            .set_bucket_tags(self.bucket, Some(tags).filter(|t| !t.is_empty()))
            .await
            .s3();
        if was {
            self.store.set_bucket_abac(self.bucket, true).await.s3()?;
        }
        set
    }

    async fn policy(&self, value: &Value) -> S3Result<()> {
        let text: String = parse("policy", value)?;
        let policy = parse_policy(self.bucket, &text)?;
        let block = self.rules.of(self.bucket).await?.block;
        if block.block_public_policy && policy.is_public() {
            return Err(public_policy_blocked());
        }
        self.store
            .set_bucket_policy(self.bucket, Some(text))
            .await
            .s3()?;
        self.rules.forget(self.bucket);
        Ok(())
    }

    async fn cors(&self, value: &Value) -> S3Result<()> {
        let rules: Vec<CorsRule> = parse("cors", value)?;
        // Checked as PutBucketCors checks it.
        let rules = cors::from_dto(dto::CORSConfiguration {
            cors_rules: cors::to_dto(rules),
        })?;
        self.store
            .set_bucket_cors(self.bucket, Some(rules))
            .await
            .s3()
    }

    async fn lifecycle(&self, value: &Value) -> S3Result<()> {
        let config: Lifecycle = parse("lifecycle", value)?;
        // Checked as PutBucketLifecycleConfiguration checks it, keeping the size given
        // (an answer fills in the default).
        let size = config
            .transition_minimum_size
            .clone()
            .map(dto::TransitionDefaultMinimumObjectSize::from);
        let config = lifecycle::from_dto(
            Some(dto::BucketLifecycleConfiguration {
                rules: lifecycle::to_dto(&config).rules.unwrap_or_default(),
            }),
            size.as_ref(),
        )?;
        self.store
            .set_bucket_lifecycle(self.bucket, Some(config))
            .await
            .s3()
    }

    /// Checked as `PutBucketNotificationConfiguration` checks them, against this
    /// server's targets; no test event is sent.
    async fn notifications(&self, value: &Value) -> S3Result<()> {
        let config: NotificationConfig = parse("notifications", value)?;
        config
            .check(|arn| self.notifier.resolve(arn))
            .map_err(|err| invalid(err.to_string()))?;
        if config.event_bridge && self.notifier.event_bridge().is_none() {
            return Err(invalid(
                "the bucket sends its events to EventBridge, which this server doesn't have"
                    .to_owned(),
            ));
        }
        self.store
            .set_bucket_notifications(self.bucket, Some(config))
            .await
            .s3()
    }

    /// Checked as `PutBucketWebsite` checks it.
    async fn website(&self, value: &Value) -> S3Result<()> {
        let config: WebsiteConfig = parse("website", value)?;
        let config = website::check(&config)?;
        self.store
            .set_bucket_website(self.bucket, Some(config))
            .await
            .s3()
    }

    /// Requester Pays and the reporting configurations, each checked as its Put checks it.
    async fn configurations(&self, value: &Value) -> S3Result<()> {
        let given: Configurations = parse("configurations", value)?;
        let checked = configs::check_all(&given)?;
        self.store
            .set_bucket_configurations(self.bucket, checked)
            .await
            .s3()
    }

    /// Checked as `MinIO`'s `SetBucketQuota` checks it.
    async fn quota(&self, value: &Value) -> S3Result<()> {
        let quota: u64 = parse("quota", value)?;
        let quota = quota::size(quota)?;
        self.store
            .set_bucket_quota(self.bucket, Some(quota))
            .await
            .s3()
    }

    /// Checked as `PutBucketLogging` checks it.
    async fn logging(&self, value: &Value, account: &str) -> S3Result<()> {
        let config: LoggingConfig = parse("logging", value)?;
        logging::check(self.store, self.rules, Some(account), self.bucket, &config).await?;
        self.store
            .set_bucket_logging(self.bucket, Some(config))
            .await
            .s3()
    }

    /// Checked as `PutBucketReplication` checks it.
    async fn replication(&self, value: &Value) -> S3Result<()> {
        let config: ReplicationConfig = parse("replication", value)?;
        let config = replication::checked(&config)?;
        replication::check(self.store, self.bucket, &config).await?;
        self.store
            .set_bucket_replication(self.bucket, Some(config))
            .await
            .s3()
    }

    async fn encryption(&self, value: &Value) -> S3Result<()> {
        let encryption: BucketEncryption = parse("encryption", value)?;
        self.store
            .set_bucket_encryption(self.bucket, Some(encryption))
            .await
            .s3()
    }
}

/// A setting read from the export, or why it can't be.
fn parse<T: DeserializeOwned>(item: &str, value: &Value) -> S3Result<T> {
    serde_json::from_value(value.clone())
        .map_err(|e| invalid(format!("the {item} isn't valid: {e}")))
}

fn invalid(message: String) -> S3Error {
    admin::error(http::StatusCode::BAD_REQUEST, "InvalidArgument", message)
}

/// What an item's failure says: the error's message, or its code.
fn message(err: &S3Error) -> String {
    err.message()
        .map_or_else(|| err.code().as_str().to_owned(), str::to_owned)
}

const fn layout_name(layout: Layout) -> &'static str {
    match layout {
        Layout::Object => "object",
        Layout::Folder => "folder",
    }
}

fn parse_layout(name: &str) -> Option<Layout> {
    match name {
        "object" => Some(Layout::Object),
        "folder" => Some(Layout::Folder),
        _ => None,
    }
}

const fn versioning_name(versioning: Versioning) -> &'static str {
    match versioning {
        Versioning::Unversioned => "unversioned",
        Versioning::Enabled => "enabled",
        Versioning::Suspended => "suspended",
    }
}

fn parse_versioning(name: &str) -> Option<Versioning> {
    match name {
        "unversioned" => Some(Versioning::Unversioned),
        "enabled" => Some(Versioning::Enabled),
        "suspended" => Some(Versioning::Suspended),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use teifs_store::BucketSettings;

    use super::*;

    #[test]
    fn names_go_both_ways() {
        for layout in [Layout::Object, Layout::Folder] {
            assert_eq!(parse_layout(layout_name(layout)), Some(layout));
        }
        for versioning in [
            Versioning::Unversioned,
            Versioning::Enabled,
            Versioning::Suspended,
        ] {
            assert_eq!(
                parse_versioning(versioning_name(versioning)),
                Some(versioning)
            );
        }
        assert_eq!(parse_layout("Object"), None);
        assert_eq!(parse_versioning("on"), None);
    }

    #[test]
    fn every_setting_a_bucket_has_is_imported() {
        let all = BucketSettings {
            encryption: Some(BucketEncryption::aws_default()),
            tags: Some(BTreeMap::new()),
            cors: Some(Vec::new()),
            policy: Some(String::new()),
            public_access_block: Some(PublicAccessBlock::ALL),
            ownership: Some(ObjectOwnership::default()),
            acl: Some(Acl::private()),
            abac: true,
            object_lock: Some(ObjectLock::default()),
            lifecycle: Some(Lifecycle::default()),
            notifications: Some(NotificationConfig::default()),
            logging: Some(LoggingConfig {
                target_bucket: String::new(),
                target_prefix: String::new(),
                key_format: None,
                grants: Vec::new(),
            }),
            website: Some(WebsiteConfig::RedirectAll {
                host_name: String::new(),
                protocol: None,
            }),
            replication: Some(ReplicationConfig {
                role: String::new(),
                rules: Vec::new(),
            }),
            quota: Some(1),
            configurations: Some(Configurations::default()),
        };
        let Value::Object(given) = serde_json::to_value(all).unwrap() else {
            unreachable!()
        };
        let mut known: Vec<&str> = SETTINGS.to_vec();
        known.sort_unstable();
        let mut exported: Vec<&str> = given.keys().map(String::as_str).collect();
        exported.sort_unstable();
        assert_eq!(known, exported);
    }

    #[test]
    fn only_a_bucket_is_a_parameter() {
        assert_eq!(admin::only_bucket(None).unwrap(), None);
        assert_eq!(
            admin::only_bucket(Some("bucket=a")).unwrap().as_deref(),
            Some("a")
        );
        for bad in ["name=a", "bucket=a&bucket=b", "Bucket=a"] {
            assert!(admin::only_bucket(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_setting_that_isnt_valid_says_which() {
        let err = parse::<PublicAccessBlock>("publicAccessBlock", &Value::from(3)).unwrap_err();
        assert!(message(&err).contains("publicAccessBlock"));
    }
}
