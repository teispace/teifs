//! One access log record in S3's format: 27 space-separated fields, `-` for what isn't
//! known, three of them quoted. Operation names are S3's (`REST.GET.OBJECT`), from the
//! request's method and subresource, and log objects are named as S3 names them.

use std::{fmt::Write as _, net::IpAddr, time::SystemTime};

use teifs_types::logging::{DateSource, LoggingConfig};
use time::{OffsetDateTime, macros::format_description};

/// What's known of a request once it's done, for one bucket's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record {
    /// The bucket whose log it goes to.
    pub(crate) bucket: String,
    /// When the request arrived.
    pub(crate) time: SystemTime,
    pub(crate) remote: Option<IpAddr>,
    /// Who: an IAM ARN, the owner's canonical id for the root user; none when unsigned.
    pub(crate) requester: Option<String>,
    pub(crate) request_id: String,
    /// S3's name for it (`REST.GET.OBJECT`).
    pub(crate) operation: String,
    pub(crate) key: Option<String>,
    /// `GET /bucket/key?query HTTP/1.1`, secrets redacted.
    pub(crate) request_uri: String,
    /// None for what no request did (a lifecycle rule's removal).
    pub(crate) status: Option<u16>,
    pub(crate) error: Option<String>,
    /// Answer body bytes sent.
    pub(crate) sent: u64,
    pub(crate) object_size: Option<u64>,
    pub(crate) total_ms: u64,
    /// Until the answer's first byte; none when it never had one.
    pub(crate) turnaround_ms: Option<u64>,
    pub(crate) referer: Option<String>,
    pub(crate) user_agent: Option<String>,
    /// The `versionId` the request named.
    pub(crate) version_id: Option<String>,
    /// `SigV2` or `SigV4`.
    pub(crate) signature: Option<&'static str>,
    /// `AuthHeader` or `QueryString`.
    pub(crate) auth: Option<&'static str>,
    /// The `Host` header.
    pub(crate) host: Option<String>,
    /// `TLSv1.2` or `TLSv1.3`.
    pub(crate) tls: Option<&'static str>,
    /// Whether an ACL was what allowed it.
    pub(crate) acl_required: bool,
}

/// The canonical id records name the bucket owner (and the root user) by.
const OWNER: &str = teifs_types::OWNER_ID;

impl Record {
    /// The record's line, without its newline.
    pub(crate) fn line(&self) -> String {
        let mut line = String::with_capacity(512);
        let time = OffsetDateTime::from(self.time)
            .format(format_description!(
                "[[[day]/[month repr:short]/[year]:[hour]:[minute]:[second] +0000]"
            ))
            .unwrap_or_else(|_| "-".to_owned());
        let dash = |value: Option<&str>| value.map_or_else(|| "-".to_owned(), bare);
        let number = |value: Option<u64>| value.map_or_else(|| "-".to_owned(), |n| n.to_string());
        let fields = [
            OWNER.to_owned(),
            bare(&self.bucket),
            time,
            dash(self.remote.map(|ip| ip.to_string()).as_deref()),
            dash(self.requester.as_deref()),
            bare(&self.request_id),
            bare(&self.operation),
            self.key
                .as_deref()
                .map_or_else(|| "-".to_owned(), encode_key),
            quoted(
                Some(&self.request_uri)
                    .filter(|uri| !uri.is_empty())
                    .map(String::as_str),
            ),
            number(self.status.map(u64::from)),
            dash(self.error.as_deref()),
            number(Some(self.sent).filter(|&n| n > 0)),
            number(self.object_size),
            self.total_ms.to_string(),
            number(self.turnaround_ms),
            quoted(self.referer.as_deref()),
            quoted(self.user_agent.as_deref()),
            dash(self.version_id.as_deref()),
            // Host id (`x-amz-id-2`) and cipher suite: none to name.
            "-".to_owned(),
            dash(self.signature),
            "-".to_owned(),
            dash(self.auth),
            dash(self.host.as_deref()),
            dash(self.tls),
            // Access point ARN: none.
            "-".to_owned(),
            if self.acl_required { "Yes" } else { "-" }.to_owned(),
            // Source region: unknown.
            "-".to_owned(),
        ];
        for (i, field) in fields.iter().enumerate() {
            if i > 0 {
                line.push(' ');
            }
            line.push_str(field);
        }
        line
    }
}

/// A field that can't hold a space, a quote or a control character: those are
/// percent-encoded, so every record parses the same way.
fn bare(value: &str) -> String {
    if value.is_empty() {
        return "-".to_owned();
    }
    escape(value, |c| c == ' ' || c == '"')
}

/// A quoted field (`"-"` when there's none), a quote inside it percent-encoded.
fn quoted(value: Option<&str>) -> String {
    let inner = value.map_or_else(|| "-".to_owned(), |v| escape(v, |c| c == '"'));
    format!("\"{inner}\"")
}

fn escape(value: &str, special: impl Fn(char) -> bool) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if c.is_control() || special(c) {
            let mut bytes = [0; 4];
            for byte in c.encode_utf8(&mut bytes).bytes() {
                let _ = write!(out, "%{byte:02X}");
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A key as records name it: URL-encoded, `/` kept.
pub(crate) fn encode_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for byte in key.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~/".contains(&byte) {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// Subresources and the resource type S3's operation names give them; the first one a
/// request has decides.
const SUBRESOURCES: &[(&str, &str)] = &[
    ("accelerate", "ACCELERATE"),
    ("acl", "ACL"),
    ("analytics", "ANALYTICS"),
    ("attributes", "OBJECT_ATTRIBUTES"),
    ("cors", "CORS"),
    ("delete", "MULTI_OBJECT_DELETE"),
    ("encryption", "ENCRYPTION"),
    ("intelligent-tiering", "INTELLIGENT_TIERING"),
    ("inventory", "INVENTORY"),
    ("legal-hold", "LEGAL_HOLD"),
    ("lifecycle", "LIFECYCLE"),
    ("location", "LOCATION"),
    ("logging", "LOGGING_STATUS"),
    ("metrics", "METRICS"),
    ("notification", "NOTIFICATION"),
    ("object-lock", "OBJECT_LOCK_CONFIGURATION"),
    ("ownershipControls", "OWNERSHIP_CONTROLS"),
    ("policy", "BUCKETPOLICY"),
    ("policyStatus", "POLICY_STATUS"),
    ("publicAccessBlock", "PUBLIC_ACCESS_BLOCK"),
    ("renameObject", "RENAME_OBJECT"),
    ("replication", "REPLICATION"),
    ("requestPayment", "REQUEST_PAYMENT"),
    ("restore", "RESTORE"),
    ("retention", "RETENTION"),
    ("select", "SELECT"),
    ("tagging", "TAGGING"),
    ("uploadId", "UPLOAD"),
    ("uploads", "UPLOADS"),
    ("versioning", "VERSIONING"),
    ("versions", "BUCKETVERSIONS"),
    ("website", "WEBSITE"),
];

/// S3's name for a request's operation: `REST.METHOD.RESOURCE`, the resource its
/// subresource (`?acl`), else `OBJECT` or `BUCKET`. A copy is `REST.COPY.OBJECT` (or
/// `PART`), as S3 names it.
pub(crate) fn operation(
    method: &str,
    s3_operation: &str,
    query: Option<&str>,
    key: bool,
) -> String {
    match s3_operation {
        "CopyObject" => return "REST.COPY.OBJECT".to_owned(),
        "UploadPartCopy" => return "REST.COPY.PART".to_owned(),
        _ => {}
    }
    let names: Vec<String> = form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .map(|(name, _)| name.into_owned())
        .collect();
    let has = |wanted: &str| names.iter().any(|name| name == wanted);
    let resource = names
        .iter()
        .find_map(|name| SUBRESOURCES.iter().find(|(n, _)| n == name))
        .map_or(if key { "OBJECT" } else { "BUCKET" }, |&(_, resource)| {
            resource
        });
    let resource = match resource {
        "TAGGING" if key => "OBJECT_TAGGING",
        "UPLOAD" if method == "PUT" && has("partNumber") => "PART",
        other => other,
    };
    format!("REST.{}.{resource}", method.to_ascii_uppercase())
}

/// The extra record's operation for a copy's source (`REST.COPY.OBJECT_GET`).
pub(crate) fn copy_source_operation(s3_operation: &str) -> Option<&'static str> {
    match s3_operation {
        "CopyObject" => Some("REST.COPY.OBJECT_GET"),
        "UploadPartCopy" => Some("REST.COPY.PART_GET"),
        _ => None,
    }
}

/// The key of a log object: `PREFIX` + `YYYY-MM-DD-hh-mm-ss-UNIQUE`, or partitioned
/// `PREFIX` + `ACCOUNT/REGION/BUCKET/YYYY/MM/DD/` + that, dated by the delivery or by
/// the records' day (at 00:00:00) as the configuration says.
pub(crate) fn object_key(
    config: &LoggingConfig,
    (account, region, source): (&str, &str, &str),
    first_record: SystemTime,
    delivered: SystemTime,
    unique: &str,
) -> String {
    let at = |time: SystemTime| OffsetDateTime::from(time);
    let name = |time: OffsetDateTime| {
        format!(
            "{:04}-{:02}-{:02}-{:02}-{:02}-{:02}-{unique}",
            time.year(),
            u8::from(time.month()),
            time.day(),
            time.hour(),
            time.minute(),
            time.second()
        )
    };
    let prefix = &config.target_prefix;
    match config.date_source() {
        None => format!("{prefix}{}", name(at(delivered))),
        Some(source_date) => {
            let time = match source_date {
                DateSource::EventTime => at(first_record).replace_time(time::Time::MIDNIGHT),
                DateSource::DeliveryTime => at(delivered),
            };
            format!(
                "{prefix}{account}/{region}/{source}/{:04}/{:02}/{:02}/{}",
                time.year(),
                u8::from(time.month()),
                time.day(),
                name(time)
            )
        }
    }
}

/// The UTC day a time falls on, as days since 1970: records of one day share a log
/// object where keys are dated by the records.
pub(crate) fn day(time: SystemTime) -> i64 {
    OffsetDateTime::from(time)
        .unix_timestamp()
        .div_euclid(86_400)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use teifs_types::logging::KeyFormat;

    use super::*;

    /// 2019-02-06 00:00:38 UTC.
    fn at(extra: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_549_411_238 + extra)
    }

    fn record() -> Record {
        Record {
            bucket: "awsexamplebucket1".to_owned(),
            time: at(0),
            remote: Some("192.0.2.3".parse().unwrap()),
            requester: Some("arn:aws:iam::123456789012:user/alice".to_owned()),
            request_id: "3E57427F3EXAMPLE".to_owned(),
            operation: "REST.GET.VERSIONING".to_owned(),
            key: None,
            request_uri: "GET /awsexamplebucket1?versioning HTTP/1.1".to_owned(),
            status: Some(200),
            error: None,
            sent: 113,
            object_size: None,
            total_ms: 7,
            turnaround_ms: None,
            referer: None,
            user_agent: Some("S3Console/0.4".to_owned()),
            version_id: None,
            signature: Some("SigV4"),
            auth: Some("AuthHeader"),
            host: Some("awsexamplebucket1.s3.us-west-1.amazonaws.com".to_owned()),
            tls: Some("TLSv1.2"),
            acl_required: false,
        }
    }

    #[test]
    fn records_are_s3s_27_fields() {
        // AWS's own example (LogFormat.html), with this drive's owner id.
        assert_eq!(
            record().line(),
            "teifs awsexamplebucket1 [06/Feb/2019:00:00:38 +0000] 192.0.2.3 \
             arn:aws:iam::123456789012:user/alice 3E57427F3EXAMPLE REST.GET.VERSIONING - \
             \"GET /awsexamplebucket1?versioning HTTP/1.1\" 200 - 113 - 7 - \"-\" \
             \"S3Console/0.4\" - - SigV4 - AuthHeader \
             awsexamplebucket1.s3.us-west-1.amazonaws.com TLSv1.2 - - -"
        );
        let mut refused = record();
        refused.requester = None;
        refused.remote = None;
        refused.key = Some("a dir/ü+\"q\".txt".to_owned());
        refused.error = Some("AccessDenied".to_owned());
        refused.status = Some(403);
        refused.sent = 0;
        refused.object_size = Some(10);
        refused.turnaround_ms = Some(3);
        refused.user_agent = Some("evil\" agent\n".to_owned());
        refused.version_id = Some("v 1".to_owned());
        refused.acl_required = true;
        refused.tls = None;
        assert_eq!(
            refused.line(),
            "teifs awsexamplebucket1 [06/Feb/2019:00:00:38 +0000] - - 3E57427F3EXAMPLE \
             REST.GET.VERSIONING a%20dir/%C3%BC%2B%22q%22.txt \
             \"GET /awsexamplebucket1?versioning HTTP/1.1\" 403 AccessDenied - 10 7 3 \"-\" \
             \"evil%22 agent%0A\" v%201 - SigV4 - AuthHeader \
             awsexamplebucket1.s3.us-west-1.amazonaws.com - - Yes -"
        );
    }

    #[test]
    fn operations_are_named_as_s3_names_them() {
        let name = |method, op, query, key| operation(method, op, query, key);
        assert_eq!(name("GET", "GetObject", None, true), "REST.GET.OBJECT");
        assert_eq!(name("HEAD", "HeadBucket", None, false), "REST.HEAD.BUCKET");
        assert_eq!(
            name("GET", "ListObjectsV2", Some("list-type=2&prefix=a"), false),
            "REST.GET.BUCKET"
        );
        assert_eq!(
            name("GET", "GetBucketAcl", Some("acl"), false),
            "REST.GET.ACL"
        );
        assert_eq!(
            name("PUT", "PutObjectAcl", Some("acl="), true),
            "REST.PUT.ACL"
        );
        assert_eq!(
            name("GET", "GetBucketTagging", Some("tagging"), false),
            "REST.GET.TAGGING"
        );
        assert_eq!(
            name("GET", "GetObjectTagging", Some("tagging&versionId=1"), true),
            "REST.GET.OBJECT_TAGGING"
        );
        assert_eq!(
            name("GET", "ListObjectVersions", Some("versions"), false),
            "REST.GET.BUCKETVERSIONS"
        );
        assert_eq!(
            name("POST", "CreateMultipartUpload", Some("uploads"), true),
            "REST.POST.UPLOADS"
        );
        assert_eq!(
            name("PUT", "UploadPart", Some("partNumber=1&uploadId=x"), true),
            "REST.PUT.PART"
        );
        assert_eq!(
            name("POST", "CompleteMultipartUpload", Some("uploadId=x"), true),
            "REST.POST.UPLOAD"
        );
        assert_eq!(
            name("POST", "DeleteObjects", Some("delete"), false),
            "REST.POST.MULTI_OBJECT_DELETE"
        );
        assert_eq!(
            name("GET", "GetBucketLogging", Some("logging"), false),
            "REST.GET.LOGGING_STATUS"
        );
        assert_eq!(name("PUT", "CopyObject", None, true), "REST.COPY.OBJECT");
        assert_eq!(
            name(
                "PUT",
                "UploadPartCopy",
                Some("partNumber=1&uploadId=x"),
                true
            ),
            "REST.COPY.PART"
        );
        assert_eq!(
            copy_source_operation("CopyObject"),
            Some("REST.COPY.OBJECT_GET")
        );
        assert_eq!(
            copy_source_operation("UploadPartCopy"),
            Some("REST.COPY.PART_GET")
        );
        assert_eq!(copy_source_operation("GetObject"), None);
    }

    fn config(key_format: Option<KeyFormat>) -> LoggingConfig {
        LoggingConfig {
            target_bucket: "logs".to_owned(),
            target_prefix: "app/".to_owned(),
            key_format,
            grants: Vec::new(),
        }
    }

    #[test]
    fn log_objects_are_named_as_s3_names_them() {
        let names = ("123456789012", "us-east-1", "app");
        // Delivered 2019-02-07 01:02:03, records from 2019-02-06.
        let delivered = at(86_400 + 3_600 + 2 * 60 + 3 - 38);
        let key = |format| object_key(&config(format), names, at(0), delivered, "0A1B2C3D4E5F6A7B");
        assert_eq!(key(None), "app/2019-02-07-01-02-03-0A1B2C3D4E5F6A7B");
        assert_eq!(key(Some(KeyFormat::Simple)), key(None));
        assert_eq!(
            key(Some(KeyFormat::Partitioned(None))),
            "app/123456789012/us-east-1/app/2019/02/06/2019-02-06-00-00-00-0A1B2C3D4E5F6A7B"
        );
        assert_eq!(
            key(Some(KeyFormat::Partitioned(Some(DateSource::EventTime)))),
            key(Some(KeyFormat::Partitioned(None)))
        );
        assert_eq!(
            key(Some(KeyFormat::Partitioned(Some(DateSource::DeliveryTime)))),
            "app/123456789012/us-east-1/app/2019/02/07/2019-02-07-01-02-03-0A1B2C3D4E5F6A7B"
        );
        assert_eq!(day(at(0)), day(at(86_400 - 39)));
        assert_ne!(day(at(0)), day(at(86_400 - 38)));
    }
}
