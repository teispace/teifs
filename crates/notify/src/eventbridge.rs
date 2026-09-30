//! EventBridge, as S3 sends to it: a bucket with EventBridge turned on sends each of its
//! events to the server's event bus, whatever its rules say, as S3's own event types
//! (`detail-type` `Object Created`, `Object Deleted`…) with S3's `detail`, using
//! `PutEvents` in EventBridge's JSON protocol, signed with Signature Version 4.
//!
//! Only AWS's services may send events whose source starts with `aws.`, so the source
//! is `teifs.s3` unless another is given; EventBridge fills in the rest of the envelope
//! (`id`, `account`, `region`, `time` from the entry).

use teifs_types::notify::{EventMessage, EventRecord, event_key_decoded};

use crate::aws::{self, Answer, AwsCredentials, Call};

/// The ETag of an empty object, which S3 gives delete markers.
const EMPTY_ETAG: &str = "d41d8cd98f00b204e9800998ecf8427e";

/// The source events are sent with, unless another is given.
pub const SOURCE: &str = "teifs.s3";

/// The event bus a server's buckets send to.
#[derive(Debug, Clone)]
pub struct EventBridge {
    /// The bus's ARN: `arn:aws:events:REGION:ACCOUNT:event-bus/NAME`.
    pub bus_arn: String,
    /// The region, from the ARN.
    pub region: String,
    /// Where requests go: EventBridge's endpoint in the region, unless another is given.
    pub endpoint: reqwest::Url,
    /// The events' `source`.
    pub source: String,
    /// The keys requests are signed with; none sends them unsigned.
    pub credentials: Option<AwsCredentials>,
}

impl EventBridge {
    /// Events for the bus `bus_arn`, sent to `endpoint` (by default EventBridge's endpoint
    /// in the bus's region) as coming from `source` (by default [`SOURCE`]).
    ///
    /// # Errors
    ///
    /// When `bus_arn` isn't an event bus's ARN, `source` isn't one EventBridge takes from
    /// a caller, or `endpoint` isn't an `http` or `https` URL without credentials in it.
    pub fn new(
        bus_arn: &str,
        endpoint: Option<&str>,
        source: Option<&str>,
    ) -> Result<Self, String> {
        let bus_arn = bus_arn.trim();
        let wrong = || {
            format!(
                "`{bus_arn}` isn't an event bus's ARN: give \
                 arn:aws:events:REGION:ACCOUNT:event-bus/default"
            )
        };
        let parts: Vec<&str> = bus_arn.split(':').collect();
        let ["arn", partition, "events", region, account, resource] = parts.as_slice() else {
            return Err(wrong());
        };
        let name = resource.strip_prefix("event-bus/").unwrap_or_default();
        let named = |s: &str, extra: &[u8]| {
            !s.is_empty()
                && s.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || extra.contains(&b)
                })
        };
        if !partition.starts_with("aws")
            || !named(region, &[])
            || account.len() != 12
            || !account.bytes().all(|b| b.is_ascii_digit())
            || !named(name, b"./")
        {
            return Err(wrong());
        }
        let source = source.unwrap_or(SOURCE).trim();
        if source.is_empty() || source.len() > 256 || source.starts_with("aws.") {
            return Err(format!(
                "`{source}` can't be a source: only AWS's services may send `aws.` sources"
            ));
        }
        Ok(Self {
            bus_arn: bus_arn.to_owned(),
            region: (*region).to_owned(),
            endpoint: aws::endpoint("events", partition, region, endpoint)?,
            source: source.to_owned(),
            credentials: None,
        })
    }

    /// Where it sends.
    #[must_use]
    pub fn shown(&self) -> String {
        format!("{} at {} as {}", self.bus_arn, self.endpoint, self.source)
    }

    /// Sends a queued event as S3 sends it to EventBridge.
    pub(crate) async fn send(&self, client: &reqwest::Client, body: &[u8]) -> Result<(), String> {
        let event: EventMessage =
            serde_json::from_slice(body).map_err(|_| "not an event".to_owned())?;
        let entries: Vec<serde_json::Value> = event
            .records
            .iter()
            .filter_map(|record| {
                let (detail_type, detail) = detail(record)?;
                Some(serde_json::json!({
                    "Source": self.source,
                    "DetailType": detail_type,
                    "Detail": detail.to_string(),
                    "Resources": [format!("arn:aws:s3:::{}", record.s3.bucket.name)],
                    "Time": record.event_time,
                    "EventBusName": self.bus_arn,
                }))
            })
            .collect();
        if entries.is_empty() {
            return Ok(());
        }
        let call = Call {
            service: "events",
            region: &self.region,
            url: &self.endpoint,
            headers: &[
                ("content-type", "application/x-amz-json-1.1"),
                ("x-amz-target", "AWSEvents.PutEvents"),
            ],
            body: serde_json::json!({ "Entries": entries })
                .to_string()
                .into_bytes(),
        };
        let Answer {
            status,
            error_type,
            body,
        } = call.send(client, self.credentials.as_ref()).await?;
        let answer: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        if !status.is_success() {
            let kind = error_type
                .or_else(|| {
                    answer["__type"]
                        .as_str()
                        .map(|t| t.rsplit('#').next().unwrap_or(t).to_owned())
                })
                .unwrap_or_default();
            let why = answer["message"]
                .as_str()
                .or(answer["Message"].as_str())
                .unwrap_or("no reason");
            return Err(format!("EventBridge answered {status}: {kind} ({why})"));
        }
        if answer["FailedEntryCount"].as_u64() != Some(0) {
            let failed = answer["Entries"]
                .as_array()
                .and_then(|e| e.iter().find(|e| e["ErrorCode"].is_string()));
            return Err(match failed {
                Some(entry) => format!(
                    "EventBridge didn't take the event: {} ({})",
                    entry["ErrorCode"].as_str().unwrap_or_default(),
                    entry["ErrorMessage"].as_str().unwrap_or("no reason")
                ),
                None => "EventBridge's answer doesn't say it took the event".to_owned(),
            });
        }
        Ok(())
    }
}

/// Whether S3 sends events named `event` (`s3:ObjectCreated:Put`) to EventBridge.
#[must_use]
pub fn sends(event: &str) -> bool {
    kind(event.strip_prefix("s3:").unwrap_or(event)).is_some()
}

/// The `detail-type` S3 gives an event, and its `reason` if it has one.
fn kind(name: &str) -> Option<(&'static str, Option<&'static str>)> {
    Some(match name {
        "ObjectCreated:Put" => ("Object Created", Some("PutObject")),
        "ObjectCreated:Post" => ("Object Created", Some("POST Object")),
        "ObjectCreated:Copy" => ("Object Created", Some("CopyObject")),
        "ObjectCreated:CompleteMultipartUpload" => {
            ("Object Created", Some("CompleteMultipartUpload"))
        }
        "ObjectRemoved:Delete" | "ObjectRemoved:DeleteMarkerCreated" => {
            ("Object Deleted", Some("DeleteObject"))
        }
        "LifecycleExpiration:Delete" | "LifecycleExpiration:DeleteMarkerCreated" => {
            ("Object Deleted", Some("Lifecycle Expiration"))
        }
        "ObjectTagging:Put" => ("Object Tags Added", None),
        "ObjectTagging:Delete" => ("Object Tags Deleted", None),
        "ObjectAcl:Put" => ("Object ACL Updated", None),
        "ObjectRetention:Put" => ("Object Retention Updated", None),
        "LifecycleTransition" => ("Object Storage Class Changed", None),
        _ => return None,
    })
}

/// The `detail-type` and `detail` S3 sends EventBridge for `record`, if it sends one.
fn detail(record: &EventRecord) -> Option<(&'static str, serde_json::Value)> {
    let (detail_type, reason) = kind(&record.event_name)?;
    let lifecycle = reason == Some("Lifecycle Expiration");
    let object = &record.s3.object;
    let mut about = serde_json::json!({ "key": event_key_decoded(&object.key) });
    if let Some(size) = object.size {
        about["size"] = size.into();
    }
    if let Some(etag) = &object.e_tag {
        about["etag"] = etag.clone().into();
    }
    if let Some(version) = &object.version_id {
        about["version-id"] = version.clone().into();
    }
    about["sequencer"] = object.sequencer.clone().into();
    let mut detail = serde_json::json!({
        "version": "0",
        "event-version": "1.2",
        "bucket": { "name": record.s3.bucket.name },
        "object": about,
        "request-id": record.response_elements.request_id,
        // Lifecycle's work is S3's own, as AWS says.
        "requester": if lifecycle { "s3.amazonaws.com" } else { record.user_identity.principal_id.as_str() },
    });
    if !lifecycle && !record.request_parameters.source_ip_address.is_empty() {
        detail["source-ip-address"] = record.request_parameters.source_ip_address.clone().into();
    }
    if let Some(reason) = reason {
        detail["reason"] = reason.into();
    }
    if detail_type == "Object Deleted" {
        let marker = record.event_name.ends_with(":DeleteMarkerCreated");
        detail["deletion-type"] = if marker {
            "Delete Marker Created"
        } else {
            "Permanently Deleted"
        }
        .into();
        if marker && detail["object"].get("etag").is_none() {
            // A delete marker is empty: S3 gives it the empty object's ETag.
            detail["object"]["etag"] = EMPTY_ETAG.into();
        }
    }
    Some((detail_type, detail))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buses_and_sources_are_checked() {
        let bus = EventBridge::new(
            "arn:aws:events:eu-west-1:123456789012:event-bus/default",
            None,
            None,
        )
        .unwrap();
        assert_eq!(bus.region, "eu-west-1");
        assert_eq!(bus.source, "teifs.s3");
        assert_eq!(
            bus.endpoint.as_str(),
            "https://events.eu-west-1.amazonaws.com/"
        );
        let own = EventBridge::new(
            "arn:aws:events:us-east-1:000000000000:event-bus/s3",
            Some("http://localhost:4566"),
            Some("acme.storage"),
        )
        .unwrap();
        assert_eq!(
            (own.source.as_str(), own.endpoint.as_str()),
            ("acme.storage", "http://localhost:4566/")
        );
        for bad in [
            "default",
            "arn:aws:events:eu-west-1:123456789012:rule/r",
            "arn:aws:events:eu-west-1:1234:event-bus/default",
            "arn:aws:sns:eu-west-1:123456789012:event-bus/default",
            "arn:aws:events:eu-west-1:123456789012:event-bus/",
        ] {
            assert!(EventBridge::new(bad, None, None).is_err(), "{bad}");
        }
        let arn = "arn:aws:events:eu-west-1:123456789012:event-bus/default";
        assert!(EventBridge::new(arn, None, Some("aws.s3")).is_err());
        assert!(EventBridge::new(arn, None, Some(" ")).is_err());
    }

    #[test]
    fn s3s_event_types_are_the_ones_sent() {
        for (event, sent) in [
            ("s3:ObjectCreated:Put", true),
            ("s3:ObjectRemoved:DeleteMarkerCreated", true),
            ("s3:LifecycleExpiration:Delete", true),
            ("s3:ObjectTagging:Delete", true),
            ("s3:ObjectAccessed:Get", false),
            ("s3:ObjectCreated:PutLegalHold", false),
            ("s3:TestEvent", false),
        ] {
            assert_eq!(sends(event), sent, "{event}");
        }
    }

    fn record(name: &str) -> EventRecord {
        serde_json::from_value(serde_json::json!({
            "eventVersion": "2.6", "eventSource": "aws:s3", "awsRegion": "eu-west-1",
            "eventTime": "2026-09-30T12:00:00.000Z", "eventName": name,
            "userIdentity": {"principalId": "AKIDUSER"},
            "requestParameters": {"sourceIPAddress": "192.0.2.1"},
            "responseElements": {"x-amz-request-id": "REQ1", "x-amz-id-2": "host"},
            "s3": {
                "s3SchemaVersion": "1.0", "configurationId": "",
                "bucket": {"name": "photos", "ownerIdentity": {"principalId": "o"},
                           "arn": "arn:aws:s3:::photos"},
                "object": {"key": "a+b%2Fc.jpg", "size": 5, "eTag": "e",
                           "versionId": "v1", "sequencer": "0A"}
            }
        }))
        .unwrap()
    }

    #[test]
    fn details_are_s3s() {
        let (kind, created) = detail(&record("ObjectCreated:CompleteMultipartUpload")).unwrap();
        assert_eq!(kind, "Object Created");
        assert_eq!(
            created,
            serde_json::json!({
                "version": "0", "event-version": "1.2",
                "bucket": {"name": "photos"},
                "object": {"key": "a b/c.jpg", "size": 5, "etag": "e", "version-id": "v1",
                           "sequencer": "0A"},
                "request-id": "REQ1", "requester": "AKIDUSER",
                "source-ip-address": "192.0.2.1", "reason": "CompleteMultipartUpload",
            })
        );
        let mut untagged = record("ObjectRemoved:DeleteMarkerCreated");
        untagged.s3.object.e_tag = None;
        let (_, marker) = detail(&untagged).unwrap();
        assert_eq!(marker["object"]["etag"], EMPTY_ETAG);
        assert_eq!(
            (&marker["reason"], &marker["deletion-type"]),
            (&"DeleteObject".into(), &"Delete Marker Created".into())
        );
        let mut gone = record("LifecycleExpiration:Delete");
        gone.s3.object.e_tag = None;
        let (_, expired) = detail(&gone).unwrap();
        assert!(
            expired["object"].get("etag").is_none(),
            "only markers get one"
        );
        assert_eq!(expired["reason"], "Lifecycle Expiration");
        assert_eq!(expired["deletion-type"], "Permanently Deleted");
        assert_eq!(expired["requester"], "s3.amazonaws.com");
        assert!(expired.get("source-ip-address").is_none());
        let (kind, tags) = detail(&record("ObjectTagging:Delete")).unwrap();
        assert_eq!(kind, "Object Tags Deleted");
        assert!(tags.get("reason").is_none() && tags.get("deletion-type").is_none());
        for (name, kind) in [
            ("ObjectCreated:Post", "Object Created"),
            ("ObjectAcl:Put", "Object ACL Updated"),
            ("ObjectRetention:Put", "Object Retention Updated"),
        ] {
            assert_eq!(detail(&record(name)).unwrap().0, kind, "{name}");
        }
        assert!(detail(&record("ObjectAccessed:Get")).is_none());
    }
}
