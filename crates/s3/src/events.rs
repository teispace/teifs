//! Bucket notifications' events: what a request did to objects, as S3 describes it,
//! sent to the targets a bucket's rules pick (queued on the drive before the request is
//! answered, see `teifs_notify`) and to whoever listens ([`crate::listen`]). Nothing is
//! built unless the server has targets or someone listens.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use teifs_notify::Notifier;
use teifs_store::{Expirations, OWNER_ID, ObjectInfo, Store};
use teifs_types::notify::{
    BucketEntity, EVENT_VERSION, EventMessage, EventRecord, Identity, ObjectEntity,
    RequestParameters, ResponseElements, S3Entity, TargetArn, TestEvent, event_key,
};
use time::OffsetDateTime;

use crate::{
    access::Client,
    drive::REGION,
    listen::{Heard, Listeners},
    observe::Seen,
};

/// The `configurationId` of listeners' events, which no rule sends (`MinIO`'s).
const LISTENED: &str = "Config";

/// What happened to one object.
#[derive(Debug, Clone, Default)]
pub(crate) struct Happened {
    pub(crate) key: String,
    pub(crate) size: Option<u64>,
    /// Its ETag, unquoted.
    pub(crate) etag: Option<String>,
    pub(crate) version_id: Option<String>,
}

impl Happened {
    /// A version written or read: its key, size, ETag and version id.
    pub(crate) fn of(info: &ObjectInfo) -> Self {
        Self {
            key: info.key.clone(),
            size: Some(info.size),
            etag: Some(info.etag.clone()),
            version_id: crate::drive::written_version(info),
        }
    }

    /// Something done to a key (its version, if named).
    pub(crate) fn to(key: &str) -> Self {
        Self {
            key: key.to_owned(),
            ..Self::default()
        }
    }
}

/// The request an event came from.
struct Request {
    id: String,
    access_key: String,
    ip: String,
    time: String,
}

impl Request {
    fn of(extensions: &http::Extensions) -> Self {
        let seen = extensions.get::<Arc<Seen>>();
        Self {
            id: crate::observe::request_id(extensions),
            access_key: seen
                .and_then(|seen| seen.access_key())
                .unwrap_or_default()
                .to_owned(),
            ip: extensions
                .get::<Client>()
                .and_then(|client| client.ip)
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            time: event_time(SystemTime::now()),
        }
    }
}

/// Sends a drive's events to the server's targets and its listeners.
#[derive(Debug, Clone)]
pub(crate) struct Events {
    store: Store,
    notifier: Arc<Notifier>,
    listeners: Arc<Listeners>,
}

impl Events {
    pub(crate) fn new(store: Store, notifier: Arc<Notifier>) -> Self {
        Self {
            store,
            notifier,
            listeners: Arc::new(Listeners::new()),
        }
    }

    pub(crate) fn notifier(&self) -> &Notifier {
        &self.notifier
    }

    pub(crate) fn listeners(&self) -> &Listeners {
        &self.listeners
    }

    /// Tells listeners that the request with these extensions did `name`
    /// (`BucketCreated:*`) to `bucket`: bucket events aren't sent to targets.
    pub(crate) fn bucket(&self, extensions: &http::Extensions, name: &str, bucket: &str) {
        if self.listeners.listened() {
            let request = Request::of(extensions);
            let record = self.record(&request, name, bucket, LISTENED, &Happened::default());
            self.listeners
                .tell(Heard::new(bucket, &format!("s3:{name}"), "", &record));
        }
    }

    /// Records that the request with these extensions did `name` (`ObjectCreated:Put`)
    /// to objects in `bucket`, for the rules that want it. A failure is logged: what
    /// the request did is done.
    pub(crate) async fn happened(
        &self,
        extensions: &http::Extensions,
        name: &str,
        bucket: &str,
        objects: Vec<Happened>,
    ) {
        let listened = self.listeners.listened();
        if (self.notifier.is_empty() && !listened) || objects.is_empty() {
            return;
        }
        let event = format!("s3:{name}");
        let request = Request::of(extensions);
        if listened {
            for object in &objects {
                let record = self.record(&request, name, bucket, LISTENED, object);
                self.listeners
                    .tell(Heard::new(bucket, &event, &object.key, &record));
            }
        }
        if self.notifier.is_empty() {
            return;
        }
        let config = match self.store.bucket_notifications(bucket).await {
            Ok(Some(config)) => config,
            Ok(None) => return,
            Err(err) => {
                tracing::error!(error = %err, bucket, "can't read the bucket's notification rules");
                return;
            }
        };
        let mut queued = Vec::new();
        for object in &objects {
            for rule in config.matching(&event, &object.key) {
                let Some(arn) = rule.target() else {
                    continue;
                };
                let message = EventMessage {
                    event_name: event.clone(),
                    key: format!("{bucket}/{}", object.key),
                    records: vec![self.record(&request, name, bucket, &rule.id, object)],
                };
                let body = serde_json::to_vec(&message).expect("an event serializes");
                queued.push((arn, body));
            }
        }
        if queued.is_empty() {
            return;
        }
        if let Err(err) = self.notifier.queue(queued).await {
            tracing::error!(error = %err, bucket, "can't queue the request's notifications");
        }
    }

    fn record(
        &self,
        request: &Request,
        name: &str,
        bucket: &str,
        rule: &str,
        object: &Happened,
    ) -> EventRecord {
        EventRecord {
            event_version: EVENT_VERSION.to_owned(),
            event_source: "aws:s3".to_owned(),
            aws_region: REGION.to_owned(),
            event_time: request.time.clone(),
            event_name: name.to_owned(),
            user_identity: Identity {
                principal_id: request.access_key.clone(),
            },
            request_parameters: RequestParameters {
                source_ip_address: request.ip.clone(),
            },
            response_elements: ResponseElements {
                request_id: request.id.clone(),
                host_id: self.store.format().drive.clone(),
            },
            s3: S3Entity {
                s3_schema_version: "1.0".to_owned(),
                configuration_id: rule.to_owned(),
                bucket: BucketEntity {
                    name: bucket.to_owned(),
                    owner_identity: Identity {
                        principal_id: OWNER_ID.to_owned(),
                    },
                    arn: format!("arn:aws:s3:::{bucket}"),
                },
                object: ObjectEntity {
                    key: event_key(&object.key),
                    size: object.size,
                    e_tag: object.etag.clone(),
                    version_id: object.version_id.clone(),
                    // Request ids only grow, as a key's sequencers must.
                    sequencer: request.id.clone(),
                },
            },
        }
    }

    /// Sends S3's test event to `arn`'s target, which a rule now names.
    pub(crate) async fn test(
        &self,
        extensions: &http::Extensions,
        bucket: &str,
        arn: &TargetArn,
    ) -> Result<(), String> {
        let request = Request::of(extensions);
        let test = TestEvent {
            service: "TeiFS".to_owned(),
            event: teifs_types::notify::TEST_EVENT.to_owned(),
            time: request.time,
            bucket: bucket.to_owned(),
            request_id: request.id,
            host_id: self.store.format().drive.clone(),
        };
        let body = serde_json::to_vec(&test).expect("a test event serializes");
        self.notifier.send_now(arn, body).await
    }
}

/// What lifecycle rules remove: `LifecycleExpiration:Delete`, or
/// `LifecycleExpiration:DeleteMarkerCreated` for a versioned bucket's current version.
impl Expirations for Events {
    fn expired<'a>(
        &'a self,
        bucket: &'a str,
        key: &'a str,
        version_id: Option<String>,
        marker: bool,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let name = if marker {
                "LifecycleExpiration:DeleteMarkerCreated"
            } else {
                "LifecycleExpiration:Delete"
            };
            let happened = Happened {
                version_id,
                ..Happened::to(key)
            };
            // No request: no client, and a new id to order it by.
            let extensions = http::Extensions::new();
            self.happened(&extensions, name, bucket, vec![happened])
                .await;
        })
    }
}

/// A time as events give it: `2026-09-30T12:00:00.000Z`.
fn event_time(time: SystemTime) -> String {
    let t = OffsetDateTime::from(time);
    let millis = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_millis());
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn times_have_milliseconds_in_utc() {
        let time = UNIX_EPOCH + Duration::from_millis(1_790_000_000_042);
        assert_eq!(event_time(time), "2026-09-21T14:13:20.042Z");
    }
}
