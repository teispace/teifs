//! Bucket notifications' delivery. The server's targets (webhooks, Elasticsearch
//! indexes, Redis keys, NSQ topics, NATS subjects, MQTT topics and SQS queues) are named by ARN, `arn:teifs:sqs::ID:TYPE`, and a bucket's rules pick which events go to which.
//! An event is queued on the drive before the request that made it is answered, and
//! each target's sender sends its events one at a time, in order, retrying one that
//! isn't taken with growing pauses until it is: a target that's down, or a restart,
//! loses nothing. A target with [`QUEUE_LIMIT`] events waiting drops new ones, counted.

#[cfg(test)]
mod tests;

mod aws;
mod elasticsearch;
mod lambda;
mod mqtt;
mod nats;
mod net;
mod nkey;
mod nsq;
mod queue;
mod redis;
mod sns;
mod sqs;
#[cfg(feature = "testing")]
pub mod testing;
mod webhook;

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

pub use aws::{AwsCredentials, region_of};
pub use elasticsearch::Elasticsearch;
pub use lambda::Lambda;
pub use mqtt::Mqtt;
pub use nats::Nats;
pub use net::tls_config;
pub use nkey::UserKey;
pub use nsq::Nsq;
pub use redis::Redis;
pub use sns::Sns;
pub use sqs::Sqs;
use teifs_types::notify::TargetArn;
use tokio::{sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;
pub use webhook::{Backoff, Webhook, client};

use crate::queue::Queue;

/// The most events that wait for one target (`MinIO`'s default); more are dropped.
pub const QUEUE_LIMIT: u64 = 100_000;
/// How many events a sender reads from the queue at a time.
const BATCH: usize = 100;

/// A target the server sends events to.
#[derive(Debug, Clone)]
pub struct TargetConfig {
    /// Its id, in its ARN.
    pub id: String,
    /// What it is.
    pub kind: TargetKind,
}

/// What a target is.
#[derive(Debug, Clone)]
pub enum TargetKind {
    /// A webhook, sent each event as JSON.
    Webhook(Webhook),
    /// An Elasticsearch index, each event a document.
    Elasticsearch(Elasticsearch),
    /// A Redis key: a hash, a field per object, or a list, an entry per event.
    Redis(Redis),
    /// An NSQ topic, published each event as JSON.
    Nsq(Nsq),
    /// A NATS subject, published each event as JSON, or a `JetStream` stream.
    Nats(Nats),
    /// An MQTT topic, published each event as JSON.
    Mqtt(Mqtt),
    /// An SQS queue, sent each event as S3 sends it.
    Sqs(Sqs),
    /// An SNS topic.
    Sns(Sns),
    /// A Lambda function, invoked with each event as S3 invokes it.
    Lambda(Lambda),
}

/// How a target that keeps documents keeps events (`MinIO`'s formats).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// One entry per object, replaced by each event, removed with the object.
    Namespace,
    /// One entry per event, added in order.
    Access,
}

impl Format {
    /// Reads `namespace` or `access`.
    ///
    /// # Errors
    ///
    /// When it's neither.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.to_ascii_lowercase().as_str() {
            "namespace" => Ok(Self::Namespace),
            "access" => Ok(Self::Access),
            _ => Err(format!("`{text}` isn't a format: give namespace or access")),
        }
    }

    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Namespace => "namespace",
            Self::Access => "access",
        }
    }
}

impl TargetConfig {
    /// A target named `id`, which must be letters, digits, `-` and `_`.
    ///
    /// # Errors
    ///
    /// When `id` isn't such a name.
    pub fn new(id: &str, kind: TargetKind) -> Result<Self, String> {
        let config = Self {
            id: id.to_owned(),
            kind,
        };
        if TargetArn::parse(&config.arn().to_string()).as_ref() == Some(&config.arn()) {
            Ok(config)
        } else {
            Err(format!(
                "`{id}` can't name a target: use letters, digits, `-` and `_`"
            ))
        }
    }

    /// Its ARN.
    #[must_use]
    pub fn arn(&self) -> TargetArn {
        TargetArn {
            id: self.id.clone(),
            kind: self.kind.name().to_owned(),
        }
    }

    /// Where it sends, without secrets: for the server's configuration.
    #[must_use]
    pub fn shown(&self) -> String {
        match &self.kind {
            TargetKind::Webhook(hook) => hook.shown(),
            TargetKind::Elasticsearch(es) => es.shown(),
            TargetKind::Redis(redis) => redis.shown(),
            TargetKind::Nsq(nsq) => nsq.shown(),
            TargetKind::Nats(nats) => nats.shown(),
            TargetKind::Mqtt(mqtt) => mqtt.shown(),
            TargetKind::Sqs(sqs) => sqs.shown(),
            TargetKind::Sns(sns) => sns.shown(),
            TargetKind::Lambda(lambda) => lambda.shown(),
        }
    }
}

impl TargetKind {
    /// Its type, in its ARN.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Webhook(_) => "webhook",
            Self::Elasticsearch(_) => "elasticsearch",
            Self::Redis(_) => "redis",
            Self::Nsq(_) => "nsq",
            Self::Nats(_) => "nats",
            Self::Mqtt(_) => "mqtt",
            Self::Sqs(_) => "sqs",
            Self::Sns(_) => "sns",
            Self::Lambda(_) => "lambda",
        }
    }

    /// Its ARN on AWS, when it's an AWS queue or topic: the other name rules may give it.
    #[must_use]
    pub fn aws_arn(&self) -> Option<String> {
        match self {
            Self::Sqs(sqs) => sqs.aws_arn(),
            Self::Sns(sns) => Some(sns.topic_arn.clone()),
            Self::Lambda(lambda) => Some(lambda.function_arn.clone()),
            _ => None,
        }
    }
}

/// How a target is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetStats {
    /// Its ARN.
    pub arn: TargetArn,
    /// Events waiting.
    pub queued: u64,
    /// Events it took.
    pub sent: u64,
    /// Tries it didn't take.
    pub failed: u64,
    /// Events dropped because too many were waiting.
    pub dropped: u64,
    /// Whether it took the last try.
    pub online: bool,
}

/// Why notifications can't start.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The queue can't be opened.
    #[error("can't open the notification queue {path}: {source}")]
    Queue {
        /// The queue's file.
        path: String,
        /// Why.
        source: rusqlite::Error,
    },
    /// The HTTP client can't be made.
    #[error("can't set up HTTPS for notifications: {0}")]
    Client(reqwest::Error),
}

/// One target, and how it's doing.
#[derive(Debug)]
struct Target {
    config: TargetConfig,
    /// Its name in the queue.
    key: String,
    queued: AtomicU64,
    sent: AtomicU64,
    failed: AtomicU64,
    dropped: AtomicU64,
    online: AtomicBool,
    /// Wakes its sender when events are added.
    added: Notify,
}

impl Target {
    /// Sends one queued event.
    async fn send(&self, client: &reqwest::Client, body: Vec<u8>) -> Result<(), String> {
        match &self.config.kind {
            TargetKind::Webhook(hook) => hook.post(client, "application/json", body).await,
            TargetKind::Elasticsearch(es) => es.send(client, &body).await,
            TargetKind::Redis(redis) => redis.send(&body).await,
            TargetKind::Nsq(nsq) => nsq.send(&body).await,
            TargetKind::Nats(nats) => nats.send(&body).await,
            TargetKind::Mqtt(mqtt) => mqtt.send(&body).await,
            TargetKind::Sqs(sqs) => sqs.send(client, &body).await,
            TargetKind::Sns(sns) => sns.send(client, &body).await,
            TargetKind::Lambda(lambda) => lambda.send(client, &body).await,
        }
    }

    /// Checks it takes events: a webhook is sent the test event `body`; a target that
    /// keeps documents is checked without writing one.
    async fn test(&self, client: &reqwest::Client, body: Vec<u8>) -> Result<(), String> {
        match &self.config.kind {
            TargetKind::Webhook(hook) => hook.post(client, "application/json", body).await,
            TargetKind::Elasticsearch(es) => es.test(client).await,
            TargetKind::Redis(redis) => redis.test().await,
            TargetKind::Nsq(nsq) => nsq.test().await,
            TargetKind::Nats(nats) => nats.test().await,
            TargetKind::Mqtt(mqtt) => mqtt.test().await,
            // As S3 does: the queue or topic is sent the test event.
            TargetKind::Sqs(sqs) => sqs.send(client, &body).await,
            TargetKind::Sns(sns) => sns.send(client, &body).await,
            // As S3 does: permission is checked, and no test event is sent.
            TargetKind::Lambda(lambda) => lambda.test(client).await,
        }
    }
}

/// The server's targets and their senders.
#[derive(Debug)]
pub struct Notifier {
    targets: BTreeMap<TargetArn, Arc<Target>>,
    queue: Option<Queue>,
    client: reqwest::Client,
    stopping: CancellationToken,
    senders: Mutex<Vec<JoinHandle<()>>>,
    /// The most events that wait for one target.
    limit: u64,
}

impl Notifier {
    /// A notifier without targets: rules can't name any, and nothing is queued.
    #[must_use]
    pub fn none() -> Self {
        Self {
            targets: BTreeMap::new(),
            queue: None,
            client: reqwest::Client::new(),
            stopping: CancellationToken::new(),
            senders: Mutex::new(Vec::new()),
            limit: QUEUE_LIMIT,
        }
    }

    /// Opens the queue at `path` (only when there are targets) and starts each target's
    /// sender, which begins with what was left waiting.
    ///
    /// # Errors
    ///
    /// When the queue can't be opened, or the HTTP client made.
    pub fn start(path: &Path, targets: Vec<TargetConfig>) -> Result<Self, OpenError> {
        Self::start_with_limit(path, targets, QUEUE_LIMIT)
    }

    fn start_with_limit(
        path: &Path,
        targets: Vec<TargetConfig>,
        limit: u64,
    ) -> Result<Self, OpenError> {
        if targets.is_empty() {
            return Ok(Self::none());
        }
        let opened = |source| OpenError::Queue {
            path: path.display().to_string(),
            source,
        };
        let queue = Queue::open(path).map_err(opened)?;
        let waiting = queue.counts().map_err(opened)?;
        let client = client().map_err(OpenError::Client)?;
        let targets: BTreeMap<_, _> = targets
            .into_iter()
            .map(|config| {
                let arn = config.arn();
                let key = arn.to_string();
                let target = Target {
                    queued: AtomicU64::new(waiting.get(&key).copied().unwrap_or(0)),
                    key,
                    config,
                    sent: AtomicU64::new(0),
                    failed: AtomicU64::new(0),
                    dropped: AtomicU64::new(0),
                    online: AtomicBool::new(true),
                    added: Notify::new(),
                };
                (arn, Arc::new(target))
            })
            .collect();
        for (key, count) in &waiting {
            if !targets.values().any(|t| &t.key == key) {
                tracing::warn!(
                    target = %key,
                    count,
                    "events wait for a target the server no longer has; they're kept"
                );
            }
        }
        let notifier = Self {
            targets,
            queue: Some(queue),
            client,
            stopping: CancellationToken::new(),
            senders: Mutex::new(Vec::new()),
            limit,
        };
        let senders = notifier
            .targets
            .values()
            .map(|target| {
                tokio::spawn(deliver(
                    Arc::clone(target),
                    notifier.queue.clone().expect("opened"),
                    notifier.client.clone(),
                    notifier.stopping.clone(),
                ))
            })
            .collect();
        *notifier
            .senders
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = senders;
        Ok(notifier)
    }

    /// Whether there are targets at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Whether `arn` names one of the targets.
    #[must_use]
    pub fn has(&self, arn: &TargetArn) -> bool {
        self.targets.contains_key(arn)
    }

    /// The target a rule's ARN names: `arn:teifs:sqs::ID:KIND` (or `MinIO`'s form), or an
    /// SQS queue's or SNS topic's own ARN on AWS, as S3's rules name them.
    #[must_use]
    pub fn resolve(&self, arn: &str) -> Option<TargetArn> {
        if let Some(ours) = TargetArn::parse(arn) {
            return self.has(&ours).then_some(ours);
        }
        self.targets
            .iter()
            .find(|(_, t)| t.config.kind.aws_arn().as_deref() == Some(arn.trim()))
            .map(|(ours, _)| ours.clone())
    }

    /// The targets.
    pub fn targets(&self) -> impl Iterator<Item = &TargetConfig> {
        self.targets.values().map(|t| &t.config)
    }

    /// Queues events, each for its target, before returning; targets it doesn't have
    /// are skipped, and a target with too many waiting drops them (counted).
    ///
    /// # Errors
    ///
    /// When the queue can't be written.
    pub async fn queue(&self, events: Vec<(TargetArn, Vec<u8>)>) -> Result<(), String> {
        let Some(queue) = self.queue.clone() else {
            return Ok(());
        };
        let mut added = Vec::with_capacity(events.len());
        let mut rows = Vec::with_capacity(events.len());
        for (arn, body) in events {
            let Some(target) = self.targets.get(&arn) else {
                continue;
            };
            let queued = target.queued.fetch_add(1, Ordering::Relaxed);
            if queued >= self.limit {
                target.queued.fetch_sub(1, Ordering::Relaxed);
                target.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            rows.push((target.key.clone(), body));
            added.push(Arc::clone(target));
        }
        if rows.is_empty() {
            return Ok(());
        }
        let pushed = tokio::task::spawn_blocking(move || queue.push(&rows))
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r.map_err(|e| e.to_string()));
        for target in &added {
            if pushed.is_ok() {
                target.added.notify_one();
            } else {
                target.queued.fetch_sub(1, Ordering::Relaxed);
                target.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        pushed
    }

    /// Tests `arn`'s target straight away, not queued, as a new rule's target is: a
    /// webhook is sent the test event `body`, and others are checked without it.
    ///
    /// # Errors
    ///
    /// When there's no such target, or it doesn't take it.
    pub async fn send_now(&self, arn: &TargetArn, body: Vec<u8>) -> Result<(), String> {
        let target = self
            .targets
            .get(arn)
            .ok_or_else(|| format!("no target {arn}"))?;
        target.test(&self.client, body).await
    }

    /// How each target is doing.
    #[must_use]
    pub fn stats(&self) -> Vec<TargetStats> {
        self.targets
            .iter()
            .map(|(arn, t)| TargetStats {
                arn: arn.clone(),
                queued: t.queued.load(Ordering::Relaxed),
                sent: t.sent.load(Ordering::Relaxed),
                failed: t.failed.load(Ordering::Relaxed),
                dropped: t.dropped.load(Ordering::Relaxed),
                online: t.online.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// Stops the senders; what's waiting is sent after the next start.
    pub async fn stop(&self) {
        self.stopping.cancel();
        let senders =
            std::mem::take(&mut *self.senders.lock().unwrap_or_else(PoisonError::into_inner));
        for sender in senders {
            let _ = sender.await;
        }
    }
}

/// Sends a target's events in order, each until it's taken, until the server stops.
async fn deliver(
    target: Arc<Target>,
    queue: Queue,
    client: reqwest::Client,
    stopping: CancellationToken,
) {
    let mut backoff = Backoff::new();
    let to = target.config.shown();
    loop {
        let (key, read) = (target.key.clone(), queue.clone());
        let batch = match tokio::task::spawn_blocking(move || read.peek(&key, BATCH)).await {
            Ok(Ok(batch)) => batch,
            Ok(Err(err)) => {
                tracing::error!(error = %err, "can't read the notification queue");
                if pause(&stopping, backoff.next_pause()).await {
                    return;
                }
                continue;
            }
            Err(_) => return,
        };
        if batch.is_empty() {
            tokio::select! {
                () = stopping.cancelled() => return,
                () = target.added.notified() => continue,
            }
        }
        let mut sent = None;
        for (seq, body) in batch {
            loop {
                let result = tokio::select! {
                    () = stopping.cancelled() => {
                        forget(&target, &queue, sent).await;
                        return;
                    }
                    result = target.send(&client, body.clone()) => result,
                };
                match result {
                    Ok(()) => {
                        target.sent.fetch_add(1, Ordering::Relaxed);
                        if !target.online.swap(true, Ordering::Relaxed) {
                            tracing::info!(to, "the notification target takes events again");
                        }
                        backoff.reset();
                        sent = Some(seq);
                        break;
                    }
                    Err(err) => {
                        target.failed.fetch_add(1, Ordering::Relaxed);
                        if target.online.swap(false, Ordering::Relaxed) {
                            tracing::error!(
                                error = %err,
                                to,
                                "the notification target didn't take an event; trying again"
                            );
                        }
                        // What was sent isn't sent again after a restart.
                        forget(&target, &queue, sent.take()).await;
                        if pause(&stopping, backoff.next_pause()).await {
                            return;
                        }
                    }
                }
            }
        }
        forget(&target, &queue, sent).await;
    }
}

/// Removes the target's events through `sent` from the queue.
async fn forget(target: &Arc<Target>, queue: &Queue, sent: Option<i64>) {
    let Some(seq) = sent else {
        return;
    };
    let (key, queue) = (target.key.clone(), queue.clone());
    match tokio::task::spawn_blocking(move || queue.remove_through(&key, seq)).await {
        Ok(Ok(removed)) => {
            target.queued.fetch_sub(removed, Ordering::Relaxed);
        }
        Ok(Err(err)) => {
            tracing::error!(error = %err, "can't remove sent events from the notification queue");
        }
        Err(_) => {}
    }
}

/// Waits `pause`, or until the server stops (then `true`).
async fn pause(stopping: &CancellationToken, pause: Duration) -> bool {
    tokio::select! {
        () = stopping.cancelled() => true,
        () = tokio::time::sleep(pause) => false,
    }
}
