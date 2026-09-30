//! The scrub job: reads every stored version back, now and then, and checks it against
//! what was recorded when it was written ([`Store::verify_next`]), so damage on the disk
//! is found while there's still a copy elsewhere to restore from, not when a client
//! next asks for the object.
//!
//! A pass starts a set time after the last one started, goes through the drive a
//! bounded piece per step, and keeps where it is and what it found in the system
//! database, so a restart carries on where it stopped. Damage is logged as it's found;
//! what the passes found is in [`Store::scrub_report`].

use std::time::Duration;

use serde::{Deserialize, Serialize};
use teifs_types::verify::{ScrubPass, ScrubReport, Verdict};

use super::{BATCH, Job, Step, millis, millis_of};
use crate::{Inner, Store, StoreError, VerifyCursor, error::Result};

/// Where the scrub's state is kept, among the drive's settings.
const SETTING: &str = "scrub";
/// The most bytes a step reads, by default.
const STEP_BYTES: u64 = 64 * 1024 * 1024;
/// Versions listed at a time.
const LISTED: usize = 16;

/// What the scrub keeps between steps and restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct State {
    /// When the drive was first scrubbed for: the first pass is due a full interval
    /// after, not at once.
    since_ms: i64,
    /// The pass under way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    current: Option<Current>,
    /// The last pass that finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last: Option<ScrubPass>,
}

impl State {
    /// A scrub that hasn't passed yet, first seen at `since_ms`.
    pub(crate) fn since(since_ms: i64) -> Self {
        Self {
            since_ms,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Current {
    #[serde(flatten)]
    pass: ScrubPass,
    cursor: VerifyCursor,
}

/// Checks the drive's stored bytes, a pass every `every`.
pub(crate) struct Scrub {
    store: Store,
    every: Duration,
    /// The most bytes a step reads (it stops after the object that goes past it).
    pub(crate) step_bytes: u64,
}

impl Scrub {
    pub(crate) fn new(store: Store, every: Duration) -> Self {
        Self {
            store,
            every,
            step_bytes: STEP_BYTES,
        }
    }

    /// One bounded piece of a pass: how many versions it checked, 0 when no pass is due.
    pub(crate) async fn run(&mut self, step: &Step) -> Result<usize> {
        let now = millis(step.now);
        let mut state = if let Some(state) = self.store.scrub_state().await? {
            state
        } else {
            let state = State::since(now);
            self.store.set_scrub_state(&state).await?;
            state
        };
        let mut current = if let Some(current) = state.current.take() {
            current
        } else {
            let from = state.last.as_ref().map_or(state.since_ms, |l| l.started_ms);
            if now < from.saturating_add(millis_of(self.every)) {
                return Ok(0);
            }
            tracing::info!("a scrub pass starts: every stored version is read back");
            Current {
                pass: ScrubPass {
                    started_ms: now,
                    ..ScrubPass::default()
                },
                cursor: VerifyCursor::default(),
            }
        };
        let (mut checked, mut bytes) = (0, 0);
        let finished = loop {
            let found = self
                .store
                .verify_until(&mut current.cursor, None, LISTED, Some(&step.cancel))
                .await?;
            if step.cancel.is_cancelled() {
                // What was checked counts; the version cut short is checked again.
                for item in found {
                    record(&mut current.pass, item);
                    checked += 1;
                }
                break false;
            }
            if found.is_empty() {
                break true;
            }
            for item in found {
                bytes += item.size;
                record(&mut current.pass, item);
                checked += 1;
            }
            if bytes >= self.step_bytes || checked >= BATCH {
                break false;
            }
        };
        if finished {
            let mut pass = current.pass;
            pass.finished_ms = Some(millis(std::time::SystemTime::now()).max(now));
            tracing::info!(
                versions = pass.versions,
                bytes = pass.bytes,
                damaged = pass.damaged,
                unverifiable = pass.unverifiable,
                "a scrub pass finished"
            );
            state.last = Some(pass);
        } else {
            state.current = Some(current);
        }
        self.store.set_scrub_state(&state).await?;
        // A pass over an empty drive still did its work.
        Ok(checked.max(usize::from(finished)))
    }
}

/// Counts `item` into `pass`, logging damage as it's found.
fn record(pass: &mut ScrubPass, item: teifs_types::verify::Checked) {
    if let Verdict::Damaged { damage } = &item.verdict {
        tracing::error!(
            bucket = item.bucket,
            key = item.key,
            version = item.version_id,
            damage = ?damage,
            "a stored version is damaged: restore it from a copy"
        );
    }
    pass.record(item);
}

impl Job for Scrub {
    fn name(&self) -> &'static str {
        "scrub"
    }

    fn step(&mut self, _inner: &Inner, step: &Step) -> Result<usize> {
        // Steps run on the blocking pool, where waiting on the store's work is allowed.
        tokio::runtime::Handle::current().block_on(self.run(step))
    }

    fn idle(&self) -> Duration {
        self.every.min(Duration::from_hours(1))
    }
}

impl Store {
    /// What the drive's scrubs have found: the pass under way and the last one that
    /// finished (both empty until the first pass starts).
    pub async fn scrub_report(&self) -> Result<ScrubReport> {
        let state = self.scrub_state().await?.unwrap_or_default();
        Ok(ScrubReport {
            current: state.current.map(|c| c.pass),
            last: state.last,
        })
    }

    async fn scrub_state(&self) -> Result<Option<State>> {
        self.blocking(|inner| {
            inner
                .system()
                .setting(SETTING)?
                .map(|json| serde_json::from_str(&json).map_err(|_| StoreError::CorruptMetadata))
                .transpose()
        })
        .await
    }

    pub(crate) async fn set_scrub_state(&self, state: &State) -> Result<()> {
        let json = serde_json::to_string(state).expect("the scrub's state serializes");
        self.blocking(move |inner| Ok(inner.system().set_setting(SETTING, Some(&json))?))
            .await
    }
}
