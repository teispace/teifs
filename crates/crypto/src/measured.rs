//! A KMS that counts its calls and how long they took, as `MinIO` reports its KMS's
//! (`mc admin kms` metrics).

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use crate::{Context, CryptoError, DataKey, KeyInfo, Kms, Result, SealedKey};

/// The upper bounds of the latency histogram's buckets, as `MinIO`'s.
pub const LATENCY_BUCKETS: [Duration; 10] = [
    Duration::from_millis(10),
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_millis(1500),
    Duration::from_secs(3),
    Duration::from_secs(5),
    Duration::from_secs(10),
];

/// What a [`Measured`] KMS has counted since it was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsMetrics {
    /// Calls that succeeded.
    pub ok: u64,
    /// Calls the KMS refused: no such key, a key or context that doesn't open a seal.
    pub errors: u64,
    /// Calls the KMS failed: it didn't answer, or answered that it failed.
    pub failures: u64,
    /// For each of [`LATENCY_BUCKETS`], the calls that took less (cumulative: a call
    /// is in its bucket and every later one; the last also holds slower calls).
    pub latency: [u64; LATENCY_BUCKETS.len()],
}

/// A KMS whose calls that use or create keys (seal, unseal, create, rotate) are
/// counted; listing keys isn't.
#[derive(Debug)]
pub struct Measured {
    inner: Arc<dyn Kms>,
    ok: AtomicU64,
    errors: AtomicU64,
    failures: AtomicU64,
    latency: [AtomicU64; LATENCY_BUCKETS.len()],
}

impl Measured {
    /// `inner`, counted.
    #[must_use]
    pub fn new(inner: Arc<dyn Kms>) -> Self {
        Self {
            inner,
            ok: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            latency: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// What was counted so far.
    #[must_use]
    pub fn metrics(&self) -> KmsMetrics {
        KmsMetrics {
            ok: self.ok.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            latency: std::array::from_fn(|i| self.latency[i].load(Ordering::Relaxed)),
        }
    }

    fn count<T>(&self, started: Instant, result: Result<T>) -> Result<T> {
        let took = started.elapsed();
        let first = LATENCY_BUCKETS
            .iter()
            .position(|bound| took < *bound)
            .unwrap_or(LATENCY_BUCKETS.len() - 1);
        for bucket in &self.latency[first..] {
            bucket.fetch_add(1, Ordering::Relaxed);
        }
        let counter = match &result {
            Ok(_) => &self.ok,
            Err(CryptoError::Kms(_) | CryptoError::Keyring(_)) => &self.failures,
            Err(_) => &self.errors,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        result
    }
}

#[async_trait::async_trait]
impl Kms for Measured {
    async fn seal(
        &self,
        key: Option<&str>,
        context: &Context,
        data_key: &DataKey,
    ) -> Result<SealedKey> {
        let started = Instant::now();
        let result = self.inner.seal(key, context, data_key).await;
        self.count(started, result)
    }

    async fn unseal(&self, sealed: &SealedKey, context: &Context) -> Result<DataKey> {
        let started = Instant::now();
        let result = self.inner.unseal(sealed, context).await;
        self.count(started, result)
    }

    async fn keys(&self) -> Result<Vec<KeyInfo>> {
        self.inner.keys().await
    }

    async fn create_key(&self, name: &str) -> Result<KeyInfo> {
        let started = Instant::now();
        let result = self.inner.create_key(name).await;
        self.count(started, result)
    }

    async fn rotate_key(&self, name: &str) -> Result<KeyInfo> {
        let started = Instant::now();
        let result = self.inner.rotate_key(name).await;
        self.count(started, result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalKms;

    #[tokio::test]
    async fn counts_calls_by_how_they_ended() {
        let dir = tempfile::tempdir().unwrap();
        let kms = Measured::new(Arc::new(LocalKms::open(dir.path().join("keys")).unwrap()));
        let context = Context::object("d", "b", "o");
        let (data_key, sealed) = kms.generate(None, &context).await.unwrap();
        assert_eq!(kms.unseal(&sealed, &context).await.unwrap(), data_key);
        let other = Context::object("d", "b", "other");
        assert!(kms.unseal(&sealed, &other).await.is_err());
        assert!(
            kms.seal(Some("missing"), &context, &data_key)
                .await
                .is_err()
        );
        kms.create_key("app").await.unwrap();
        kms.keys().await.unwrap();
        let metrics = kms.metrics();
        assert_eq!((metrics.ok, metrics.errors, metrics.failures), (3, 2, 0));
        // Each call is in its bucket and every later one: the last holds them all.
        assert_eq!(metrics.latency[LATENCY_BUCKETS.len() - 1], 5);
        assert!(metrics.latency.windows(2).all(|w| w[0] <= w[1]));
        // A key that exists is refused, not a failure.
        assert!(kms.create_key("app").await.is_err());
        assert_eq!((kms.metrics().errors, kms.metrics().failures), (3, 0));
    }
}
