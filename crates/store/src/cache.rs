//! Bucket settings read on many requests (lifecycle and notification rules): read from
//! a bucket's record once, and kept until any bucket's settings change.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use crate::error::Result;

/// One setting of every bucket, by bucket name (`None` for a bucket without it).
#[derive(Debug)]
pub(crate) struct SettingCache<T> {
    state: Mutex<State<T>>,
}

#[derive(Debug)]
struct State<T> {
    /// Bumped by every change, so a read that raced one isn't kept.
    generation: u64,
    buckets: HashMap<String, Option<Arc<T>>>,
}

impl<T> Default for SettingCache<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                generation: 0,
                buckets: HashMap::new(),
            }),
        }
    }
}

impl<T> SettingCache<T> {
    fn state(&self) -> MutexGuard<'_, State<T>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Forgets everything; called after a bucket's settings change, or a bucket goes.
    pub(crate) fn clear(&self) {
        let mut state = self.state();
        state.generation += 1;
        state.buckets.clear();
    }

    /// The bucket's setting if it's in memory.
    #[expect(
        clippy::option_option,
        reason = "not in memory, or in memory as a setting the bucket doesn't have"
    )]
    pub(crate) fn cached(&self, bucket: &str) -> Option<Option<Arc<T>>> {
        self.state().buckets.get(bucket).cloned()
    }

    /// The bucket's setting, from memory, or from `read` (and then kept).
    pub(crate) fn get(
        &self,
        bucket: &str,
        read: impl FnOnce() -> Result<Option<T>>,
    ) -> Result<Option<Arc<T>>> {
        let generation = {
            let state = self.state();
            if let Some(found) = state.buckets.get(bucket) {
                return Ok(found.clone());
            }
            state.generation
        };
        let found = read()?.map(Arc::new);
        let mut state = self.state();
        if state.generation == generation {
            state.buckets.insert(bucket.to_owned(), found.clone());
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_that_raced_a_change_is_not_kept() {
        let cache = SettingCache::<u32>::default();
        let found = cache
            .get("bkt", || {
                cache.clear();
                Ok(Some(1))
            })
            .unwrap();
        assert_eq!(found.as_deref(), Some(&1));
        assert!(cache.cached("bkt").is_none());
        cache.get("bkt", || Ok(Some(2))).unwrap();
        assert_eq!(cache.cached("bkt").flatten().as_deref(), Some(&2));
        cache.get("none", || Ok(None)).unwrap();
        assert_eq!(cache.cached("none"), Some(None));
    }
}
