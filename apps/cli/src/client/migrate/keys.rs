//! A bucket's keys one at a time, in S3's order, each with its versions and delete
//! markers (oldest first) or its current object. Read a page at a time, so a bucket of
//! any size is walked in little memory.

use std::collections::VecDeque;

use aws_sdk_s3::{Client, error::ProvideErrorMetadata, primitives::DateTime};

use super::super::Error;

/// A version, a delete marker, or (listing current objects) the object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// `None` for a current object listed without versions.
    pub version_id: Option<String>,
    pub marker: bool,
    pub latest: bool,
    pub size: u64,
    pub etag: Option<String>,
    pub modified: Option<DateTime>,
}

/// A key below the listed prefix, with what's under it, oldest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub relative: String,
    pub items: Vec<Item>,
}

/// Where a listing goes on from.
enum Next {
    Start,
    Token(String),
    Markers(String, Option<String>),
    Done,
}

pub struct Keys {
    client: Client,
    bucket: String,
    prefix: String,
    versions: bool,
    /// For messages.
    name: String,
    /// A bucket that isn't there lists nothing (a destination not made yet).
    missing_is_empty: bool,
    /// The most keys (or versions) a page holds; `None`: the endpoint's (1,000).
    page: Option<i32>,
    next: Next,
    buffer: VecDeque<(String, Item)>,
}

impl Keys {
    pub fn new(
        client: Client,
        bucket: &str,
        prefix: &str,
        versions: bool,
        name: String,
        missing_is_empty: bool,
        page: Option<i32>,
    ) -> Self {
        Self {
            client,
            bucket: bucket.to_owned(),
            prefix: prefix.to_owned(),
            versions,
            name,
            missing_is_empty,
            page,
            next: Next::Start,
            buffer: VecDeque::new(),
        }
    }

    /// The next key, or `None` after the last.
    pub async fn next(&mut self) -> Result<Option<Group>, Error> {
        loop {
            let done = matches!(self.next, Next::Done);
            if let Some((key, _)) = self.buffer.front() {
                // A key's last versions may be on the next page: it's whole once a later
                // key follows it, or the listing ends.
                let whole = done || self.buffer.back().is_some_and(|(last, _)| last != key);
                if whole {
                    let key = key.clone();
                    let mut items = Vec::new();
                    while let Some((_, item)) = self.buffer.pop_front_if(|(k, _)| *k == key) {
                        items.push(item);
                    }
                    oldest_first(&mut items);
                    let relative = key.strip_prefix(&self.prefix).unwrap_or(&key).to_owned();
                    return Ok(Some(Group { relative, items }));
                }
            } else if done {
                return Ok(None);
            }
            self.fetch().await?;
        }
    }

    /// Reads the next page into the buffer.
    async fn fetch(&mut self) -> Result<(), Error> {
        let next = std::mem::replace(&mut self.next, Next::Done);
        let page = if self.versions {
            self.versions_page(next).await?
        } else {
            self.current_page(next).await?
        };
        let Some(mut page) = page else {
            return Ok(());
        };
        // Versions and delete markers come as two lists: one, by key (stable, so each
        // keeps the endpoint's order within a key).
        page.sort_by(|a, b| a.0.cmp(&b.0));
        self.buffer.extend(page);
        Ok(())
    }

    /// Whether a failed listing is of a bucket that isn't there and lists nothing.
    fn empty_when<E: ProvideErrorMetadata>(&self, err: &E) -> bool {
        self.missing_is_empty && err.code() == Some("NoSuchBucket")
    }

    /// A page of versions and delete markers; `None` when the bucket isn't there.
    async fn versions_page(&mut self, next: Next) -> Result<Option<Vec<(String, Item)>>, Error> {
        let (key_marker, version_marker) = match next {
            Next::Markers(key, version) => (Some(key), version),
            _ => (None, None),
        };
        let got = self
            .client
            .list_object_versions()
            .bucket(&self.bucket)
            .prefix(&self.prefix)
            .set_key_marker(key_marker)
            .set_version_id_marker(version_marker)
            .set_max_keys(self.page)
            .send()
            .await;
        let got = match got {
            Ok(got) => got,
            Err(e) if self.empty_when(&e) => return Ok(None),
            Err(e) => {
                let what = format!("can't list the versions in {}", self.name);
                return Err(Error::s3(what, &e));
            }
        };
        let versions = got.versions().iter().map(|v| {
            let item = Item {
                version_id: Some(v.version_id().unwrap_or("null").to_owned()),
                marker: false,
                latest: v.is_latest().unwrap_or(false),
                size: v.size().and_then(|s| u64::try_from(s).ok()).unwrap_or(0),
                etag: v.e_tag().map(str::to_owned),
                modified: v.last_modified().copied(),
            };
            (v.key().unwrap_or_default().to_owned(), item)
        });
        let markers = got.delete_markers().iter().map(|m| {
            let item = Item {
                version_id: Some(m.version_id().unwrap_or("null").to_owned()),
                marker: true,
                latest: m.is_latest().unwrap_or(false),
                size: 0,
                etag: None,
                modified: m.last_modified().copied(),
            };
            (m.key().unwrap_or_default().to_owned(), item)
        });
        let page = versions.chain(markers).collect();
        if got.is_truncated().unwrap_or(false) {
            let key = got.next_key_marker().map(str::to_owned).ok_or_else(|| {
                Error::general(format!(
                    "can't list the versions in {}: the endpoint gave no marker to go on from",
                    self.name
                ))
            })?;
            self.next = Next::Markers(key, got.next_version_id_marker().map(str::to_owned));
        }
        Ok(Some(page))
    }

    /// A page of current objects; `None` when the bucket isn't there.
    async fn current_page(&mut self, next: Next) -> Result<Option<Vec<(String, Item)>>, Error> {
        let token = match next {
            Next::Token(token) => Some(token),
            _ => None,
        };
        let got = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&self.prefix)
            .set_continuation_token(token)
            .set_max_keys(self.page)
            .send()
            .await;
        let got = match got {
            Ok(got) => got,
            Err(e) if self.empty_when(&e) => return Ok(None),
            Err(e) => return Err(Error::s3(format!("can't list {}", self.name), &e)),
        };
        let page = got
            .contents()
            .iter()
            .map(|o| {
                let item = Item {
                    version_id: None,
                    marker: false,
                    latest: true,
                    size: o.size().and_then(|s| u64::try_from(s).ok()).unwrap_or(0),
                    etag: o.e_tag().map(str::to_owned),
                    modified: o.last_modified().copied(),
                };
                (o.key().unwrap_or_default().to_owned(), item)
            })
            .collect();
        if got.is_truncated().unwrap_or(false) {
            let token = got
                .next_continuation_token()
                .map(str::to_owned)
                .ok_or_else(|| {
                    Error::general(format!(
                        "can't list {}: the endpoint gave no token to go on from",
                        self.name
                    ))
                })?;
            self.next = Next::Token(token);
        }
        Ok(Some(page))
    }
}

/// A key's versions and delete markers, oldest first: S3 lists each newest first; the
/// two lists are put together by time, and the current one is last whatever its time
/// (times are to the second).
fn oldest_first(items: &mut [Item]) {
    items.reverse();
    items.sort_by(|a, b| {
        a.latest.cmp(&b.latest).then_with(|| {
            a.modified
                .map(|t| t.as_nanos())
                .cmp(&b.modified.map(|t| t.as_nanos()))
        })
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, marker: bool, latest: bool, secs: i64) -> Item {
        Item {
            version_id: Some(id.to_owned()),
            marker,
            latest,
            size: 0,
            etag: None,
            modified: Some(DateTime::from_secs(secs)),
        }
    }

    #[test]
    fn versions_are_put_oldest_first() {
        // As listed: versions newest first, then markers newest first.
        let mut items = vec![
            item("v3", false, false, 30),
            item("v2b", false, false, 20),
            item("v2a", false, false, 20),
            item("m4", true, true, 30),
            item("m1", true, false, 10),
        ];
        oldest_first(&mut items);
        let ids: Vec<&str> = items
            .iter()
            .map(|i| i.version_id.as_deref().unwrap())
            .collect();
        // Same-second versions keep the endpoint's order (oldest of them first once
        // reversed); the current one is last though v3 has its time.
        assert_eq!(ids, ["m1", "v2a", "v2b", "v3", "m4"]);
    }
}
