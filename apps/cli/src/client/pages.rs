//! Listings S3 answers a page at a time, read whole.

use super::Error;

/// A page of a listing: its items, and the token of the next page when there is one.
pub(super) struct Page<T> {
    pub(super) items: Vec<T>,
    pub(super) truncated: bool,
    pub(super) next: Option<String>,
}

/// Every item of a listing: `page` reads the page a continuation token (`None`: the
/// first) names.
pub(super) async fn every<T, F, Fut>(mut page: F) -> Result<Vec<T>, Error>
where
    F: FnMut(Option<String>) -> Fut,
    Fut: Future<Output = Result<Page<T>, Error>>,
{
    let mut items = Vec::new();
    let mut token = None;
    loop {
        let read = page(token).await?;
        items.extend(read.items);
        token = read.next;
        if !read.truncated || token.is_none() {
            return Ok(items);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use super::*;

    #[tokio::test]
    async fn every_page_is_read_until_one_isnt_truncated() {
        let mut asked = Vec::new();
        let items = every(|token: Option<String>| {
            asked.push(token.clone());
            let n: usize = token.map_or(0, |t| t.parse().unwrap());
            async move {
                Ok(Page {
                    items: vec![n],
                    truncated: n < 2,
                    next: Some((n + 1).to_string()),
                })
            }
        })
        .await
        .unwrap();
        assert_eq!(items, [0, 1, 2]);
        assert_eq!(asked, [None, Some("1".to_owned()), Some("2".to_owned())]);
        // A truncated page without a token ends the listing rather than starting over.
        let once = every(|_| async {
            Ok(Page {
                items: vec![7],
                truncated: true,
                next: None,
            })
        })
        .await
        .unwrap();
        assert_eq!(once, [7]);
    }
}
