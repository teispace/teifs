//! The Query protocol's parameters: a form of `Name=value` pairs, lists as
//! `Name.member.1`, `Name.member.2`…, and tags as `Tags.member.N.Key` and `.Value`.

use std::{collections::BTreeMap, ops::Bound};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use super::ApiError;

/// A request's parameters. A name given twice is refused rather than one of its values
/// silently chosen.
#[derive(Debug)]
pub(crate) struct Params(BTreeMap<String, String>);

/// Which page of a list to answer with.
#[derive(Debug, Default)]
pub(crate) struct Page {
    /// Items sort after this key (from the previous page's `Marker`).
    after: Option<String>,
    max: usize,
}

/// The most items one page may hold, and how many unless asked.
const MAX_ITEMS: usize = 1000;
const DEFAULT_ITEMS: usize = 100;

impl Params {
    pub(crate) fn parse(body: &[u8]) -> Result<Self, ApiError> {
        let mut map = BTreeMap::new();
        for (name, value) in form_urlencoded::parse(body) {
            let name = name.into_owned();
            if map.contains_key(&name) {
                return Err(ApiError::validation(format!(
                    "The parameter {name} is given more than once."
                )));
            }
            map.insert(name, value.into_owned());
        }
        Ok(Self(map))
    }

    pub(crate) fn optional(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    pub(crate) fn required(&self, name: &str) -> Result<&str, ApiError> {
        self.optional(name).ok_or_else(|| ApiError::missing(name))
    }

    /// `true` or `false`; `default` when absent.
    pub(crate) fn boolean(&self, name: &str, default: bool) -> Result<bool, ApiError> {
        match self.optional(name) {
            None => Ok(default),
            Some("true") => Ok(true),
            Some("false") => Ok(false),
            Some(other) => Err(ApiError::invalid_value(name, other)),
        }
    }

    /// One of `choices`, if given.
    pub(crate) fn choice(
        &self,
        name: &str,
        choices: &[&'static str],
    ) -> Result<Option<&'static str>, ApiError> {
        self.optional(name)
            .map(|value| {
                choices
                    .iter()
                    .copied()
                    .find(|c| *c == value)
                    .ok_or_else(|| ApiError::invalid_value(name, value))
            })
            .transpose()
    }

    /// The list `Name.member.N`, in order.
    pub(crate) fn list(&self, name: &str) -> Result<Vec<&str>, ApiError> {
        self.indexed(&format!("{name}.member."))?
            .into_iter()
            .map(|(n, mut fields)| {
                fields
                    .remove("")
                    .filter(|_| fields.is_empty())
                    .ok_or_else(|| ApiError::missing(&format!("{name}.member.{n}")))
            })
            .collect()
    }

    /// The tags `Tags.member.N.Key` and `.Value`.
    pub(crate) fn tags(&self) -> Result<Vec<(String, String)>, ApiError> {
        self.indexed("Tags.member.")?
            .into_iter()
            .map(|(n, mut fields)| {
                let mut take = |field: &str| {
                    fields
                        .remove(field)
                        .map(str::to_owned)
                        .ok_or_else(|| ApiError::missing(&format!("Tags.member.{n}.{field}")))
                };
                let tag = (take("Key")?, take("Value")?);
                match fields.into_keys().next() {
                    Some(other) => Err(ApiError::validation(format!(
                        "Tags.member.{n}.{other} isn't a tag's field."
                    ))),
                    None => Ok(tag),
                }
            })
            .collect()
    }

    /// `Marker` and `MaxItems`.
    pub(crate) fn page(&self) -> Result<Page, ApiError> {
        let max = match self.optional("MaxItems") {
            None => DEFAULT_ITEMS,
            Some(text) => text
                .parse()
                .ok()
                .filter(|n| (1..=MAX_ITEMS).contains(n))
                .ok_or_else(|| {
                    ApiError::validation(format!(
                        "1 validation error detected: Value '{text}' at 'maxItems' failed to \
                         satisfy constraint: Member must have value between 1 and {MAX_ITEMS}"
                    ))
                })?,
        };
        let after = self
            .optional("Marker")
            .map(|marker| {
                URL_SAFE_NO_PAD
                    .decode(marker)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .ok_or_else(|| ApiError::invalid_value("Marker", marker))
            })
            .transpose()?;
        Ok(Page { after, max })
    }

    /// The parameters under `prefix`, by their index (numbered from 1, without gaps) and
    /// the field after it (`""` for a plain list member).
    fn indexed(&self, prefix: &str) -> Result<BTreeMap<usize, BTreeMap<&str, &str>>, ApiError> {
        let mut out: BTreeMap<usize, BTreeMap<&str, &str>> = BTreeMap::new();
        let under = self
            .0
            .range::<str, _>((Bound::Included(prefix), Bound::Unbounded))
            .take_while(|(name, _)| name.starts_with(prefix));
        for (name, value) in under {
            let rest = &name[prefix.len()..];
            let (index, field) = rest.split_once('.').unwrap_or((rest, ""));
            let index = index
                .parse::<usize>()
                .ok()
                .filter(|n| *n >= 1 && n.to_string() == index)
                .ok_or_else(|| ApiError::validation(format!("{name} isn't a valid parameter.")))?;
            out.entry(index).or_default().insert(field, value);
        }
        if out.keys().enumerate().any(|(i, n)| *n != i + 1) {
            return Err(ApiError::validation(format!(
                "The members of {prefix} must be numbered 1, 2, 3…"
            )));
        }
        Ok(out)
    }
}

/// One page of `items`, in the order of `key`, and the marker of the next page if there
/// is one.
pub(crate) fn paged<T>(
    mut items: Vec<T>,
    page: &Page,
    key: impl Fn(&T) -> String,
) -> (Vec<T>, Option<String>) {
    let mut keyed: Vec<(String, T)> = items.drain(..).map(|item| (key(&item), item)).collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    let start = page
        .after
        .as_ref()
        .map_or(0, |after| keyed.partition_point(|(k, _)| k <= after));
    let mut rest = keyed.into_iter().skip(start);
    let items: Vec<(String, T)> = rest.by_ref().take(page.max).collect();
    let next = if rest.next().is_some() {
        items.last().map(|(k, _)| URL_SAFE_NO_PAD.encode(k))
    } else {
        None
    };
    (items.into_iter().map(|(_, item)| item).collect(), next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(body: &str) -> Params {
        Params::parse(body.as_bytes()).unwrap()
    }

    fn code<T: std::fmt::Debug>(r: Result<T, ApiError>) -> &'static str {
        r.unwrap_err().code
    }

    #[test]
    fn forms_decode_as_browsers_encode_them() {
        let p = params("Action=CreateUser&UserName=a%2Bb&Path=%2Fx+y%2F&Empty=");
        assert_eq!(p.required("Action").unwrap(), "CreateUser");
        assert_eq!(p.optional("UserName"), Some("a+b"));
        assert_eq!(p.optional("Path"), Some("/x y/"));
        assert_eq!(p.optional("Empty"), Some(""));
        assert_eq!(p.optional("None"), None);
        assert_eq!(code(p.required("UserId")), "ValidationError");
        assert_eq!(
            code(Params::parse(b"UserName=a&UserName=b")),
            "ValidationError"
        );
    }

    #[test]
    fn lists_and_tags_are_numbered_from_one() {
        let p = params(
            "TagKeys.member.2=b&TagKeys.member.1=a&Tags.member.1.Key=k&Tags.member.1.Value=v\
             &Tags.member.2.Key=e&Tags.member.2.Value=",
        );
        assert_eq!(p.list("TagKeys").unwrap(), ["a", "b"]);
        assert!(p.list("Other").unwrap().is_empty());
        assert_eq!(
            p.tags().unwrap(),
            [("k".into(), "v".into()), ("e".into(), String::new())]
        );
        for bad in [
            "TagKeys.member.2=a",
            "TagKeys.member.0=a",
            "TagKeys.member.01=a",
            "TagKeys.member.+1=a",
            "TagKeys.member.x=a",
            "TagKeys.member.1.Key=a",
        ] {
            assert_eq!(
                code(params(bad).list("TagKeys")),
                "ValidationError",
                "{bad}"
            );
        }
        for bad in [
            "Tags.member.1.Key=k",
            "Tags.member.1.Value=v",
            "Tags.member.1.Key=k&Tags.member.1.Value=v&Tags.member.1.Other=x",
        ] {
            assert_eq!(code(params(bad).tags()), "ValidationError", "{bad}");
        }
    }

    #[test]
    fn booleans_and_choices_are_exact() {
        let p = params("A=true&B=false&C=True&S=Local");
        assert!(p.boolean("A", false).unwrap());
        assert!(!p.boolean("B", true).unwrap());
        assert!(p.boolean("Z", true).unwrap());
        assert_eq!(code(p.boolean("C", false)), "ValidationError");
        assert_eq!(p.choice("S", &["All", "Local"]).unwrap(), Some("Local"));
        assert_eq!(p.choice("T", &["All"]).unwrap(), None);
        assert_eq!(code(p.choice("S", &["All"])), "ValidationError");
    }

    #[test]
    fn pages_follow_their_markers() {
        let items: Vec<String> = ["c", "a", "e", "b", "d"].map(String::from).into();
        let key = |s: &String| s.clone();
        let (first, marker) = paged(items.clone(), &params("MaxItems=2").page().unwrap(), key);
        assert_eq!(first, ["a", "b"]);
        let marker = marker.unwrap();
        let (second, marker) = paged(
            items.clone(),
            &params(&format!("MaxItems=2&Marker={marker}"))
                .page()
                .unwrap(),
            key,
        );
        assert_eq!(second, ["c", "d"]);
        let (last, marker) = paged(
            items.clone(),
            &params(&format!("MaxItems=2&Marker={}", marker.unwrap()))
                .page()
                .unwrap(),
            key,
        );
        assert_eq!((last, marker), (vec!["e".to_owned()], None));
        let (all, marker) = paged(items, &params("").page().unwrap(), key);
        assert_eq!((all.len(), marker), (5, None));

        for bad in ["MaxItems=0", "MaxItems=1001", "MaxItems=x", "Marker=%25%25"] {
            assert_eq!(code(params(bad).page()), "ValidationError", "{bad}");
        }
    }
}
