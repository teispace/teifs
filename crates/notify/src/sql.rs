//! What the database targets (PostgreSQL, MySQL) do with an event, in `MinIO`'s formats,
//! and the table names they take.

use teifs_types::notify::EventMessage;

use crate::Format;

/// The change an event makes to a target's table.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Change {
    /// `namespace`: the object's row (`bucket/key`) set to `{"Records":[record]}`.
    Set { key: String, value: String },
    /// `namespace`: the object's row removed.
    Delete { key: String },
    /// `access`: a row of the event's time and the event as a webhook is sent it.
    Add { time: String, event: String },
}

impl Change {
    /// The change the event `body` makes in `format`.
    pub(crate) fn of(format: Format, body: &[u8]) -> Result<Self, String> {
        let message: EventMessage =
            serde_json::from_slice(body).map_err(|e| format!("not an event: {e}"))?;
        Ok(match format {
            Format::Namespace if Format::removes(&message.event_name) => {
                Self::Delete { key: message.key }
            }
            Format::Namespace => Self::Set {
                value: serde_json::json!({ "Records": message.records }).to_string(),
                key: message.key,
            },
            Format::Access => Self::Add {
                time: message
                    .records
                    .first()
                    .map(|r| r.event_time.clone())
                    .unwrap_or_default(),
                event: String::from_utf8(body.to_vec()).map_err(|_| "not an event")?,
            },
        })
    }
}

/// Whether `table` is a name the target takes: unquoted (a letter or `_`, then letters,
/// digits, `_` and `$`), or anything but `quote` between two of them, at most `max`
/// bytes. It's spliced into SQL, so nothing else is.
pub(crate) fn is_table(table: &str, quote: char, max: usize) -> bool {
    if let Some(quoted) = table
        .strip_prefix(quote)
        .and_then(|t| t.strip_suffix(quote))
    {
        return !quoted.is_empty() && !quoted.contains([quote, '\0']) && quoted.len() <= max;
    }
    let mut chars = table.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        && table.len() <= max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_are_names_or_quoted() {
        for good in ["events", "_e$1", "\"Events Table\"", "E"] {
            assert!(is_table(good, '"', 63), "{good}");
        }
        assert!(is_table("`S3 Events`", '`', 64));
        assert!(!is_table("`S3 Events`", '"', 64));
        assert!(is_table(&"e".repeat(64), '`', 64));
        assert!(!is_table(&"e".repeat(64), '"', 63));
        for bad in [
            "",
            "1events",
            "events;drop table x",
            "a.b",
            "\"\"",
            "\"a\"b\"",
            "\"a",
            "ev-ents",
            "ü",
        ] {
            assert!(!is_table(bad, '"', 63), "{bad}");
        }
    }

    #[test]
    fn events_become_changes_by_format() {
        let body = crate::tests::message("s3:ObjectRemoved:Delete", "b/k");
        assert_eq!(
            Change::of(Format::Namespace, &body),
            Ok(Change::Delete { key: "b/k".into() })
        );
        let Ok(Change::Add { time, event }) = Change::of(Format::Access, &body) else {
            panic!("not a row")
        };
        assert_eq!(time, "2026-09-30T12:00:00.000Z");
        assert_eq!(event.as_bytes(), body);
        let body = crate::tests::message("s3:ObjectCreated:Put", "b/k");
        let Ok(Change::Set { key, value }) = Change::of(Format::Namespace, &body) else {
            panic!("not set")
        };
        assert_eq!(key, "b/k");
        assert!(value.starts_with("{\"Records\":[{"), "{value}");
        assert!(Change::of(Format::Access, b"{}").is_err());
    }
}
