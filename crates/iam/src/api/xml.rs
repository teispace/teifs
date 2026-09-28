//! Writing the Query protocol's XML answers.

use std::fmt::Write as _;

/// An XML document being written. Text is always escaped; a character XML can't hold
/// becomes U+FFFD, so an answer is well-formed whatever went into it.
#[derive(Debug, Default)]
pub(crate) struct Xml(String);

impl Xml {
    pub(crate) fn new() -> Self {
        Self(String::with_capacity(512))
    }

    /// `<tag>…</tag>`, with `f` writing what's inside.
    pub(crate) fn el(&mut self, tag: &str, f: impl FnOnce(&mut Self)) -> &mut Self {
        let _ = write!(self.0, "<{tag}>");
        f(self);
        let _ = write!(self.0, "</{tag}>");
        self
    }

    /// `<tag>text</tag>`.
    pub(crate) fn text(&mut self, tag: &str, text: &str) -> &mut Self {
        self.el(tag, |x| escape(&mut x.0, text))
    }

    /// Text, not in an element of its own (a `<member>` of a list of names).
    pub(crate) fn content(&mut self, text: &str) -> &mut Self {
        escape(&mut self.0, text);
        self
    }

    /// `<tag>text</tag>` if there's a text.
    pub(crate) fn maybe(&mut self, tag: &str, text: Option<&str>) -> &mut Self {
        if let Some(text) = text {
            self.text(tag, text);
        }
        self
    }

    /// `<tag>n</tag>`.
    pub(crate) fn number(&mut self, tag: &str, n: usize) -> &mut Self {
        let _ = write!(self.0, "<{tag}>{n}</{tag}>");
        self
    }

    /// `<tag>true</tag>` or `<tag>false</tag>`.
    pub(crate) fn boolean(&mut self, tag: &str, b: bool) -> &mut Self {
        let _ = write!(self.0, "<{tag}>{b}</{tag}>");
        self
    }

    /// `<tag>2026-09-29T12:00:00Z</tag>`, from milliseconds since the Unix epoch.
    pub(crate) fn date(&mut self, tag: &str, ms: i64) -> &mut Self {
        let _ = write!(self.0, "<{tag}>");
        iso8601(&mut self.0, ms);
        let _ = write!(self.0, "</{tag}>");
        self
    }

    /// `<tag><member>…</member>…</tag>`, with `f` writing each member.
    pub(crate) fn members<T>(
        &mut self,
        tag: &str,
        items: &[T],
        mut f: impl FnMut(&mut Self, &T),
    ) -> &mut Self {
        self.el(tag, |x| {
            for item in items {
                x.el("member", |x| f(x, item));
            }
        })
    }

    /// `<Tags>` as AWS lists them.
    pub(crate) fn tags(&mut self, tags: &[(String, String)]) -> &mut Self {
        self.members("Tags", tags, |x, (key, value)| {
            x.text("Key", key).text("Value", value);
        })
    }

    /// Another document's content, as is.
    pub(crate) fn raw(&mut self, other: &Self) -> &mut Self {
        self.0.push_str(&other.0);
        self
    }

    pub(crate) fn into_string(self) -> String {
        self.0
    }
}

fn escape(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // Kept as a reference, or a parser would turn it into a line feed.
            '\r' => out.push_str("&#xD;"),
            '\t' | '\n' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'.. => {
                out.push(c);
            }
            _ => out.push('\u{FFFD}'),
        }
    }
}

/// Seconds precision, UTC, as IAM writes dates.
fn iso8601(out: &mut String, ms: i64) {
    let date = time::OffsetDateTime::from_unix_timestamp(ms.div_euclid(1000))
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
    let _ = write!(
        out,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        date.year(),
        u8::from(date.month()),
        date.day(),
        date.hour(),
        date.minute(),
        date.second()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_escaped_and_always_well_formed() {
        let mut x = Xml::new();
        x.text("A", "<a & 'b'>\"c\"\r\n\t\u{0}\u{1}\u{FFFE}é日");
        assert_eq!(
            x.into_string(),
            "<A>&lt;a &amp; &apos;b&apos;&gt;&quot;c&quot;&#xD;\n\t\u{FFFD}\u{FFFD}\u{FFFD}é日</A>"
        );
    }

    #[test]
    fn members_numbers_and_dates() {
        let mut x = Xml::new();
        x.members("Names", &["a", "b"], |x, n| {
            x.text("Name", n);
        })
        .number("Count", 2)
        .boolean("IsTruncated", false)
        .date("CreateDate", 1_790_000_000_999)
        .maybe("Marker", None)
        .tags(&[("k".into(), String::new())]);
        assert_eq!(
            x.into_string(),
            "<Names><member><Name>a</Name></member><member><Name>b</Name></member></Names>\
             <Count>2</Count><IsTruncated>false</IsTruncated>\
             <CreateDate>2026-09-21T14:13:20Z</CreateDate>\
             <Tags><member><Key>k</Key><Value></Value></member></Tags>"
        );
    }
}
