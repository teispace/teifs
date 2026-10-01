//! Distinguished names (RFC 4514): parsed, compared and written in one form, so a DN
//! given in any spelling finds the mappings stored for it.
//!
//! The written form is MinIO's: attribute types in lower case, values escaped as RFC
//! 4514 asks, the RDNs joined with `,` and no spaces. Comparisons ignore case in types
//! and values, as the directory's usual matching rules for names do.

use std::fmt;

/// A parsed distinguished name: its RDNs from the entry up to the root, each one or more
/// attribute type and value pairs.
#[derive(Debug, Clone)]
pub(crate) struct Dn {
    rdns: Vec<Vec<Ava>>,
}

/// One attribute type and value. A value given in hex (`#04…`) is kept as written.
#[derive(Debug, Clone)]
struct Ava {
    kind: String,
    value: String,
    hex: bool,
}

impl Dn {
    /// Parses `text`; the empty string is the root's empty DN.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let bad = |why: &str| format!("`{text}` isn't a distinguished name: {why}");
        let mut rdns = Vec::new();
        let mut rdn = Vec::new();
        let mut chars = text.chars().peekable();
        if text.trim().is_empty() {
            return Ok(Self { rdns });
        }
        loop {
            // The attribute type, up to `=`.
            let mut kind = String::new();
            loop {
                match chars.next() {
                    Some('=') => break,
                    Some(c) => kind.push(c),
                    None => return Err(bad("an attribute has no `=`")),
                }
            }
            let kind = kind.trim().to_ascii_lowercase();
            if !is_attribute_type(&kind) {
                return Err(bad(&format!("`{kind}` isn't an attribute type")));
            }
            while chars.next_if(|c| *c == ' ').is_some() {}
            // The value, up to an unescaped `,`, `;` or `+`.
            let (value, hex, end) = if chars.next_if_eq(&'#').is_some() {
                let mut hex = String::from("#");
                let mut end = None;
                for c in chars.by_ref() {
                    if matches!(c, ',' | ';' | '+') {
                        end = Some(c);
                        break;
                    }
                    hex.push(c);
                }
                let hex = hex.trim_end().to_ascii_lowercase();
                if hex.len() < 3
                    || hex.len() % 2 == 0
                    || !hex[1..].bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(bad("a `#` value isn't hex"));
                }
                (hex, true, end)
            } else if chars.next_if_eq(&'"').is_some() {
                // RFC 2253's quoted value.
                let mut value = Vec::new();
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => unescape(&mut chars, &mut value).map_err(bad)?,
                        Some(c) => push(&mut value, c),
                        None => return Err(bad("a quoted value isn't closed")),
                    }
                }
                while chars.next_if(|c| *c == ' ').is_some() {}
                let end = match chars.next() {
                    None => None,
                    Some(c @ (',' | ';' | '+')) => Some(c),
                    Some(_) => return Err(bad("text follows a quoted value")),
                };
                let value = String::from_utf8(value).map_err(|_| bad("a value isn't UTF-8"))?;
                (value, false, end)
            } else {
                let mut value = Vec::new();
                // The length up to the last escaped character: trailing spaces past it
                // aren't part of the value.
                let mut kept = 0;
                let mut end = None;
                while let Some(c) = chars.next() {
                    match c {
                        ',' | ';' | '+' => {
                            end = Some(c);
                            break;
                        }
                        '\\' => {
                            unescape(&mut chars, &mut value).map_err(bad)?;
                            kept = value.len();
                        }
                        '"' | '<' | '>' => {
                            return Err(bad(&format!("`{c}` must be escaped")));
                        }
                        c => push(&mut value, c),
                    }
                }
                while value.len() > kept && value.last() == Some(&b' ') {
                    value.pop();
                }
                let value = String::from_utf8(value).map_err(|_| bad("a value isn't UTF-8"))?;
                (value, false, end)
            };
            rdn.push(Ava { kind, value, hex });
            match end {
                Some('+') => {}
                Some(_) => {
                    rdns.push(std::mem::take(&mut rdn));
                    while chars.next_if(|c| *c == ' ').is_some() {}
                    if chars.peek().is_none() {
                        return Err(bad("it ends with a separator"));
                    }
                }
                None => {
                    rdns.push(rdn);
                    return Ok(Self { rdns });
                }
            }
        }
    }

    /// Whether `other` sits below this DN in the tree (not this DN itself).
    pub(crate) fn is_ancestor_of(&self, other: &Self) -> bool {
        other.rdns.len() > self.rdns.len()
            && self
                .rdns
                .iter()
                .rev()
                .zip(other.rdns.iter().rev())
                .all(|(a, b)| same_rdn(a, b))
    }

    /// Whether both name the same entry.
    pub(crate) fn same(&self, other: &Self) -> bool {
        self.rdns.len() == other.rdns.len()
            && self
                .rdns
                .iter()
                .zip(&other.rdns)
                .all(|(a, b)| same_rdn(a, b))
    }
}

impl fmt::Display for Dn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, rdn) in self.rdns.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            for (j, ava) in rdn.iter().enumerate() {
                if j > 0 {
                    f.write_str("+")?;
                }
                write!(f, "{}=", ava.kind)?;
                if ava.hex {
                    f.write_str(&ava.value)?;
                } else {
                    escape(f, &ava.value)?;
                }
            }
        }
        Ok(())
    }
}

/// Normalizes a DN: parsed and written in the one form, which is how TeiFS keeps DNs.
///
/// # Errors
///
/// Why `text` isn't a DN.
pub fn normalize(text: &str) -> Result<String, String> {
    Dn::parse(text).map(|dn| dn.to_string())
}

fn same_rdn(a: &[Ava], b: &[Ava]) -> bool {
    a.len() == b.len()
        && a.iter().all(|x| {
            b.iter().any(|y| {
                x.kind == y.kind
                    && x.hex == y.hex
                    && x.value.to_lowercase() == y.value.to_lowercase()
            })
        })
}

/// A descriptor (`cn`, `ou-x`) or a numeric OID (`2.5.4.3`).
fn is_attribute_type(kind: &str) -> bool {
    let descr = kind.starts_with(|c: char| c.is_ascii_alphabetic())
        && kind.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    let oid = !kind.is_empty()
        && kind
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    descr || oid
}

fn push(value: &mut Vec<u8>, c: char) {
    let mut buf = [0; 4];
    value.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
}

/// After a `\`: an escaped special character, or a byte in two hex digits.
fn unescape(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    value: &mut Vec<u8>,
) -> Result<(), &'static str> {
    match chars.next() {
        Some(c) if c.is_ascii_hexdigit() => {
            let low = chars
                .next()
                .and_then(|l| l.to_digit(16))
                .ok_or("a `\\` escape isn't two hex digits")?;
            let high = c.to_digit(16).ok_or("a `\\` escape isn't two hex digits")?;
            value.push(u8::try_from(high * 16 + low).map_err(|_| "a bad escape")?);
            Ok(())
        }
        Some(c) if " \"#+,;<=>\\".contains(c) => {
            push(value, c);
            Ok(())
        }
        _ => Err("a `\\` escapes nothing that needs it"),
    }
}

/// Writes a value as RFC 4514 asks: `"+,;<>\` and NUL escaped, and a leading `#` or
/// space and a trailing space.
fn escape(f: &mut fmt::Formatter<'_>, value: &str) -> fmt::Result {
    let last = value.chars().count().saturating_sub(1);
    for (i, c) in value.chars().enumerate() {
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => write!(f, "\\{c}")?,
            '\0' => f.write_str("\\00")?,
            '#' if i == 0 => f.write_str("\\#")?,
            ' ' if i == 0 || i == last => f.write_str("\\ ")?,
            c => write!(f, "{c}")?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_are_written_in_one_form() {
        for (given, normal) in [
            (
                "UID=dillon, OU=people,ou=swengg ,DC=min,dc=io",
                "uid=dillon,ou=people,ou=swengg,dc=min,dc=io",
            ),
            ("cn=Smith\\, John,dc=x", "cn=Smith\\, John,dc=x"),
            ("cn=a\\2cb;dc=x", "cn=a\\,b,dc=x"),
            ("cn=\"a, b\",dc=x", "cn=a\\, b,dc=x"),
            ("cn=a+sn=b,dc=x", "cn=a+sn=b,dc=x"),
            ("cn=\\#x\\ ,dc=x", "cn=\\#x\\ ,dc=x"),
            ("cn=a\\00b", "cn=a\\00b"),
            ("cn=Пользователь,dc=x", "cn=Пользователь,dc=x"),
            ("cn=\\D0\\9F,dc=x", "cn=П,dc=x"),
            ("2.5.4.3=#04024869", "2.5.4.3=#04024869"),
            ("uid=slash/user,dc=x", "uid=slash/user,dc=x"),
            ("cn=a   ,dc=x", "cn=a,dc=x"),
            ("", ""),
        ] {
            assert_eq!(normalize(given).as_deref(), Ok(normal), "{given}");
            // Written forms parse back to themselves.
            assert_eq!(normalize(normal).as_deref(), Ok(normal), "{normal}");
        }
    }

    #[test]
    fn what_isnt_a_dn_is_refused() {
        for bad in [
            "dillon",
            "cn=a,",
            "cn=a,,dc=x",
            "=a",
            "c n=a",
            "1a=x",
            "cn=a<b",
            "cn=\\zz",
            "cn=\\4",
            "cn=#4",
            "cn=#zz",
            "cn=\"open",
            "cn=\"a\"b",
            "cn=\\ff",
            "cn=a\"b",
            "cn=a>b",
        ] {
            assert!(normalize(bad).is_err(), "{bad}");
        }
        // Each says why.
        assert!(
            normalize("cn=a, ")
                .unwrap_err()
                .contains("ends with a separator")
        );
        assert!(
            normalize("cn=a\"b")
                .unwrap_err()
                .contains("must be escaped")
        );
    }

    #[test]
    fn ancestors_and_equality_ignore_case() {
        let dn = |s| Dn::parse(s).unwrap();
        let base = dn("ou=People,DC=min,dc=io");
        assert!(base.is_ancestor_of(&dn("uid=dillon,ou=people,dc=MIN,dc=io")));
        assert!(base.is_ancestor_of(&dn("uid=x,ou=sub,ou=people,dc=min,dc=io")));
        assert!(!base.is_ancestor_of(&dn("ou=people,dc=min,dc=io")));
        assert!(!base.is_ancestor_of(&dn("uid=x,ou=groups,dc=min,dc=io")));
        assert!(!base.is_ancestor_of(&dn("dc=io")));
        assert!(dn("").is_ancestor_of(&dn("dc=io")));
        assert!(dn("").rdns.is_empty());
        assert!(base.same(&dn("OU=people , dc=min,dc=IO")));
        assert!(!base.same(&dn("ou=people,dc=min")));
        assert!(dn("cn=a+sn=b").same(&dn("sn=B+cn=A")));
        assert!(!dn("cn=a+sn=b").same(&dn("cn=a+sn=c")));
        assert!(!dn("cn=a+sn=b").same(&dn("cn=a")));
    }
}
