//! Wildcards as IAM has them: `*` is any run of characters (including none), `?` is any
//! one character. No escapes: a literal `*` or `?` comes from a policy variable
//! (`${*}`, `${?}`), so patterns are atoms rather than text.
//!
//! Matching keeps only the last `*` to fall back to, so it takes at most
//! O(pattern × text) steps whatever the input: no recursion, no exponential cases.

/// One element of a pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Atom {
    /// This character.
    Char(char),
    /// `*`: any run of characters.
    Star,
    /// `?`: any one character.
    One,
}

/// `text` read as a pattern: `*` and `?` are wildcards.
pub(crate) fn atoms(text: &str) -> impl Iterator<Item = Atom> + '_ {
    text.chars().map(|c| match c {
        '*' => Atom::Star,
        '?' => Atom::One,
        c => Atom::Char(c),
    })
}

/// `text` read literally.
pub(crate) fn literal(text: &str) -> impl Iterator<Item = Atom> + '_ {
    text.chars().map(Atom::Char)
}

/// Whether `pattern` matches all of `text`; `fold` compares ASCII letters without case.
pub(crate) fn matches(pattern: &[Atom], text: &str, fold: bool) -> bool {
    let same = |a: char, b: char| a == b || (fold && a.eq_ignore_ascii_case(&b));
    let (mut p, mut t) = (0, 0);
    // After the last `*` seen: where the pattern resumes, and where in the text that
    // `*` stopped (it grows by one character on each fallback).
    let mut fallback: Option<(usize, usize)> = None;
    while let Some(c) = text[t..].chars().next() {
        match pattern.get(p) {
            Some(Atom::Star) => {
                p += 1;
                fallback = Some((p, t));
                continue;
            }
            Some(Atom::One) => {
                p += 1;
                t += c.len_utf8();
                continue;
            }
            Some(Atom::Char(want)) if same(*want, c) => {
                p += 1;
                t += c.len_utf8();
                continue;
            }
            _ => {}
        }
        let Some((resume, stopped)) = fallback else {
            return false;
        };
        let grown = stopped + text[stopped..].chars().next().map_or(0, char::len_utf8);
        fallback = Some((resume, grown));
        p = resume;
        t = grown;
    }
    pattern[p..].iter().all(|atom| *atom == Atom::Star)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn glob(pattern: &str, text: &str) -> bool {
        matches(&atoms(pattern).collect::<Vec<_>>(), text, false)
    }

    /// The obvious recursive definition, to check against.
    fn reference(pattern: &[char], text: &[char]) -> bool {
        match pattern.split_first() {
            None => text.is_empty(),
            Some(('*', rest)) => (0..=text.len()).any(|skip| reference(rest, &text[skip..])),
            Some(('?', rest)) => !text.is_empty() && reference(rest, &text[1..]),
            Some((c, rest)) => text.first() == Some(c) && reference(rest, &text[1..]),
        }
    }

    #[test]
    fn stars_and_question_marks() {
        for (pattern, text, expected) in [
            ("*", "", true),
            ("*", "anything/at all", true),
            ("", "", true),
            ("", "a", false),
            ("a", "", false),
            ("abc", "abc", true),
            ("abc", "abcd", false),
            ("a*", "a", true),
            ("a*c", "abbbc", true),
            ("a*c", "abbbd", false),
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("*.jpg", "x/y.jpg", true),
            ("*.jpg", "x/y.jpg.png", false),
            ("a*b*c", "aXbYbZc", true),
            ("a*b*c", "aXbYbZ", false),
            ("**", "x", true),
            ("?*", "", false),
            ("home/*/doc?", "home/alice/docs", true),
            // `?` is one character, not one byte.
            ("caf?", "café", true),
            ("?", "日", true),
            ("??", "日", false),
            ("*本", "日本", true),
        ] {
            assert_eq!(glob(pattern, text), expected, "{pattern:?} on {text:?}");
        }
    }

    #[test]
    fn folding_is_for_ascii_letters() {
        let pattern: Vec<Atom> = atoms("s3:Get*").collect();
        assert!(matches(&pattern, "S3:GETOBJECT", true));
        assert!(!matches(&pattern, "S3:GETOBJECT", false));
    }

    #[test]
    fn literal_atoms_are_not_wildcards() {
        let pattern: Vec<Atom> = literal("a*").collect();
        assert!(matches(&pattern, "a*", false));
        assert!(!matches(&pattern, "ab", false));
    }

    #[test]
    fn agrees_with_the_recursive_definition() {
        // Every pattern and text up to length 5 over a small alphabet.
        let alphabet = ['a', 'b', '*', '?'];
        let (mut patterns, mut layer) = (vec![String::new()], vec![String::new()]);
        for _ in 0..5 {
            layer = layer
                .iter()
                .flat_map(|p| alphabet.iter().map(move |c| format!("{p}{c}")))
                .collect();
            patterns.extend(layer.iter().cloned());
        }
        let texts: Vec<&String> = patterns
            .iter()
            .filter(|p| !p.contains(['*', '?']))
            .collect();
        let mut checked = 0;
        for pattern in &patterns {
            let chars: Vec<char> = pattern.chars().collect();
            for text in &texts {
                let text_chars: Vec<char> = text.chars().collect();
                assert_eq!(
                    glob(pattern, text),
                    reference(&chars, &text_chars),
                    "{pattern:?} on {text:?}"
                );
                checked += 1;
            }
        }
        assert!(checked > 50_000, "{checked}");
    }

    #[test]
    fn hostile_patterns_stay_fast() {
        let pattern = "*a".repeat(2_000) + "b";
        let text = "a".repeat(20_000);
        let started = std::time::Instant::now();
        assert!(!glob(&pattern, &text));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }
}
