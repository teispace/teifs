//! The ceph/s3-tests results in `docs/COMPATIBILITY.md`, generated from the lists in
//! `tests/s3-tests/` so the published counts are always the lists' own. `cargo xtask
//! docs` fails when the section is out of date; `UPDATE_DOCS=1 cargo xtask docs` writes
//! it again.

use std::{collections::BTreeSet, fmt::Write as _, fs, path::Path};

/// The document the results are published in.
const DOC: &str = "docs/COMPATIBILITY.md";
const START: &str = "<!-- generated: s3-tests -->\n";
const END: &str = "<!-- end generated: s3-tests -->";
const LISTS: &str = "tests/s3-tests";

/// The tests a list names: one per line, without comments or reasons.
fn tests(text: &str) -> Vec<&str> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|test| !test.is_empty())
        .collect()
}

/// The ceph/s3-tests commit `run.sh` pins.
fn commit(run: &str) -> Option<&str> {
    run.lines()
        .find_map(|line| line.strip_prefix("COMMIT="))
        .map(str::trim)
        .filter(|c| c.len() >= 7 && c.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `part` of `whole` as a percentage with one decimal, rounded down.
fn percent(part: usize, whole: usize) -> String {
    let tenths = (part * 1000).checked_div(whole).unwrap_or(0);
    format!("{}.{}%", tenths / 10, tenths % 10)
}

struct Lists<'a> {
    implemented: Vec<&'a str>,
    unimplemented: Vec<&'a str>,
    excluded: Vec<&'a str>,
    folder_excluded: Vec<&'a str>,
}

impl Lists<'_> {
    /// What makes the counts wrong: a test in two lists, or listed twice, or a test folder
    /// buckets can't pass that object buckets don't pass either.
    fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let mut seen = BTreeSet::new();
        for (list, names) in [
            ("implemented.txt", &self.implemented),
            ("unimplemented.txt", &self.unimplemented),
            ("excluded.txt", &self.excluded),
        ] {
            for &name in names {
                if !seen.insert(name) {
                    problems.push(format!("{list}: {name} is listed more than once"));
                }
            }
        }
        let implemented: BTreeSet<_> = self.implemented.iter().collect();
        for name in &self.folder_excluded {
            if !implemented.contains(name) {
                problems.push(format!(
                    "folder-excluded.txt: {name} isn't in implemented.txt"
                ));
            }
        }
        problems
    }

    /// The generated section's text.
    fn summary(&self, commit: &str) -> String {
        let implemented = self.implemented.len();
        let not_yet = self.unimplemented.len();
        let excluded = self.excluded.len();
        let folder = implemented - self.folder_excluded.len().min(implemented);
        let run = implemented + not_yet + excluded;
        let goal = implemented + not_yet;
        let short = commit.get(..7).unwrap_or(commit);
        let mut out = format!(
            "The suite at commit [`{short}`](https://github.com/ceph/s3-tests/tree/{commit}), \
             counted from the lists:\n\n\
             | Tests | Count | |\n|---|---|---|\n\
             | Pass on object buckets (`implemented.txt`) | {implemented} | {} of the {goal} that are a goal |\n\
             | Pass on folder buckets too | {folder} | the other {} store keys a folder can't hold, or need encryption at rest (`folder-excluded.txt`) |\n\
             | Not supported yet (`unimplemented.txt`) | {not_yet} | standard S3 behaviour still to come |\n\
             | Not a goal (`excluded.txt`) | {excluded} | another server's own behaviour, or a test that can't pass anywhere; each says why |\n\
             | Run | {run} | |\n",
            percent(implemented, goal),
            implemented - folder,
        );
        if !self.unimplemented.is_empty() {
            let _ = write!(
                out,
                "\n<details><summary>The {not_yet} tests not supported yet</summary>\n\n"
            );
            for name in &self.unimplemented {
                let _ = writeln!(out, "- `{name}`");
            }
            out.push_str("\n</details>\n");
        }
        out
    }
}

/// Checks the section, or writes it again when `update`.
pub fn check(root: &Path, update: bool) -> Result<(), String> {
    let read = |path: &str| fs::read_to_string(root.join(path)).map_err(|e| format!("{path}: {e}"));
    let texts = [
        read(&format!("{LISTS}/implemented.txt"))?,
        read(&format!("{LISTS}/unimplemented.txt"))?,
        read(&format!("{LISTS}/excluded.txt"))?,
        read(&format!("{LISTS}/folder-excluded.txt"))?,
    ];
    let lists = Lists {
        implemented: tests(&texts[0]),
        unimplemented: tests(&texts[1]),
        excluded: tests(&texts[2]),
        folder_excluded: tests(&texts[3]),
    };
    let problems = lists.problems();
    if !problems.is_empty() {
        return Err(format!("s3-tests lists:\n  {}", problems.join("\n  ")));
    }
    let run = read(&format!("{LISTS}/run.sh"))?;
    let commit = commit(&run).ok_or(format!("{LISTS}/run.sh has no COMMIT= line"))?;
    let doc = read(DOC)?;
    let current = replace(&doc, &lists.summary(commit))?;
    if current == doc {
        println!("s3-tests: {DOC}'s results match the lists");
        Ok(())
    } else if update {
        fs::write(root.join(DOC), current).map_err(|e| format!("{DOC}: {e}"))?;
        println!("s3-tests: wrote the results into {DOC}");
        Ok(())
    } else {
        Err(format!(
            "{DOC}'s s3-tests results are out of date: run `UPDATE_DOCS=1 cargo xtask docs`"
        ))
    }
}

/// `doc` with its generated section replaced by `section`.
fn replace(doc: &str, section: &str) -> Result<String, String> {
    let (before, rest) = doc
        .split_once(START)
        .ok_or(format!("{DOC} has no `{}` marker", START.trim()))?;
    let (_, after) = rest
        .split_once(END)
        .ok_or(format!("{DOC} has no `{END}` marker"))?;
    Ok(format!("{before}{START}{section}{END}{after}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_are_read_without_comments_or_reasons() {
        let text = "# Heading\n# more\ntest_a\n\ntest_b[x-1]  # why\n  \n";
        assert_eq!(tests(text), ["test_a", "test_b[x-1]"]);
        assert_eq!(commit("X=1\nCOMMIT=5522d1c351f7\n"), Some("5522d1c351f7"));
        assert_eq!(commit("COMMIT=main\n"), None);
        assert_eq!(percent(535, 602), "88.8%");
        assert_eq!(percent(1, 0), "0.0%");
    }

    #[test]
    fn counts_come_from_the_lists_and_overlaps_are_refused() {
        let lists = Lists {
            implemented: vec!["a", "b", "c"],
            unimplemented: vec!["d"],
            excluded: vec!["e"],
            folder_excluded: vec!["c"],
        };
        assert!(lists.problems().is_empty());
        let summary = lists.summary("5522d1c351f75bc00ae0f64f742f3f095f5939d9");
        assert!(summary.contains("| Pass on object buckets (`implemented.txt`) | 3 | 75.0% of the 4 that are a goal |"), "{summary}");
        assert!(
            summary.contains("| Pass on folder buckets too | 2 | the other 1 "),
            "{summary}"
        );
        assert!(summary.contains("| Run | 5 | |"), "{summary}");
        assert!(summary.contains("[`5522d1c`]"), "{summary}");
        assert!(summary.contains("- `d`\n"), "{summary}");
        let twice = Lists {
            implemented: vec!["a"],
            unimplemented: vec!["a"],
            excluded: vec![],
            folder_excluded: vec!["z"],
        };
        assert_eq!(twice.problems().len(), 2, "{:?}", twice.problems());
    }

    #[test]
    fn only_the_generated_section_is_replaced() {
        let doc = format!("intro\n{START}old\n{END}\nrest\n");
        assert_eq!(
            replace(&doc, "new\n").unwrap(),
            format!("intro\n{START}new\n{END}\nrest\n")
        );
        assert!(replace("no markers", "x").is_err());
    }

    /// The repository's own lists are consistent and the published section is theirs.
    #[test]
    fn the_published_results_are_current() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        check(root, false).unwrap();
    }
}
