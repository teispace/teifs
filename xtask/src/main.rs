//! Project tasks, run with `cargo xtask <task>`.
//!
//! - `verify`: everything CI checks. Must pass before every commit.
//! - `docs`: only the documentation check.
//! - `release VERSION`: prepares a release (version, changelog, lock file).
//! - `release-notes VERSION`: prints a release's notes, checking they're in place.
//! - `manifests VERSION SHA256SUMS OUT`: a release's Homebrew formula and winget manifests.

#![allow(clippy::print_stdout, reason = "a task runner reports to the terminal")]

mod manifests;
mod release;

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let task = args.next().unwrap_or_default();
    let version = args.next();
    let rest: Vec<String> = args.collect();
    let root = root();
    let result = match (task.as_str(), version.as_deref()) {
        ("manifests", Some(version)) if rest.len() == 2 => {
            manifests::write(version, Path::new(&rest[0]), Path::new(&rest[1]))
        }
        _ if !rest.is_empty() => Err("too many arguments".into()),
        ("verify", None) => verify(&root),
        ("docs", None) => check_docs(&root).and_then(|()| check_planning_ids(&root)),
        ("release", Some(version)) => release::prepare(&root, version),
        ("release-notes", Some(version)) => release::notes(&root, version),
        _ => {
            eprintln!(
                "usage: cargo xtask <verify|docs|release VERSION|release-notes VERSION|manifests VERSION SHA256SUMS OUT>"
            );
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xtask: {message}");
            ExitCode::FAILURE
        }
    }
}

/// The workspace root (the parent of this crate).
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives inside the workspace")
        .to_owned()
}

fn verify(root: &Path) -> Result<(), String> {
    cargo(root, &["fmt", "--all", "--check"])?;
    cargo(
        root,
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    if has_subcommand("nextest") {
        cargo(root, &["nextest", "run", "--workspace", "--locked"])?;
        cargo(root, &["test", "--workspace", "--doc", "--locked"])?;
    } else {
        println!("cargo-nextest isn't installed; running cargo test");
        cargo(root, &["test", "--workspace", "--locked"])?;
    }
    if has_subcommand("deny") {
        cargo(root, &["deny", "--log-level", "error", "check"])?;
    } else {
        return Err("cargo-deny isn't installed: cargo install cargo-deny --locked".into());
    }
    check_docs(root)?;
    check_planning_ids(root)?;
    println!("verify: all checks passed");
    Ok(())
}

fn cargo(root: &Path, args: &[&str]) -> Result<(), String> {
    println!("▶ cargo {}", args.join(" "));
    let status = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(args)
        .current_dir(root)
        .status()
        .map_err(|e| format!("can't run cargo: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`cargo {}` failed", args.join(" ")))
    }
}

fn has_subcommand(name: &str) -> bool {
    Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args([name, "--version"])
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Markdown files whose code spans name repository paths.
const DOCS: &[&str] = &[
    "README.md",
    "AGENTS.md",
    "CONTRIBUTING.md",
    "docs/ARCHITECTURE.md",
    "docs/CONVENTIONS.md",
    "docs/SECURITY_MODEL.md",
    "docs/ON_DISK_FORMAT.md",
    "docs/ENCRYPTION_FORMAT.md",
    "docs/COMPATIBILITY.md",
    "docs/CLI.md",
    "tests/s3-tests/README.md",
];

/// Top-level folders a path in the docs can start with.
const TRACKED_ROOTS: &[&str] = &[
    "crates/", "apps/", "docs/", "xtask/", ".claude/", ".github/",
];

/// Where skills live.
const SKILLS: &str = ".claude/skills";

/// Fails when a doc names a repository path (in backticks or a relative link) that
/// doesn't exist, so the docs can't silently go stale when code moves.
fn check_docs(root: &Path) -> Result<(), String> {
    let mut missing = check_skills(root)?;
    let mut checked = 0;
    let skills = skill_names(root)?
        .into_iter()
        .map(|name| format!("{SKILLS}/{name}/SKILL.md"));
    let docs: Vec<String> = DOCS.iter().map(|d| (*d).to_owned()).chain(skills).collect();
    for doc in &docs {
        let text = fs::read_to_string(root.join(doc)).map_err(|e| format!("{doc}: {e}"))?;
        for path in referenced_paths(&text) {
            checked += 1;
            if !root.join(&path).exists() {
                missing.push(format!("{doc}: `{path}` doesn't exist"));
            }
        }
    }
    if missing.is_empty() {
        println!("docs: all {checked} referenced paths exist, skills are valid");
        Ok(())
    } else {
        Err(format!("docs and skills:\n  {}", missing.join("\n  ")))
    }
}

fn skill_names(root: &Path) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(root.join(SKILLS)).map_err(|e| format!("{SKILLS}: {e}"))? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.path().is_dir() {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    Ok(names)
}

/// Each skill has frontmatter whose `name` is its folder and a `description`, and is
/// listed in AGENTS.md's skills table.
fn check_skills(root: &Path) -> Result<Vec<String>, String> {
    let agents = fs::read_to_string(root.join("AGENTS.md")).map_err(|e| e.to_string())?;
    let mut problems = Vec::new();
    for name in skill_names(root)? {
        let file = format!("{SKILLS}/{name}/SKILL.md");
        let Ok(text) = fs::read_to_string(root.join(&file)) else {
            problems.push(format!("{file} is missing"));
            continue;
        };
        let Some(front) = text
            .strip_prefix("---\n")
            .and_then(|rest| rest.split_once("\n---\n"))
            .map(|(front, _)| front)
        else {
            problems.push(format!("{file}: no frontmatter"));
            continue;
        };
        if !front.lines().any(|l| l == format!("name: {name}")) {
            problems.push(format!("{file}: `name` must be `{name}`"));
        }
        if !front.lines().any(|l| {
            l.strip_prefix("description: ")
                .is_some_and(|d| d.len() >= 40)
        }) {
            problems.push(format!(
                "{file}: needs a `description` saying when to use it"
            ));
        }
        if !agents.contains(&format!("| `{name}` |")) {
            problems.push(format!(
                "AGENTS.md: skill `{name}` is missing from the table"
            ));
        }
    }
    Ok(problems)
}

/// Paths inside backticks that start with a tracked folder, trimmed of anything that
/// isn't part of the path (`crates/store/src/lib.rs:12`, `crates/meta` →
/// `crates/meta`). Paths with placeholders (`<`, `*`, `…`) are skipped.
fn referenced_paths(text: &str) -> Vec<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .filter(|span| TRACKED_ROOTS.iter().any(|r| span.starts_with(r)))
        .filter(|span| !span.contains(['<', '*', '…', ' ']))
        .map(|span| {
            let span = span.split(':').next().unwrap_or(span);
            span.trim_end_matches('/').to_owned()
        })
        .collect()
}

/// Fails when a file git tracks (or would) names a private planning id: a milestone task (the letter
/// F, a digit, a dash and two digits), a decision (F, dash, D, dash, digits) or a bare
/// milestone in parentheses. The maintainer's plans stay out of the public tree.
fn check_planning_ids(root: &Path) -> Result<(), String> {
    let out = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root)
        .output()
        .map_err(|e| format!("can't run git: {e}"))?;
    let mut found = Vec::new();
    for file in out.stdout.split(|b| *b == 0).filter(|f| !f.is_empty()) {
        let file = String::from_utf8_lossy(file);
        // Binary files and the lockfile can't hold prose.
        let Ok(text) = fs::read_to_string(root.join(file.as_ref())) else {
            continue;
        };
        if file == "Cargo.lock" {
            continue;
        }
        for (number, line) in text.lines().enumerate() {
            if let Some(id) = planning_id(line) {
                found.push(format!("{file}:{}: {id}", number + 1));
            }
        }
    }
    if found.is_empty() {
        println!("ids: no planning ids in tracked files");
        Ok(())
    } else {
        Err(format!(
            "planning ids in tracked files:\n  {}",
            found.join("\n  ")
        ))
    }
}

/// The first planning id in `line`, if any.
fn planning_id(line: &str) -> Option<String> {
    let chars: Vec<char> = line.chars().collect();
    let digit = |i: usize| chars.get(i).is_some_and(char::is_ascii_digit);
    let at = |i: usize, c: char| chars.get(i) == Some(&c);
    let word_start = |i: usize| i == 0 || !chars[i - 1].is_alphanumeric();
    for i in 0..chars.len() {
        if !at(i, 'F') || !word_start(i) {
            continue;
        }
        let task = digit(i + 1) && at(i + 2, '-') && digit(i + 3) && digit(i + 4);
        let decision = at(i + 1, '-') && at(i + 2, 'D') && at(i + 3, '-') && digit(i + 4);
        let milestone = i > 0 && at(i - 1, '(') && digit(i + 1) && at(i + 2, ')');
        let end = if task || decision {
            Some(i + 5)
        } else if milestone {
            Some(i + 2)
        } else {
            None
        };
        if let Some(end) = end
            && !chars
                .get(end)
                .is_some_and(|c| c.is_ascii_digit() && !at(i + 1, '-'))
        {
            return Some(chars[i..end].iter().collect());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_planning_ids() {
        let id = |parts: &[&str]| parts.concat();
        let task = id(&["F", "1-04"]);
        let decision = id(&["F-", "D-017"]);
        let milestone = id(&["(F", "1)"]);
        assert_eq!(planning_id(&format!("see {task} here")), Some(task.clone()));
        assert_eq!(planning_id(&format!("{task}b")), Some(task));
        assert!(planning_id(&format!("per {decision}.")).is_some());
        assert!(planning_id(&format!("limits {milestone}, later")).is_some());
        for fine in [
            "CRC32 F1 key",
            "0xF1-02",
            "RFC1-23",
            "F12",
            "PF1-04",
            "F1-2",
        ] {
            assert_eq!(planning_id(fine), None, "{fine}");
        }
    }

    #[test]
    fn finds_paths_in_code_spans() {
        let text = "See `crates/store/src/lib.rs:10`, `cargo test`, `docs/` and \
                    `crates/store/tests/fixtures/format-<n>.tar.gz`.";
        assert_eq!(referenced_paths(text), ["crates/store/src/lib.rs", "docs"]);
    }
}
