//! Project tasks, run with `cargo xtask <task>`.
//!
//! - `verify`: everything CI checks. Must pass before every commit.
//! - `docs`: only the documentation check.

#![allow(clippy::print_stdout, reason = "a task runner reports to the terminal")]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

fn main() -> ExitCode {
    let task = env::args().nth(1).unwrap_or_default();
    let root = root();
    let result = match task.as_str() {
        "verify" => verify(&root),
        "docs" => check_docs(&root),
        _ => {
            eprintln!("usage: cargo xtask <verify|docs>");
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
    "docs/COMPATIBILITY.md",
];

/// Top-level folders a path in the docs can start with.
const TRACKED_ROOTS: &[&str] = &["crates/", "apps/", "docs/", "xtask/"];

/// Fails when a doc names a repository path (in backticks or a relative link) that
/// doesn't exist, so the docs can't silently go stale when code moves.
fn check_docs(root: &Path) -> Result<(), String> {
    let mut missing = Vec::new();
    let mut checked = 0;
    for doc in DOCS {
        let text = fs::read_to_string(root.join(doc)).map_err(|e| format!("{doc}: {e}"))?;
        for path in referenced_paths(&text) {
            checked += 1;
            if !root.join(&path).exists() {
                missing.push(format!("{doc}: `{path}` doesn't exist"));
            }
        }
    }
    if missing.is_empty() {
        println!("docs: all {checked} referenced paths exist");
        Ok(())
    } else {
        Err(format!(
            "stale paths in the docs:\n  {}",
            missing.join("\n  ")
        ))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_paths_in_code_spans() {
        let text = "See `crates/store/src/lib.rs:10`, `cargo test`, `docs/` and \
                    `crates/store/tests/fixtures/format-<n>.tar.gz`.";
        assert_eq!(referenced_paths(text), ["crates/store/src/lib.rs", "docs"]);
    }
}
