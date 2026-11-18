//! `docs/CLI.md`: every command and option, generated from the command line's own
//! definition so it can't fall behind, and a check that each says what it does.

use std::fmt::Write as _;

use clap::{Arg, Command, CommandFactory, builder::StyledStr};

use crate::Cli;

/// Every visible command, depth first, built (so each knows its full name).
fn commands(command: &Command, out: &mut Vec<Command>) {
    if command.is_hide_set() {
        return;
    }
    out.push(command.clone());
    for sub in command.get_subcommands().filter(|c| c.get_name() != "help") {
        commands(sub, out);
    }
}

fn all() -> Vec<Command> {
    let mut root = Cli::command();
    root.build();
    let mut out = Vec::new();
    commands(&root, &mut out);
    out
}

/// Paragraphs of `text`, each on one line and ending as a sentence does (clap drops a
/// one-line help's full stop).
fn paragraphs(text: Option<&StyledStr>) -> Vec<String> {
    text.map(ToString::to_string)
        .unwrap_or_default()
        .split("\n\n")
        .map(|p| p.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|p| !p.is_empty())
        .map(|p| if p.ends_with(['.', ':']) { p } else { p + "." })
        .collect()
}

/// The options a command's section lists: its own, not `--help` and not the global ones
/// every command takes (those are listed once, under `teifs`).
fn listed(command: &Command, root: bool) -> impl Iterator<Item = &Arg> {
    command.get_arguments().filter(move |arg| {
        !arg.is_hide_set()
            && !matches!(arg.get_id().as_str(), "help" | "version")
            && (root || !arg.is_global_set())
    })
}

fn name(arg: &Arg) -> String {
    let value = arg
        .get_value_names()
        .and_then(|names| names.first())
        .map_or_else(|| arg.get_id().as_str().to_uppercase(), ToString::to_string);
    let takes_value = arg.get_num_args().is_some_and(|n| n.takes_values());
    match (arg.get_long(), arg.get_short()) {
        (None, None) => format!("`<{value}>`"),
        (long, short) => {
            let mut flag = [
                short.map(|s| format!("-{s}")),
                long.map(|l| format!("--{l}")),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", ");
            if takes_value {
                let _ = write!(flag, " <{value}>");
            }
            format!("`{flag}`")
        }
    }
}

fn description(arg: &Arg) -> String {
    let mut text = paragraphs(arg.get_long_help().or(arg.get_help())).join(" ");
    let values: Vec<String> = arg
        .get_possible_values()
        .iter()
        .filter(|v| !v.is_hide_set())
        .map(|v| format!("`{}`", v.get_name()))
        .collect();
    if !values.is_empty() && arg.get_num_args().is_some_and(|n| n.takes_values()) {
        let _ = write!(text, " One of {}.", values.join(", "));
    }
    let defaults: Vec<String> = arg
        .get_default_values()
        .iter()
        .map(|v| v.to_string_lossy().into_owned())
        .collect();
    if !defaults.is_empty() && arg.get_action().takes_values() {
        let _ = write!(text, " Default: `{}`.", defaults.join(","));
    }
    if let Some(env) = arg.get_env() {
        let _ = write!(text, " Environment: `{}`.", env.to_string_lossy());
    }
    text.replace('|', "\\|")
}

fn reference() -> String {
    let mut out = String::new();
    for (i, command) in all().iter_mut().enumerate() {
        let full = command
            .get_bin_name()
            .unwrap_or(command.get_name())
            .to_owned();
        let _ = writeln!(out, "## {full}\n");
        for paragraph in paragraphs(command.get_long_about().or(command.get_about())) {
            let _ = writeln!(out, "{paragraph}\n");
        }
        let usage = command.render_usage().to_string();
        let usage = usage.trim_start_matches("Usage: ").trim();
        let _ = writeln!(out, "```\n{usage}\n```\n");
        let args: Vec<&Arg> = listed(command, i == 0).collect();
        if !args.is_empty() {
            out.push_str("| Argument | |\n|---|---|\n");
            for arg in args {
                let _ = writeln!(out, "| {} | {} |", name(arg), description(arg));
            }
            out.push('\n');
        }
    }
    out
}

#[test]
fn every_command_and_option_says_what_it_does() {
    let mut silent = Vec::new();
    for (i, command) in all().iter().enumerate() {
        let full = command.get_bin_name().unwrap_or(command.get_name());
        if paragraphs(command.get_about()).is_empty() {
            silent.push(full.to_owned());
        }
        for arg in listed(command, i == 0) {
            if paragraphs(arg.get_help()).is_empty() {
                silent.push(format!("{full} {}", arg.get_id()));
            }
        }
    }
    assert!(silent.is_empty(), "no help: {silent:#?}");
}

#[test]
fn the_command_line_reference_is_current() {
    const START: &str = "<!-- generated: commands -->\n";
    const END: &str = "<!-- end generated -->";
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/CLI.md");
    let doc = std::fs::read_to_string(path).unwrap();
    let (before, rest) = doc.split_once(START).expect("the start marker");
    let (_, after) = rest.split_once(END).expect("the end marker");
    let current = format!("{before}{START}\n{}{END}{after}", reference());
    if std::env::var_os("UPDATE_DOCS").is_some() {
        std::fs::write(path, &current).unwrap();
        return;
    }
    assert!(
        doc == current,
        "docs/CLI.md is out of date: run this test with UPDATE_DOCS=1"
    );
}

/// The words of a shell command line, as `sh` splits them: quotes kept together, a `#`
/// starting a word ends the line.
fn shell_words(line: &str) -> Vec<String> {
    let (mut words, mut word, mut quote, mut started) = (Vec::new(), String::new(), None, false);
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => word.push(c),
            (None, '\'' | '"') => (quote, started) = (Some(c), true),
            (None, '#') if !started => break,
            (None, c) if c.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                }
                started = false;
            }
            (None, c) => (word.push(c), started = true).1,
        }
    }
    if started {
        words.push(word);
    }
    words
}

/// Every `teifs` command in a Markdown file's `sh` blocks, as words, with continued lines
/// joined and pipes and `&&` splitting commands.
fn teifs_commands(markdown: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for block in markdown.split("```sh\n").skip(1) {
        let block = block.split("\n```").next().unwrap_or_default();
        for line in block.replace("\\\n", " ").lines() {
            let words = shell_words(line);
            for command in words.split(|w| matches!(w.as_str(), "|" | "&&" | ";")) {
                if command.first().is_some_and(|w| w == "teifs") {
                    out.push(command.to_vec());
                }
            }
        }
    }
    out
}

#[test]
fn shell_lines_split_as_sh_splits_them() {
    assert_eq!(
        shell_words(r#"teifs cp 'a b' "c d" e # a comment"#),
        ["teifs", "cp", "a b", "c d", "e"]
    );
    let commands = teifs_commands(
        "```sh\nteifs ls a | teifs cp - b \\\n  --part-size 8MiB\nmc ls x\n```\n```yaml\nteifs: no\n```\n",
    );
    assert_eq!(
        commands,
        [
            vec!["teifs", "ls", "a"],
            vec!["teifs", "cp", "-", "b", "--part-size", "8MiB"]
        ]
    );
}

/// The guides people follow command by command: each `teifs` command they show must be
/// one the command line takes.
#[test]
fn the_guides_commands_are_ones_teifs_takes() {
    use clap::Parser as _;
    for guide in ["docs/MOVING_FROM_MINIO.md"] {
        let path = format!("{}/../../{guide}", env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(path).unwrap();
        let commands = teifs_commands(&text);
        assert!(commands.len() > 5, "{guide}: {commands:?}");
        for words in commands {
            if let Err(err) = Cli::try_parse_from(&words) {
                panic!("{guide}: `{}` doesn't parse: {err}", words.join(" "));
            }
        }
    }
}
