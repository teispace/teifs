//! Everything `teifs` shows: results, confirmations, warnings, errors with what to do,
//! tables, progress and questions. Commands say *what* to show; this module decides how.
//!
//! - Results (listings, details, links) go to standard output; notes, warnings, errors
//!   and progress go to standard error, so `teifs ls … | …` gets only the listing.
//! - `--json` makes standard output JSON Lines: one object per line, each with a
//!   `type`, for every result, confirmation and error (as `{"type":"error",…}`).
//! - `--quiet` drops confirmations and notes (not results, warnings or errors).
//! - Colors follow `--color` (auto: only on a terminal, and never with `NO_COLOR`);
//!   progress bars and questions appear only on a terminal.

use std::{
    fmt::{Display, Write as _},
    io::IsTerminal,
    sync::{Mutex, OnceLock},
    time::Duration,
};

use anstyle::{AnsiColor, Style};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use serde_json::Value;

use crate::error::{Error, Kind};

const SUCCESS: Style = AnsiColor::Green.on_default().bold();
const WARNING: Style = AnsiColor::Yellow.on_default().bold();
const FAILURE: Style = AnsiColor::Red.on_default().bold();
const DIM: Style = Style::new().dimmed();
const HEADER: Style = Style::new().bold();
const FOLDER: Style = AnsiColor::Blue.on_default().bold();

/// How output is shown, from the global flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct Settings {
    pub json: bool,
    pub quiet: bool,
    /// Questions are answered yes (`--yes`).
    pub yes: bool,
}

/// `--color`.
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum ColorArg {
    /// On a terminal, unless `NO_COLOR` is set.
    #[default]
    Auto,
    Always,
    Never,
}

static SETTINGS: OnceLock<Settings> = OnceLock::new();
/// The progress bar on screen, if any: lines are printed around it.
static BAR: Mutex<Option<ProgressBar>> = Mutex::new(None);

/// Sets how output is shown; once, before anything is shown.
pub fn init(settings: Settings, color: ColorArg) {
    let choice = match color {
        ColorArg::Auto => anstream::ColorChoice::Auto,
        ColorArg::Always => anstream::ColorChoice::Always,
        ColorArg::Never => anstream::ColorChoice::Never,
    };
    choice.write_global();
    let _ = SETTINGS.set(settings);
}

fn settings() -> Settings {
    SETTINGS.get().copied().unwrap_or_default()
}

/// Whether standard output is JSON Lines.
pub fn json() -> bool {
    settings().json
}

/// Runs `print` without tearing the progress bar, if one is showing.
fn around_bar<T>(print: impl FnOnce() -> T) -> T {
    let bar = BAR.lock().ok().and_then(|bar| bar.clone());
    match bar {
        Some(bar) => bar.suspend(print),
        None => print(),
    }
}

fn stdout_line(line: &str) {
    raw(&format!("{line}\n"));
}

/// `text` on standard output as it is, for output meant for another program (a
/// completion script); a reader that stops early ends the command quietly.
pub fn raw(text: &str) {
    use std::io::Write;
    let result = around_bar(|| anstream::stdout().write_all(text.as_bytes()));
    if let Err(err) = result
        && err.kind() == std::io::ErrorKind::BrokenPipe
    {
        // The reader stopped (`teifs ls … | head`): nothing more to say.
        std::process::exit(0);
    }
}

fn stderr_line(line: &str) {
    use std::io::Write;
    let _ = around_bar(|| writeln!(anstream::stderr(), "{line}"));
}

/// `text` dimmed, for secondary columns (dates, sizes).
pub fn dim(text: impl Display) -> String {
    format!("{DIM}{text}{DIM:#}")
}

/// `text` styled as a folder or bucket name.
pub fn folder(text: impl Display) -> String {
    format!("{FOLDER}{text}{FOLDER:#}")
}

/// A result: the line for people, or the record for `--json`.
pub fn item(human: impl FnOnce() -> String, record: impl FnOnce() -> Value) {
    if json() {
        emit(&record());
    } else {
        stdout_line(&human());
    }
}

/// A JSON line, whatever the mode (for commands whose output is always JSON-shaped).
pub fn emit(record: &Value) {
    stdout_line(&record.to_string());
}

/// Something done: `✓ message` for people (not with `--quiet`), or the record.
pub fn done(message: impl Display, record: impl FnOnce() -> Value) {
    if json() {
        emit(&record());
    } else if !settings().quiet {
        stdout_line(&format!("{SUCCESS}✓{SUCCESS:#} {message}"));
    }
}

/// Secondary information for people, on standard error (not with `--quiet` or `--json`).
pub fn note(message: impl Display) {
    let settings = settings();
    if !settings.quiet && !settings.json {
        stderr_line(&format!("{DIM}{message}{DIM:#}"));
    }
}

/// Something to know about that didn't stop the command.
pub fn warn(message: impl Display) {
    stderr_line(&format!("{WARNING}warning:{WARNING:#} {message}"));
}

/// A failure: `error: message` and what to do on standard error, and with `--json` a
/// record on standard output too.
pub fn error(err: &Error) {
    if err.shown {
        return;
    }
    if json() {
        emit(&serde_json::json!({
            "type": "error",
            "kind": err.kind.name(),
            "exitCode": err.kind.code(),
            "message": err.message,
            "hint": err.hint,
        }));
    }
    stderr_line(&render_error(err));
}

fn render_error(err: &Error) -> String {
    let mut text = format!("{FAILURE}error:{FAILURE:#} {}", err.message);
    if let Some(hint) = &err.hint {
        let _ = write!(text, "\n  {DIM}→{DIM:#} {hint}");
    }
    text
}

/// Asks a yes-or-no question on the terminal. `--yes` answers yes; with no terminal to
/// ask on, it fails with `unattended`'s advice.
pub fn confirm(question: &str, unattended: &str) -> Result<bool, Error> {
    if settings().yes {
        return Ok(true);
    }
    if !interactive() {
        return Err(
            Error::new(Kind::Usage, format!("{question} (can't ask: no terminal)"))
                .with_hint(unattended.to_owned()),
        );
    }
    around_bar(|| {
        inquire::Confirm::new(question)
            .with_default(false)
            .prompt()
            .map_err(prompt_error)
    })
}

/// Whether to ask rather than take defaults: questions can be asked, and `--yes`
/// didn't say to take them.
pub fn asking() -> bool {
    !settings().yes && interactive()
}

/// Asks for a line of text, `default` when left empty; `check` says what's wrong
/// with an answer.
pub fn ask_text(
    question: &str,
    default: &str,
    check: impl Fn(&str) -> Result<(), String> + Clone + 'static,
) -> Result<String, Error> {
    use inquire::validator::Validation;
    around_bar(|| {
        inquire::Text::new(question)
            .with_default(default)
            .with_validator(move |text: &str| {
                Ok(match check(text.trim()) {
                    Ok(()) => Validation::Valid,
                    Err(why) => Validation::Invalid(why.into()),
                })
            })
            .prompt()
            .map(|text| text.trim().to_owned())
            .map_err(prompt_error)
    })
}

/// Asks to pick one of `options` (the first is the default); returns its index.
pub fn ask_choice(question: &str, options: &[&str]) -> Result<usize, Error> {
    around_bar(|| {
        inquire::Select::new(question, options.to_vec())
            .raw_prompt()
            .map(|choice| choice.index)
            .map_err(prompt_error)
    })
}

/// Asks a yes-or-no question whose answer is `default` when Enter is pressed.
pub fn ask_yes(question: &str, default: bool) -> Result<bool, Error> {
    around_bar(|| {
        inquire::Confirm::new(question)
            .with_default(default)
            .prompt()
            .map_err(prompt_error)
    })
}

fn prompt_error(err: inquire::InquireError) -> Error {
    match err {
        inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted => {
            Error::usage("stopped: nothing more was done")
        }
        err => Error::usage(err.to_string()),
    }
}

/// Whether questions can be asked: standard input and error are a terminal, and the
/// output isn't for a program.
pub fn interactive() -> bool {
    !json() && std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// A table with a header, columns aligned (by display width, so names in any script
/// line up); the last column isn't padded.
pub struct Table {
    header: Vec<&'static str>,
    right: Vec<bool>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// Columns named `header`; a name starting with `>` is right-aligned (numbers).
    pub fn new(header: &[&'static str]) -> Self {
        Self {
            header: header.iter().map(|h| h.trim_start_matches('>')).collect(),
            right: header.iter().map(|h| h.starts_with('>')).collect(),
            rows: Vec::new(),
        }
    }

    pub fn row(&mut self, cells: Vec<String>) {
        debug_assert_eq!(cells.len(), self.header.len());
        self.rows.push(cells);
    }

    /// The table's lines, header first.
    pub fn lines(&self) -> Vec<String> {
        use unicode_width::UnicodeWidthStr;
        let header: Vec<String> = self.header.iter().map(|h| (*h).to_owned()).collect();
        let mut widths = vec![0; self.header.len()];
        for row in std::iter::once(&header).chain(&self.rows) {
            for (width, cell) in widths.iter_mut().zip(row) {
                *width = (*width).max(cell.width());
            }
        }
        let render = |row: &[String]| {
            let last = row.len() - 1;
            let cells: Vec<String> = row
                .iter()
                .enumerate()
                .map(|(i, cell)| {
                    let pad = " ".repeat(widths[i] - cell.width());
                    if self.right[i] {
                        format!("{pad}{cell}")
                    } else if i == last {
                        cell.clone()
                    } else {
                        format!("{cell}{pad}")
                    }
                })
                .collect();
            cells.join("  ").trim_end().to_owned()
        };
        std::iter::once(format!("{HEADER}{}{HEADER:#}", render(&header)))
            .chain(self.rows.iter().map(|row| render(row)))
            .collect()
    }

    /// Prints the table (no rows: `empty` instead, as a note).
    pub fn print(&self, empty: &str) {
        if self.rows.is_empty() {
            note(empty);
            return;
        }
        for line in self.lines() {
            stdout_line(&line);
        }
    }
}

/// Details of one thing: `Label:  value` lines for people (labels aligned, values
/// that are empty left out), or `record` for `--json`.
pub fn details(fields: &[(&str, String)], record: impl FnOnce() -> Value) {
    if json() {
        emit(&record());
        return;
    }
    for line in field_lines(fields, "") {
        stdout_line(&line);
    }
}

fn field_lines(fields: &[(&str, String)], indent: &str) -> Vec<String> {
    let width = fields
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0)
        + 1;
    fields
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(label, value)| {
            let label = format!("{label}:");
            format!("{indent}{DIM}{label:<width$}{DIM:#}  {value}")
        })
        .collect()
}

/// A block for people on standard error: a `✓ title`, its fields, then `next` steps
/// (commands to copy). Not shown with `--quiet` or `--json`.
pub fn banner(title: impl Display, fields: &[(&str, String)], next: &[String]) {
    let settings = settings();
    if settings.quiet || settings.json {
        return;
    }
    let mut lines = vec![format!("{SUCCESS}✓{SUCCESS:#} {HEADER}{title}{HEADER:#}")];
    lines.extend(field_lines(fields, "  "));
    if !next.is_empty() {
        lines.push(String::new());
        lines.push(format!("  {DIM}Next:{DIM:#}"));
        lines.extend(next.iter().map(|line| format!("    {line}")));
    }
    stderr_line(&lines.join("\n"));
}

/// Rows of a result: `table` for people, or one record each for `--json`.
pub fn rows(table: &Table, records: &[Value], empty: &str) {
    if json() {
        for record in records {
            emit(record);
        }
    } else {
        table.print(empty);
    }
}

/// A progress bar for bytes on standard error, shown only on a terminal (not with
/// `--quiet` or `--json`); otherwise every call does nothing. Clones share one bar.
#[derive(Clone)]
pub struct Progress(Option<ProgressBar>);

impl Progress {
    /// A bar for `total` bytes, labelled `label`.
    pub fn bytes(total: u64, label: &str) -> Self {
        let settings = settings();
        if settings.quiet || settings.json || !std::io::stderr().is_terminal() {
            return Self(None);
        }
        let bar = ProgressBar::with_draw_target(Some(total), ProgressDrawTarget::stderr());
        bar.set_style(
            ProgressStyle::with_template(
                "{msg} {wide_bar} {binary_bytes}/{binary_total_bytes} {binary_bytes_per_sec} {eta}",
            )
            .expect("the template is valid")
            .progress_chars("━━─"),
        );
        bar.set_message(label.to_owned());
        bar.enable_steady_tick(Duration::from_millis(120));
        if let Ok(mut current) = BAR.lock() {
            *current = Some(bar.clone());
        }
        Self(Some(bar))
    }

    pub fn add(&self, bytes: u64) {
        if let Some(bar) = &self.0 {
            bar.inc(bytes);
        }
    }

    /// Takes the bar off the screen.
    pub fn finish(&self) {
        if let Some(bar) = &self.0 {
            bar.finish_and_clear();
            if let Ok(mut current) = BAR.lock() {
                *current = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_align_by_display_width() {
        anstream::ColorChoice::Never.write_global();
        let mut table = Table::new(&["NAME", ">SIZE", "NOTE"]);
        table.row(vec!["naïve café".into(), "5 B".into(), "x".into()]);
        table.row(vec!["日本".into(), "12.0 KiB".into(), String::new()]);
        let lines: Vec<String> = table
            .lines()
            .iter()
            .map(|l| anstream::adapter::strip_str(l).to_string())
            .collect();
        assert_eq!(
            lines,
            [
                "NAME            SIZE  NOTE",
                "naïve café       5 B  x",
                "日本        12.0 KiB",
            ]
        );
    }

    #[test]
    fn errors_say_what_to_do_on_their_own_line() {
        let err =
            Error::new(Kind::NotFound, "there's no alias x").with_hint("see `teifs alias ls`");
        let text = anstream::adapter::strip_str(&render_error(&err)).to_string();
        assert_eq!(text, "error: there's no alias x\n  → see `teifs alias ls`");
    }
}
