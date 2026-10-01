//! `teifs serve` started again as it was started, when the admin API asks it to restart
//! (`mc admin service restart`, `teifs admin service restart`).
//!
//! On Unix the process becomes the new one (`exec`), so it keeps its process id: a
//! service manager sees one process throughout. Windows has no `exec`, so the new one is
//! a child, and this process waits for it and ends as it ends.

use std::{
    path::PathBuf,
    process::{Command, ExitCode},
};

use crate::{error::Error, ui};

/// Starts `teifs` again with the arguments it was given; returns only if it can't.
pub fn again() -> ExitCode {
    let mut command = Command::new(program());
    command.args(std::env::args_os().skip(1));
    let err = run(&mut command);
    let err = Error::general(format!("can't start again: {err}"));
    ui::error(&err);
    ExitCode::from(err.kind.code())
}

/// This program: the binary that was started, or the one now at its path when a package
/// replaced it (Linux names a replaced binary `PATH (deleted)`).
fn program() -> PathBuf {
    let Ok(path) = std::env::current_exe() else {
        return PathBuf::from("teifs");
    };
    match path.to_str().and_then(|p| p.strip_suffix(" (deleted)")) {
        Some(replaced) => PathBuf::from(replaced),
        None => path,
    }
}

#[cfg(unix)]
fn run(command: &mut Command) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    command.exec()
}

#[cfg(not(unix))]
fn run(command: &mut Command) -> std::io::Error {
    match command.status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(err) => err,
    }
}
