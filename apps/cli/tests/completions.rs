//! `teifs completions`: a script for each shell that knows every command.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

use std::process::Command;

#[test]
fn completions_know_every_command_in_every_shell() {
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let output = Command::new(env!("CARGO_BIN_EXE_teifs"))
            .args(["completions", shell])
            .env_clear()
            .output()
            .unwrap();
        assert!(output.status.success(), "{shell}");
        let script = String::from_utf8(output.stdout).unwrap();
        for command in [
            "init",
            "serve",
            "alias",
            "mirror",
            "presign",
            "admin",
            "completions",
        ] {
            assert!(script.contains(command), "{shell} lacks {command}");
        }
        assert!(!script.contains('\u{1b}'), "{shell}: no colors in a script");
    }
    let unknown = Command::new(env!("CARGO_BIN_EXE_teifs"))
        .args(["completions", "tcsh"])
        .output()
        .unwrap();
    assert_eq!(unknown.status.code(), Some(2));
}
