//! `teifs` run as a program against a TeiFS server, for the CLI's tests.

#![allow(dead_code, reason = "each test binary uses a different part")]

use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

use tempfile::TempDir;

use crate::common::{ACCESS_KEY, SECRET_KEY, Server};

/// A place to run `teifs` from, with alias `t` for the server (and `u`, the same
/// server by another name, so copies between them pass through the client).
pub struct Client {
    pub work: TempDir,
    pub env: Vec<(String, String)>,
}

pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Client {
    pub fn new(server: &Server) -> Self {
        let work = tempfile::tempdir().unwrap();
        let address = server.endpoint.trim_start_matches("http://");
        let port = address.rsplit_once(':').unwrap().1;
        let mut env = vec![
            (
                "TEIFS_ALIAS_T".to_owned(),
                format!("http://{ACCESS_KEY}:{SECRET_KEY}@{address}"),
            ),
            (
                "TEIFS_ALIAS_U".to_owned(),
                format!("http://{ACCESS_KEY}:{SECRET_KEY}@localhost:{port}"),
            ),
            (
                "TEIFS_CLIENT_CONFIG".to_owned(),
                work.path().join("aliases.toml").display().to_string(),
            ),
        ];
        // Windows can't open a socket without it.
        if let Some(root) = std::env::var_os("SystemRoot") {
            env.push(("SystemRoot".to_owned(), root.to_string_lossy().into_owned()));
        }
        Self { work, env }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.work.path().join(name)
    }

    /// Runs `teifs ARGS` in the work folder, feeding it `stdin`.
    pub async fn run_with(&self, args: &[&str], stdin: &str) -> Run {
        let args: Vec<String> = args.iter().map(|&a| a.to_owned()).collect();
        let (env, dir, stdin) = (
            self.env.clone(),
            self.work.path().to_owned(),
            stdin.to_owned(),
        );
        tokio::task::spawn_blocking(move || {
            let mut child = Command::new(env!("CARGO_BIN_EXE_teifs"))
                .args(&args)
                .current_dir(dir)
                .env_clear()
                .envs(env)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(stdin.as_bytes())
                .unwrap();
            let output = child.wait_with_output().unwrap();
            let run = Run {
                code: output.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            };
            assert!(
                !run.stdout.contains(SECRET_KEY) && !run.stderr.contains(SECRET_KEY),
                "a secret was printed: {}{}",
                run.stdout,
                run.stderr
            );
            run
        })
        .await
        .unwrap()
    }

    pub async fn run(&self, args: &[&str]) -> Run {
        self.run_with(args, "").await
    }

    /// Runs `teifs ARGS`, which must succeed; its standard output.
    pub async fn ok(&self, args: &[&str]) -> String {
        let run = self.run(args).await;
        assert_eq!(
            run.code, 0,
            "teifs {args:?} failed:\n{}{}",
            run.stdout, run.stderr
        );
        run.stdout
    }

    /// Runs `teifs ARGS`, which must fail with exit code `code`; its error output.
    pub async fn fails(&self, args: &[&str], code: i32) -> String {
        let run = self.run(args).await;
        assert_eq!(
            run.code, code,
            "teifs {args:?}:\n{}{}",
            run.stdout, run.stderr
        );
        run.stderr
    }
}

/// Each line of `--json` output, parsed; each must be an object with a `type`.
pub fn records(out: &str) -> Vec<serde_json::Value> {
    out.lines()
        .map(|line| {
            let record: serde_json::Value =
                serde_json::from_str(line).unwrap_or_else(|e| panic!("not JSON ({e}): {line}"));
            assert!(record["type"].is_string(), "no type: {line}");
            record
        })
        .collect()
}
