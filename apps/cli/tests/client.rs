//! `teifs` as an S3 client, through the real binary against a TeiFS server: aliases,
//! copies both ways and between endpoints, resumed uploads, mirrors, removals, and the
//! exit codes scripts rely on.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

#[path = "../../../crates/server/tests/common/mod.rs"]
mod common;

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use aws_sdk_s3::{
    primitives::ByteStream,
    types::{ChecksumAlgorithm, CompletedMultipartUpload, CompletedPart},
};
use common::{ACCESS_KEY, SECRET_KEY, Server, client, start, start_with};
use tempfile::TempDir;

const MIB: usize = 1024 * 1024;

/// A place to run `teifs` from, with alias `t` for the server (and `u`, the same
/// server by another name, so copies between them pass through the client).
struct Client {
    work: TempDir,
    env: Vec<(String, String)>,
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Client {
    fn new(server: &Server) -> Self {
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

    fn path(&self, name: &str) -> PathBuf {
        self.work.path().join(name)
    }

    /// Runs `teifs ARGS` in the work folder, feeding it `stdin`.
    async fn run_with(&self, args: &[&str], stdin: &str) -> Run {
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

    async fn run(&self, args: &[&str]) -> Run {
        self.run_with(args, "").await
    }

    /// Runs `teifs ARGS`, which must succeed; its standard output.
    async fn ok(&self, args: &[&str]) -> String {
        let run = self.run(args).await;
        assert_eq!(
            run.code, 0,
            "teifs {args:?} failed:\n{}{}",
            run.stdout, run.stderr
        );
        run.stdout
    }

    /// Runs `teifs ARGS`, which must fail with exit code `code`; its error output.
    async fn fails(&self, args: &[&str], code: i32) -> String {
        let run = self.run(args).await;
        assert_eq!(
            run.code, code,
            "teifs {args:?}:\n{}{}",
            run.stdout, run.stderr
        );
        run.stderr
    }
}

/// Bytes that differ from part to part, so a misplaced part shows.
fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i / 4099 + i * 31 + usize::from(seed)) % 251).unwrap())
        .collect()
}

/// A folder with nested, Unicode, spaced and empty files.
fn make_tree(root: &Path) {
    fs::create_dir_all(root.join("a/b")).unwrap();
    fs::create_dir_all(root.join("ünïcødé")).unwrap();
    fs::write(root.join("a/one.txt"), "one").unwrap();
    fs::write(root.join("a/b/deep.bin"), data(70_000, 1)).unwrap();
    fs::write(root.join("ünïcødé/naïve café.txt"), "café").unwrap();
    fs::write(root.join("with space.txt"), "spaced").unwrap();
    fs::write(root.join("empty"), "").unwrap();
}

/// Every file under `root`, by relative path, with its bytes.
fn read_tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut folders = vec![root.to_owned()];
    while let Some(folder) = folders.pop() {
        for item in fs::read_dir(folder).unwrap() {
            let path = item.unwrap().path();
            if path.is_dir() {
                folders.push(path);
            } else {
                let relative = path.strip_prefix(root).unwrap();
                let relative = relative
                    .components()
                    .map(|c| c.as_os_str().to_str().unwrap())
                    .collect::<Vec<_>>()
                    .join("/");
                files.push((relative, fs::read(&path).unwrap()));
            }
        }
    }
    files.sort();
    files
}

#[tokio::test(flavor = "multi_thread")]
async fn folders_and_large_files_copy_both_ways() {
    let server = start().await;
    let cli = Client::new(&server);
    make_tree(&cli.path("tree"));
    let big = data(21 * MIB + 5, 7);
    fs::write(cli.path("big.bin"), &big).unwrap();

    cli.ok(&["mb", "t/files"]).await;
    let out = cli.ok(&["cp", "-r", "tree", "t/files/tree"]).await;
    assert!(out.contains("Copied 5 files"), "{out}");
    // A destination ending in / takes the file's name; parts of 5 MiB go four at once.
    cli.ok(&[
        "cp",
        "big.bin",
        "t/files/",
        "--part-size",
        "5MiB",
        "--parallel",
        "4",
    ])
    .await;

    let listing = cli.ok(&["ls", "t/files/tree"]).await;
    for name in ["a/", "ünïcødé/", "with space.txt", "empty"] {
        assert!(listing.contains(name), "{name} not in:\n{listing}");
    }
    let all = cli.ok(&["ls", "-r", "t/files"]).await;
    assert!(
        all.contains("tree/a/b/deep.bin") && all.contains("big.bin"),
        "{all}"
    );
    let buckets = cli.ok(&["ls", "t"]).await;
    assert!(buckets.contains("files/"), "{buckets}");

    // Back again: the same files, byte for byte.
    cli.ok(&["cp", "-r", "t/files/tree", "back"]).await;
    assert_eq!(read_tree(&cli.path("back")), read_tree(&cli.path("tree")));
    // A large object comes down in ranges at once, and keeps its time.
    cli.ok(&["cp", "t/files/big.bin", "big.back", "--part-size", "5MiB"])
        .await;
    assert_eq!(fs::read(cli.path("big.back")).unwrap(), big);
    let head = client(&server, SECRET_KEY)
        .head_object()
        .bucket("files")
        .key("big.bin")
        .send()
        .await
        .unwrap();
    let modified = fs::metadata(cli.path("big.back"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(
        modified,
        std::time::SystemTime::try_from(*head.last_modified().unwrap()).unwrap()
    );
    // No partial files are left behind.
    assert!(
        fs::read_dir(cli.work.path()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("partial"))
    );

    let cat = cli
        .ok(&["cat", "t/files/tree/ünïcødé/naïve café.txt"])
        .await;
    assert_eq!(cat, "café");
    let stat = cli.ok(&["stat", "t/files/tree/with space.txt"]).await;
    assert!(
        stat.contains("6 bytes") && stat.contains("text/plain"),
        "{stat}"
    );

    // Folders need -r, and local-to-local isn't a thing.
    let err = cli.fails(&["cp", "tree", "t/files/x"], 2).await;
    assert!(err.contains("add -r"), "{err}");
    let err = cli.fails(&["cp", "t/files/tree", "x"], 5).await;
    assert!(err.contains("teifs cp -r t/files/tree/"), "{err}");
    cli.fails(&["cp", "big.bin", "other.bin"], 2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn copies_between_objects_by_the_server_or_through_the_client() {
    let server = start().await;
    let cli = Client::new(&server);
    let big = data(12 * MIB, 3);
    fs::write(cli.path("big.bin"), &big).unwrap();
    fs::write(cli.path("page.html"), "<p>hi</p>").unwrap();
    cli.ok(&["mb", "t/one"]).await;
    cli.ok(&["mb", "t/two"]).await;
    cli.ok(&["cp", "big.bin", "page.html", "t/one/"]).await;

    // Same endpoint: CopyObject.
    cli.ok(&["cp", "t/one/big.bin", "t/two/copy.bin"]).await;
    // Another endpoint (by name): ranged reads sent on as parts, keeping the type.
    cli.ok(&[
        "cp",
        "t/one/big.bin",
        "u/two/streamed.bin",
        "--part-size",
        "5MiB",
    ])
    .await;
    cli.ok(&["cp", "t/one/page.html", "u/two/page.html"]).await;
    for key in ["copy.bin", "streamed.bin"] {
        cli.ok(&["cp", &format!("t/two/{key}"), key]).await;
        assert_eq!(fs::read(cli.path(key)).unwrap(), big, "{key}");
    }
    let stat = cli.ok(&["stat", "t/two/page.html"]).await;
    assert!(stat.contains("text/html"), "{stat}");
    // Recursively between endpoints.
    cli.ok(&["cp", "-r", "t/one", "u/two/all/"]).await;
    let listing = cli.ok(&["ls", "t/two/all"]).await;
    assert!(
        listing.contains("big.bin") && listing.contains("page.html"),
        "{listing}"
    );

    let err = cli
        .fails(&["cp", "t/one/big.bin", "t/one/big.bin"], 2)
        .await;
    assert!(err.contains("same object"), "{err}");
    // mv removes the source once copied.
    cli.ok(&["mv", "t/one/page.html", "t/two/moved.html"]).await;
    cli.fails(&["stat", "t/one/page.html"], 5).await;
    cli.ok(&["mv", "big.bin", "t/two/"]).await;
    assert!(!cli.path("big.bin").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn interrupted_uploads_resume_from_the_parts_already_sent() {
    let server = start().await;
    let cli = Client::new(&server);
    let big = data(16 * MIB, 9);
    fs::write(cli.path("big.bin"), &big).unwrap();
    cli.ok(&["mb", "t/resumed"]).await;
    // An earlier run sent the first part, then stopped.
    let s3 = client(&server, SECRET_KEY);
    let upload = s3
        .create_multipart_upload()
        .bucket("resumed")
        .key("big.bin")
        .checksum_algorithm(ChecksumAlgorithm::Crc32)
        .send()
        .await
        .unwrap();
    let id = upload.upload_id().unwrap();
    s3.upload_part()
        .bucket("resumed")
        .key("big.bin")
        .upload_id(id)
        .part_number(1)
        .checksum_algorithm(ChecksumAlgorithm::Crc32)
        .body(ByteStream::from(big[..5 * MIB].to_vec()))
        .send()
        .await
        .unwrap();
    // And a part that doesn't match the file is sent again.
    s3.upload_part()
        .bucket("resumed")
        .key("big.bin")
        .upload_id(id)
        .part_number(2)
        .checksum_algorithm(ChecksumAlgorithm::Crc32)
        .body(ByteStream::from(vec![0; 5 * MIB]))
        .send()
        .await
        .unwrap();

    let run = cli
        .run(&["cp", "big.bin", "t/resumed/big.bin", "--part-size", "5MiB"])
        .await;
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
    assert!(
        run.stderr
            .contains("Resuming the upload of t/resumed/big.bin: 1 of 4 parts"),
        "{}",
        run.stderr
    );
    cli.ok(&["cp", "t/resumed/big.bin", "back.bin"]).await;
    assert_eq!(fs::read(cli.path("back.bin")).unwrap(), big);
    // The upload was completed, not left behind.
    let left = s3
        .list_multipart_uploads()
        .bucket("resumed")
        .send()
        .await
        .unwrap();
    assert!(left.uploads().is_empty());
    // A retried Complete (as after a lost answer) doesn't change what was stored.
    let retried = CompletedMultipartUpload::builder()
        .parts(CompletedPart::builder().part_number(1).build())
        .build();
    let _ = s3
        .complete_multipart_upload()
        .bucket("resumed")
        .key("big.bin")
        .upload_id(id)
        .multipart_upload(retried)
        .send()
        .await;
    cli.ok(&["cp", "t/resumed/big.bin", "again.bin"]).await;
    assert_eq!(fs::read(cli.path("again.bin")).unwrap(), big);
}

#[tokio::test(flavor = "multi_thread")]
async fn mirrors_copy_changes_and_remove_what_is_gone() {
    let server = start().await;
    let cli = Client::new(&server);
    make_tree(&cli.path("tree"));
    cli.ok(&["mb", "t/mirrored"]).await;
    let out = cli.ok(&["mirror", "tree", "t/mirrored/copy"]).await;
    assert!(out.contains("Copied 5 files"), "{out}");
    let out = cli.ok(&["mirror", "tree", "t/mirrored/copy"]).await;
    assert!(out.contains("Nothing to do: already the same"), "{out}");

    // A change, a new file and a deleted one.
    fs::write(cli.path("tree/a/one.txt"), "one, longer now").unwrap();
    fs::write(cli.path("tree/new.txt"), "new").unwrap();
    fs::remove_file(cli.path("tree/empty")).unwrap();
    let out = cli
        .ok(&["mirror", "tree", "t/mirrored/copy", "--remove", "--dry-run"])
        .await;
    for line in [
        "would copy a/one.txt",
        "would copy new.txt",
        "would remove empty",
    ] {
        assert!(out.contains(line), "{line} not in:\n{out}");
    }
    let out = cli.ok(&["mirror", "tree", "t/mirrored/copy"]).await;
    assert!(out.contains("Copied 2 files"), "{out}");
    cli.ok(&["stat", "t/mirrored/copy/empty"]).await;
    let out = cli
        .ok(&["mirror", "tree", "t/mirrored/copy", "--remove"])
        .await;
    assert!(out.contains("Removed 1 file"), "{out}");
    cli.fails(&["stat", "t/mirrored/copy/empty"], 5).await;

    // Down to a new folder, then again: nothing to do, as times were kept.
    cli.ok(&["mirror", "t/mirrored/copy", "down"]).await;
    assert_eq!(read_tree(&cli.path("down")), read_tree(&cli.path("tree")));
    let out = cli.ok(&["mirror", "t/mirrored/copy", "down"]).await;
    assert!(out.contains("Nothing to do: already the same"), "{out}");
    cli.fails(&["mirror", "tree", "down"], 2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn removals_are_exact_and_need_force_to_recurse() {
    let server = start_with(|config| config.default_layout = teifs_store::Layout::Object).await;
    let cli = Client::new(&server);
    let s3 = client(&server, SECRET_KEY);
    cli.ok(&["mb", "t/removals"]).await;
    for key in [
        "photos/a.jpg",
        "photos/b/c.jpg",
        "photos",
        "photos2/keep.jpg",
        "top.txt",
    ] {
        s3.put_object()
            .bucket("removals")
            .key(key)
            .body(ByteStream::from_static(b"x"))
            .send()
            .await
            .unwrap();
    }
    cli.fails(&["rm", "t/removals/nothing"], 5).await;
    let err = cli.fails(&["rm", "-r", "t/removals/photos"], 2).await;
    assert!(err.contains("--force"), "{err}");
    let out = cli.ok(&["rm", "-r", "--force", "t/removals/photos"]).await;
    assert!(out.contains("Removed 3 objects"), "{out}");
    let left = cli.ok(&["ls", "-r", "t/removals"]).await;
    assert!(
        left.contains("photos2/keep.jpg") && left.contains("top.txt"),
        "{left}"
    );
    assert!(!left.contains("photos/"), "{left}");

    let err = cli.fails(&["rb", "t/removals"], 6).await;
    assert!(err.contains("--force"), "{err}");
    cli.fails(&["mb", "t/removals"], 6).await;
    cli.ok(&["mb", "t/removals", "--ignore-existing"]).await;
    cli.ok(&["rb", "t/removals", "--force"]).await;
    cli.fails(&["ls", "t/removals"], 5).await;

    // On TeiFS, --layout makes a folder bucket of plain files.
    cli.ok(&["mb", "t/plain", "--layout", "folder"]).await;
    fs::write(cli.path("f.txt"), "plain").unwrap();
    cli.ok(&["cp", "f.txt", "t/plain/docs/"]).await;
    assert_eq!(
        fs::read_to_string(server.dir.path().join("plain/docs/f.txt")).unwrap(),
        "plain"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn keys_that_would_leave_the_folder_are_not_written() {
    let server = start_with(|config| config.default_layout = teifs_store::Layout::Object).await;
    let cli = Client::new(&server);
    let s3 = client(&server, SECRET_KEY);
    cli.ok(&["mb", "t/evil"]).await;
    s3.put_object()
        .bucket("evil")
        .key("x/fine.txt")
        .body(ByteStream::from_static(b"fine"))
        .send()
        .await
        .unwrap();
    let evil = s3
        .put_object()
        .bucket("evil")
        .key("x/../../escaped.txt")
        .body(ByteStream::from_static(b"evil"))
        .send()
        .await;
    let run = cli.run(&["cp", "-r", "t/evil/x", "out"]).await;
    assert_eq!(
        fs::read_to_string(cli.path("out/fine.txt")).unwrap(),
        "fine"
    );
    assert!(!cli.path("escaped.txt").exists());
    assert!(
        !cli.work
            .path()
            .parent()
            .unwrap()
            .join("escaped.txt")
            .exists()
    );
    if evil.is_ok() {
        assert_ne!(run.code, 0);
        assert!(
            run.stderr.contains("can't be a file name here"),
            "{}",
            run.stderr
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn aliases_keep_secrets_out_of_sight() {
    let server = start().await;
    let cli = Client::new(&server);
    let url = server.endpoint.as_str();
    let secret = format!("{SECRET_KEY}\n");
    let run = cli
        .run_with(
            &[
                "alias",
                "set",
                "home",
                url,
                "--access-key",
                ACCESS_KEY,
                "--secret-key-stdin",
            ],
            &secret,
        )
        .await;
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
    let file = cli.path("aliases.toml");
    let saved = fs::read_to_string(&file).unwrap();
    assert!(saved.contains("[aliases.home]"), "{saved}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let listed = cli.ok(&["alias", "ls"]).await;
    assert!(
        listed.contains("home") && listed.contains(ACCESS_KEY),
        "{listed}"
    );
    assert!(
        listed
            .lines()
            .any(|line| line.starts_with("t ") && line.ends_with("TEIFS_ALIAS_T")),
        "{listed}"
    );
    cli.ok(&["mb", "home/aliased"]).await;

    // Keys that don't work aren't saved, unless asked.
    let wrong = "a-wrong-secret-key\n";
    let args = [
        "alias",
        "set",
        "bad",
        url,
        "--access-key",
        ACCESS_KEY,
        "--secret-key-stdin",
    ];
    let run = cli.run_with(&args, wrong).await;
    assert_eq!(run.code, 4, "{}", run.stderr);
    assert!(run.stderr.contains("--no-check"), "{}", run.stderr);
    let mut unchecked = args.to_vec();
    unchecked.push("--no-check");
    assert_eq!(cli.run_with(&unchecked, wrong).await.code, 0);
    let err = cli.fails(&["ls", "bad"], 4).await;
    assert!(err.contains("secret key"), "{err}");

    // A drive's own keys.
    let drive = tempfile::tempdir().unwrap();
    fs::create_dir(drive.path().join(".teifs")).unwrap();
    fs::write(
        drive.path().join(".teifs/credentials.json"),
        format!(r#"{{"accessKey":"{ACCESS_KEY}","secretKey":"{SECRET_KEY}"}}"#),
    )
    .unwrap();
    // It wins over keys in the environment (a server's shell often has them).
    let mut with_env = Client::new(&server);
    with_env.env[2] = cli.env[2].clone();
    with_env
        .env
        .push(("TEIFS_ACCESS_KEY".to_owned(), "someone-else".to_owned()));
    let drive = drive.path().to_str().unwrap();
    with_env
        .ok(&["alias", "set", "drive", url, "--drive", drive])
        .await;
    cli.ok(&["ls", "drive"]).await;

    // Without a terminal, keys aren't asked for.
    let err = cli
        .fails(&["alias", "set", "x", url, "--access-key", "k"], 2)
        .await;
    assert!(err.contains("--secret-key-stdin"), "{err}");
    cli.fails(&["alias", "set", "Bad.Name", url, "--no-check"], 2)
        .await;
    cli.fails(&["alias", "set", "x", "ftp://h", "--no-check"], 2)
        .await;
    cli.ok(&["alias", "rm", "bad"]).await;
    cli.fails(&["alias", "rm", "bad"], 5).await;
    cli.fails(&["alias", "rm", "t"], 2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn presigned_links_work_without_keys() {
    let server = start().await;
    let cli = Client::new(&server);
    cli.ok(&["mb", "t/share"]).await;
    fs::write(cli.path("note.txt"), "shared").unwrap();
    cli.ok(&["cp", "note.txt", "t/share/"]).await;
    let get = cli
        .ok(&["presign", "t/share/note.txt", "--expires", "10m"])
        .await;
    let body = reqwest::get(get.trim())
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "shared");
    let put = cli.ok(&["presign", "t/share/up.txt", "--put"]).await;
    let status = reqwest::Client::new()
        .put(put.trim())
        .body("uploaded")
        .send()
        .await
        .unwrap()
        .status();
    assert!(status.is_success(), "{status}");
    assert_eq!(cli.ok(&["cat", "t/share/up.txt"]).await, "uploaded");
    cli.fails(&["presign", "t/share/note.txt", "--expires", "8d"], 2)
        .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn failures_have_exit_codes_scripts_can_use() {
    let server = start().await;
    let cli = Client::new(&server);
    cli.fails(&["ls", "t/missing"], 5).await;
    cli.fails(&["cat", "t/missing/key"], 5).await;
    // A copy's one failure is said once.
    fs::write(cli.path("f"), "x").unwrap();
    let err = cli.fails(&["cp", "f", "t/missing/"], 5).await;
    assert_eq!(err.matches("error:").count(), 1, "{err}");
    // `nowhere` isn't an alias, so it's a local path: ls needs a remote.
    let err = cli.fails(&["ls", "nowhere/b"], 2).await;
    assert!(err.contains("teifs alias ls"), "{err}");
    // Nothing listens there.
    let mut offline = Client::new(&server);
    offline.env[0].1 = format!("http://{ACCESS_KEY}:{SECRET_KEY}@127.0.0.1:9");
    let err = offline.fails(&["ls", "t"], 3).await;
    assert!(err.contains("can't be reached"), "{err}");
    // What to do is on a line of its own.
    assert!(
        err.lines()
            .any(|line| line.starts_with("  → ") && line.contains("server is running")),
        "{err}"
    );
}

/// Each line of `--json` output, parsed; each must be an object with a `type`.
fn records(out: &str) -> Vec<serde_json::Value> {
    out.lines()
        .map(|line| {
            let record: serde_json::Value =
                serde_json::from_str(line).unwrap_or_else(|e| panic!("not JSON ({e}): {line}"));
            assert!(record["type"].is_string(), "no type: {line}");
            record
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn json_output_is_one_record_per_line_for_programs() {
    let server = start().await;
    let cli = Client::new(&server);
    make_tree(&cli.path("tree"));

    let made = records(&cli.ok(&["--json", "mb", "t/jsonb"]).await);
    assert_eq!(made.len(), 1);
    let copied = records(&cli.ok(&["--json", "cp", "-r", "tree", "t/jsonb/"]).await);
    let each = copied.iter().filter(|r| r["type"] == "copy").count();
    assert_eq!(each, 5, "{copied:?}");
    let summary = copied.last().unwrap();
    assert_eq!(summary["type"], "summary", "{summary}");
    assert_eq!(summary["copied"], 5, "{summary}");

    let listed = records(&cli.ok(&["--json", "ls", "-r", "t/jsonb"]).await);
    let one = listed
        .iter()
        .find(|r| r["key"] == "a/one.txt")
        .unwrap_or_else(|| panic!("{listed:?}"));
    assert_eq!(one["type"], "object");
    assert_eq!(one["size"], 3);
    assert!(one["modified"].as_str().unwrap().ends_with('Z'), "{one}");

    let stat = records(&cli.ok(&["--json", "stat", "t/jsonb/a/one.txt"]).await);
    assert_eq!(stat.len(), 1);
    assert_eq!(stat[0]["size"], 3);

    // Failures are a record too, with the exit code; the message stays on stderr.
    let run = cli.run(&["--json", "cat", "t/jsonb/missing"]).await;
    assert_eq!(run.code, 5);
    let error = records(&run.stdout);
    assert_eq!(error.len(), 1, "{}", run.stdout);
    assert_eq!(error[0]["type"], "error");
    assert_eq!(error[0]["kind"], "not_found");
    assert_eq!(error[0]["exitCode"], 5);
    assert!(run.stderr.starts_with("error: "), "{}", run.stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_output_is_stable_for_scripts() {
    let server = start().await;
    let cli = Client::new(&server);
    fs::write(cli.path("note.txt"), "hello").unwrap();

    // Without a terminal: no colors, no progress bars, results on stdout.
    let run = cli.run(&["mb", "t/plain"]).await;
    assert_eq!(
        (run.stdout.as_str(), run.stderr.as_str()),
        ("✓ Created t/plain\n", "")
    );
    let run = cli.run(&["cp", "note.txt", "t/plain/"]).await;
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(lines[0], "✓ note.txt → t/plain/note.txt", "{}", run.stdout);
    assert!(
        lines[1].starts_with("✓ Copied 1 file, 5 B in "),
        "{}",
        run.stdout
    );
    assert_eq!(
        (lines.len(), run.stderr.as_str()),
        (2, ""),
        "{}",
        run.stdout
    );
    assert!(!run.stdout.contains('\u{1b}') && !run.stderr.contains('\u{1b}'));
    // `--color always` colors them.
    let colored = cli.ok(&["--color", "always", "ls", "t/plain"]).await;
    assert!(colored.contains('\u{1b}'), "{colored:?}");
    // `--quiet` leaves only results.
    assert_eq!(
        cli.ok(&["-q", "cp", "note.txt", "t/plain/again.txt"]).await,
        ""
    );
    assert_eq!(cli.ok(&["-q", "cat", "t/plain/again.txt"]).await, "hello");

    // Questions can't be asked without a terminal: say how to answer instead.
    let err = cli.fails(&["rm", "-r", "t/plain/"], 2).await;
    assert!(err.contains("--force"), "{err}");
    assert!(cli.ok(&["ls", "t/plain"]).await.contains("note.txt"));
    // `--yes` answers.
    cli.ok(&["--yes", "rm", "-r", "t/plain/"]).await;
    assert!(!cli.ok(&["ls", "t/plain"]).await.contains("note.txt"));
}
