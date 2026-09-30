//! `teifs` as an S3 client, through the real binary against a TeiFS server: aliases,
//! copies both ways and between endpoints, resumed uploads, mirrors, removals, and the
//! exit codes scripts rely on.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

#[path = "../../../crates/server/tests/common/mod.rs"]
mod common;
mod harness;

use std::{fs, path::Path};

use aws_sdk_s3::{
    primitives::ByteStream,
    types::{ChecksumAlgorithm, CompletedMultipartUpload, CompletedPart},
};
use common::{ACCESS_KEY, SECRET_KEY, client, start, start_with};
use harness::{Client, records};

const MIB: usize = 1024 * 1024;

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
    // A link can limit what it uploads; the limit only makes sense for uploads.
    let capped = cli
        .ok(&["presign", "t/share/small.txt", "--put", "--max-size", "1K"])
        .await;
    assert!(
        capped.contains("x-teifs-max-content-length=1024"),
        "{capped}"
    );
    let send = |body: Vec<u8>| reqwest::Client::new().put(capped.trim()).body(body).send();
    assert_eq!(send(vec![b'x'; 1025]).await.unwrap().status(), 400);
    assert!(send(vec![b'x'; 1024]).await.unwrap().status().is_success());
    cli.fails(&["presign", "t/share/note.txt", "--max-size", "1K"], 2)
        .await;
    cli.fails(
        &["presign", "t/share/up.txt", "--put", "--max-size", "1T"],
        2,
    )
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

#[tokio::test(flavor = "multi_thread")]
async fn streams_copy_from_standard_input_and_to_standard_output() {
    let server = start().await;
    let cli = Client::new(&server);
    cli.ok(&["mb", "t/streams"]).await;
    // Three 5 MiB parts and a bit, sent two at a time.
    let text = (0..700_000).fold(String::new(), |mut text, i| {
        use std::fmt::Write as _;
        let _ = writeln!(text, "{i:>22}");
        text
    });
    let run = cli
        .run_with(
            &[
                "cp",
                "-",
                "t/streams/big.txt",
                "--part-size",
                "5MiB",
                "--parallel",
                "2",
            ],
            &text,
        )
        .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout
            .starts_with("✓ Copied standard input to t/streams/big.txt")
    );
    let stat = cli.ok(&["stat", "t/streams/big.txt"]).await;
    assert!(stat.contains(&format!("({} bytes)", text.len())), "{stat}");
    assert!(stat.contains("-4\""), "four parts: {stat}");
    // Back out, whole, with nothing but the object on stdout and nothing on stderr.
    let run = cli.run(&["cp", "t/streams/big.txt", "-"]).await;
    assert_eq!((run.code, run.stderr.as_str()), (0, ""));
    assert!(run.stdout == text, "the object came back different");

    // Small and empty inputs are one request.
    cli.run_with(&["cp", "-", "t/streams/small.txt"], "hello")
        .await;
    assert_eq!(cli.ok(&["cat", "t/streams/small.txt"]).await, "hello");
    cli.run_with(&["cp", "-", "t/streams/empty"], "").await;
    assert!(
        cli.ok(&["stat", "t/streams/empty"])
            .await
            .contains("(0 bytes)")
    );

    // A stream needs an object name, one source, and can't be moved.
    for args in [
        &["cp", "-", "t/streams/"][..],
        &["mv", "-", "t/streams/x"],
        &["cp", "-", "-"],
        &["cp", "-", "t/streams/small.txt", "t/streams/y"],
        &["cp", "-r", "-", "t/streams/z"],
    ] {
        cli.fails(args, 2).await;
    }
    // No upload was left behind.
    let uploads = client(&server, SECRET_KEY)
        .list_multipart_uploads()
        .bucket("streams")
        .send()
        .await
        .unwrap();
    assert!(uploads.uploads().is_empty());
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

#[tokio::test(flavor = "multi_thread")]
async fn versions_are_listed_read_copied_and_removed() {
    let server = start().await;
    let cli = Client::new(&server);
    fs::write(cli.path("one.txt"), "one").unwrap();
    fs::write(cli.path("two.txt"), "two!").unwrap();
    for layout in ["object", "folder"] {
        let bucket = format!("t/v-{layout}");
        let at = |key: &str| format!("{bucket}/{key}");
        cli.ok(&["mb", &bucket, "--layout", layout]).await;
        let info = records(&cli.ok(&["--json", "version", "info", &bucket]).await);
        assert_eq!(info[0]["status"], "off");
        cli.ok(&["version", "enable", &bucket]).await;
        let stat = records(&cli.ok(&["--json", "stat", &bucket]).await);
        assert_eq!(stat[0]["versioning"], "enabled", "{layout}");

        cli.ok(&["cp", "one.txt", &at("a.txt")]).await;
        cli.ok(&["cp", "two.txt", &at("a.txt")]).await;
        let listed = records(&cli.ok(&["--json", "ls", "--versions", &bucket]).await);
        assert_eq!(listed.len(), 2, "{layout}: {listed:?}");
        assert!(
            listed
                .iter()
                .all(|r| r["type"] == "version" && r["key"] == "a.txt")
        );
        assert_eq!(
            (listed[0]["latest"].clone(), listed[0]["size"].clone()),
            (true.into(), 4.into())
        );
        let v1 = listed[1]["versionId"].as_str().unwrap().to_owned();
        let v2 = listed[0]["versionId"].as_str().unwrap().to_owned();
        assert_eq!(listed[1]["latest"], false);

        older_versions_are_read_and_copied(&cli, layout, &v1).await;
        // One version of one object: not with mv, several sources, or a local file.
        cli.fails(&["mv", "--version-id", &v1, &at("a.txt"), "x.txt"], 2)
            .await;
        cli.fails(
            &[
                "cp",
                "--version-id",
                &v1,
                &at("a.txt"),
                &at("b.txt"),
                "dir/",
            ],
            2,
        )
        .await;
        cli.fails(&["cp", "--version-id", &v1, "one.txt", &at("c.txt")], 2)
            .await;

        // A delete keeps the versions and adds a marker, shown as deleted and current.
        cli.ok(&["rm", &at("a.txt")]).await;
        let plain = cli.ok(&["ls", "--versions", &at("a.txt")]).await;
        assert!(
            plain.contains("deleted") && plain.contains("(current)"),
            "{plain}"
        );
        // The marker is listed first, even made in the same second as the versions.
        let listed = records(&cli.ok(&["--json", "ls", "--versions", &at("a.txt")]).await);
        assert_eq!(listed[0]["type"], "deleteMarker", "{listed:?}");
        assert_eq!(listed[0]["latest"], true);
        cli.fails(&["cat", &at("a.txt")], 5).await;

        // Removing one version for good; one that isn't there is an error, not a no-op.
        cli.ok(&["rm", "--version-id", &v2, &at("a.txt")]).await;
        cli.fails(&["rm", "--version-id", &"0".repeat(32), &at("a.txt")], 5)
            .await;
        // All of a key's versions go only when asked for twice, and only that key's.
        cli.ok(&["cp", "one.txt", &at("a.txt2")]).await;
        let err = cli.fails(&["rm", "--versions", &at("a.txt")], 2).await;
        assert!(err.contains("--force"), "{err}");
        let out = cli.ok(&["rm", "--versions", "--force", &at("a.txt")]).await;
        assert!(out.contains("Removed 2 versions"), "{layout}: {out}");
        let left = records(&cli.ok(&["--json", "ls", "--versions", &bucket]).await);
        assert!(left.iter().all(|r| r["key"] != "a.txt"), "{left:?}");
        assert!(left.iter().any(|r| r["key"] == "a.txt2"), "{left:?}");

        cli.ok(&["version", "suspend", &bucket]).await;
        let info = records(&cli.ok(&["--json", "version", "info", &bucket]).await);
        assert_eq!(info[0]["status"], "suspended");
        cli.fails(&["version", "info", &at("b.txt")], 2).await;
        // --force removes a bucket's older versions and markers too.
        cli.ok(&["rm", &at("b.txt")]).await;
        cli.ok(&["rb", "--force", &bucket]).await;
        cli.fails(&["ls", &bucket], 5).await;
    }
}

/// `cat`, `stat` and `cp` of an older version `v1` of `a.txt` (whose bytes are `one`)
/// in the bucket `v-LAYOUT`: down, across, through the client and in ranged parts.
async fn older_versions_are_read_and_copied(cli: &Client, layout: &str, v1: &str) {
    let at = |key: &str| format!("t/v-{layout}/{key}");
    assert_eq!(
        cli.ok(&["cat", "--version-id", v1, &at("a.txt")]).await,
        "one"
    );
    let stat = records(
        &cli.ok(&["--json", "stat", "--version-id", v1, &at("a.txt")])
            .await,
    );
    assert_eq!(stat[0]["versionId"], v1);
    assert_eq!(
        cli.run(&["cp", "--version-id", v1, &at("a.txt"), "-"])
            .await
            .stdout,
        "one"
    );
    cli.ok(&["cp", "--version-id", v1, &at("a.txt"), "old.txt"])
        .await;
    assert_eq!(fs::read_to_string(cli.path("old.txt")).unwrap(), "one");
    cli.ok(&["cp", "--version-id", v1, &at("a.txt"), &at("b.txt")])
        .await;
    assert_eq!(cli.ok(&["cat", &at("b.txt")]).await, "one");
    // Through the client too: across endpoints (`u` is the same server by another
    // name), and in ranged parts.
    let across = format!("u/v-{layout}/c.txt");
    cli.ok(&["cp", "--version-id", v1, &at("a.txt"), &across])
        .await;
    assert_eq!(cli.ok(&["cat", &across]).await, "one");
    fs::write(cli.path("big1"), data(6 * MIB, 1)).unwrap();
    fs::write(cli.path("big2"), data(6 * MIB, 2)).unwrap();
    cli.ok(&["cp", "big1", &at("big")]).await;
    let first = records(&cli.ok(&["--json", "stat", &at("big")]).await);
    let first = first[0]["versionId"].as_str().unwrap().to_owned();
    cli.ok(&["cp", "big2", &at("big")]).await;
    let get = [
        "cp",
        "--version-id",
        &first,
        &at("big"),
        "got",
        "--part-size",
        "5MiB",
    ];
    cli.ok(&get).await;
    assert_eq!(fs::read(cli.path("got")).unwrap(), data(6 * MIB, 1));
    cli.ok(&["rm", "--versions", "--force", &at("big")]).await;
    cli.ok(&["rm", "--versions", "--force", &across]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn objects_are_locked_held_and_released() {
    let server = start().await;
    let cli = Client::new(&server);
    fs::write(cli.path("one.txt"), "one").unwrap();
    for layout in ["object", "folder"] {
        let bucket = format!("t/l-{layout}");
        let at = |key: &str| format!("{bucket}/{key}");
        cli.ok(&["mb", "--with-lock", &bucket, "--layout", layout])
            .await;
        let stat = records(&cli.ok(&["--json", "stat", &bucket]).await);
        assert_eq!(stat[0]["versioning"], "enabled", "{layout}");
        assert_eq!(stat[0]["objectLock"], "on, no default retention");

        default_retention_is_set_shown_and_cleared(&cli, &bucket, layout).await;

        // A governance retention gives way only to --bypass.
        let listed = records(&cli.ok(&["--json", "ls", "--versions", &at("a.txt")]).await);
        let v1 = listed[0]["versionId"].as_str().unwrap().to_owned();
        cli.fails(&["rm", "--version-id", &v1, &at("a.txt")], 4)
            .await;
        cli.fails(&["retention", "clear", &at("a.txt")], 4).await;
        cli.ok(&["rm", "--version-id", &v1, "--bypass", &at("a.txt")])
            .await;
        cli.fails(&["rm", "--bypass", &at("a.txt")], 2).await;

        // Compliance and a legal hold, on every object under a prefix.
        cli.ok(&["cp", "one.txt", &at("docs/b.txt")]).await;
        cli.ok(&["cp", "one.txt", &at("docs/c.txt")]).await;
        let out = cli
            .ok(&["retention", "set", "-r", "compliance", "1d", &at("docs/")])
            .await;
        assert!(
            out.contains("docs/b.txt: COMPLIANCE until") && out.contains("docs/c.txt"),
            "{out}"
        );
        cli.ok(&["legalhold", "set", &at("docs/b.txt")]).await;
        let stat = records(&cli.ok(&["--json", "stat", &at("docs/b.txt")]).await);
        assert_eq!(stat[0]["retention"]["mode"], "COMPLIANCE", "{layout}");
        assert_eq!(stat[0]["legalHold"], "on");
        let info = records(
            &cli.ok(&["--json", "legalhold", "info", &at("docs/c.txt")])
                .await,
        );
        assert_eq!(info[0]["on"], false);
        let err = cli
            .fails(
                &[
                    "rm",
                    "--versions",
                    "-r",
                    "--force",
                    "--bypass",
                    &at("docs/"),
                ],
                1,
            )
            .await;
        assert!(err.contains("can't delete 2 objects"), "{err}");
        cli.ok(&["legalhold", "clear", &at("docs/b.txt")]).await;
        let info = records(
            &cli.ok(&["--json", "legalhold", "info", &at("docs/b.txt")])
                .await,
        );
        assert_eq!(info[0]["on"], false);

        // Every version of a key, governance-locked, goes with --bypass only.
        cli.ok(&["cp", "one.txt", &at("g.txt")]).await;
        cli.ok(&["retention", "set", "governance", "1d", &at("g.txt")])
            .await;
        cli.fails(&["rm", "--versions", "--force", &at("g.txt")], 1)
            .await;
        cli.ok(&["rm", "--versions", "--force", "--bypass", &at("g.txt")])
            .await;

        // Versioning can't be suspended under Object Lock.
        cli.fails(&["version", "suspend", &bucket], 6).await;
    }
    // A bucket without Object Lock can't take a default until versioning is on.
    cli.ok(&["mb", "t/plain-lock"]).await;
    let err = cli
        .fails(
            &[
                "retention",
                "set",
                "--default",
                "compliance",
                "1y",
                "t/plain-lock",
            ],
            6,
        )
        .await;
    assert!(err.contains("version enable"), "{err}");
    cli.fails(
        &["retention", "set", "governance", "0d", "t/plain-lock/a"],
        2,
    )
    .await;
}

async fn default_retention_is_set_shown_and_cleared(cli: &Client, bucket: &str, layout: &str) {
    let at = |key: &str| format!("{bucket}/{key}");
    // A default for new objects, shown and removed again.
    cli.ok(&["retention", "set", "--default", "governance", "30d", bucket])
        .await;
    let info = records(
        &cli.ok(&["--json", "retention", "info", "--default", bucket])
            .await,
    );
    assert_eq!(info[0]["status"], "on, new objects kept GOVERNANCE for 30d");
    cli.ok(&["cp", "one.txt", &at("a.txt")]).await;
    let info = records(&cli.ok(&["--json", "retention", "info", &at("a.txt")]).await);
    assert_eq!(info[0]["mode"], "GOVERNANCE", "{layout}");
    cli.ok(&["retention", "clear", "--default", bucket]).await;
}

/// `teifs ilm rule ACTION BUCKET` and the options in `rest`.
fn ilm<'a>(action: &'a str, bucket: &'a str, rest: &'a str) -> Vec<&'a str> {
    let mut args = vec!["ilm", "rule", action, bucket];
    args.extend(rest.split_whitespace());
    args
}

#[tokio::test(flavor = "multi_thread")]
async fn lifecycle_rules_are_added_changed_exported_and_removed() {
    let server = start().await;
    let cli = Client::new(&server);
    for layout in ["object", "folder"] {
        let bucket = format!("t/ilm-{layout}");
        cli.ok(&["mb", &bucket, "--layout", layout]).await;
        let run = cli.run_with(&ilm("ls", &bucket, ""), "").await;
        assert!(
            run.stdout.is_empty() && run.stderr.contains("no lifecycle rules"),
            "{}",
            run.stderr
        );
        cli.fails(&ilm("export", &bucket, ""), 5).await;
        cli.fails(&ilm("rm", &bucket, "--all --force"), 5).await;

        // Added with and without a name; a rule that does nothing is refused.
        cli.fails(&ilm("add", &bucket, "--prefix a/"), 2).await;
        let logs = "--id logs --prefix logs/ --expire-days 30 --abort-uploads-days 2";
        cli.ok(&ilm("add", &bucket, logs)).await;
        let tagged = "--tags tmp=yes --size-gt 1KiB --noncurrent-expire-days 7 \
                      --noncurrent-expire-newer 3 --disable";
        let added = records(
            &cli.ok(&[&["--json"][..], &ilm("add", &bucket, tagged)].concat())
                .await,
        );
        let made = added[0]["id"].as_str().unwrap().to_owned();
        assert_eq!(made.len(), 20);
        cli.fails(&ilm("add", &bucket, "--id logs --expire-days 1"), 6)
            .await;
        // The server's own checks come through.
        let cold = "--id cold --transition-days 30 --transition-tier GLACIER";
        cli.fails(&ilm("add", &bucket, cold), 1).await;
        cli.fails(&ilm("add", &bucket, "--expire-days 0"), 2).await;
        cli.fails(&ilm("add", &bucket, "--expire-date 2026-02-30"), 2)
            .await;

        let listed = records(
            &cli.ok(&[&["--json"][..], &ilm("ls", &bucket, "")].concat())
                .await,
        );
        assert_eq!(listed.len(), 2, "{layout}");
        assert_eq!(
            listed[0]["rule"],
            serde_json::json!({
                "ID": "logs", "Status": "Enabled", "Filter": {"Prefix": "logs/"},
                "Expiration": {"Days": 30},
                "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 2}
            })
        );
        assert_eq!(
            listed[1]["rule"]["Filter"],
            serde_json::json!({"And": {"Tags": [{"Key": "tmp", "Value": "yes"}], "ObjectSizeGreaterThan": 1024}})
        );
        assert_eq!(listed[1]["rule"]["Status"], "Disabled");
        let table = cli.ok(&ilm("ls", &bucket, "")).await;
        assert!(
            table.contains("logs/*") && table.contains("expire after 30d; abort uploads after 2d"),
            "{table}"
        );

        // Edited: what's given changes, the rest stays.
        let change = format!("--id {made} --enable --prefix tmp/ --expire-date 2030-01-01");
        cli.ok(&ilm("edit", &bucket, &change)).await;
        cli.fails(&ilm("edit", &bucket, "--id nope --enable"), 5)
            .await;
        let exported = cli.ok(&ilm("export", &bucket, "")).await;
        let config: serde_json::Value = serde_json::from_str(&exported).unwrap();
        let edited = &config["Rules"][1];
        assert_eq!(edited["Status"], "Enabled");
        assert_eq!(edited["Filter"]["And"]["Prefix"], "tmp/");
        assert_eq!(edited["Filter"]["And"]["ObjectSizeGreaterThan"], 1024);
        assert_eq!(edited["Expiration"]["Date"], "2030-01-01T00:00:00Z");
        assert_eq!(
            edited["NoncurrentVersionExpiration"]["NewerNoncurrentVersions"],
            3
        );

        rules_are_removed_and_imported_back(&cli, &bucket, &exported).await;
    }
}

async fn rules_are_removed_and_imported_back(cli: &Client, bucket: &str, exported: &str) {
    // Removed one by one, then all, then imported back as they were.
    cli.ok(&ilm("rm", bucket, "--id logs")).await;
    cli.fails(&ilm("rm", bucket, "--id logs"), 5).await;
    cli.fails(&ilm("rm", bucket, ""), 2).await;
    cli.fails(&ilm("rm", bucket, "--all"), 2).await;
    cli.ok(&ilm("rm", bucket, "--all --force")).await;
    cli.fails(&ilm("export", bucket, ""), 5).await;
    let run = cli.run_with(&ilm("import", bucket, ""), exported).await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(cli.ok(&ilm("export", bucket, "")).await, exported);
    let run = cli
        .run_with(&ilm("import", bucket, ""), r#"{"Rules": []}"#)
        .await;
    assert_eq!(run.code, 2, "{}", run.stderr);
    cli.fails(&ilm("ls", &format!("{bucket}/key"), ""), 2).await;
}

#[tokio::test]
async fn buckets_encrypt_by_default_and_objects_move_to_kms_keys() {
    let server = start().await;
    let cli = Client::new(&server);
    fs::write(cli.path("one.txt"), "one").unwrap();
    cli.ok(&["mb", "t/enc", "--layout", "object"]).await;
    // New buckets use SSE-S3; this server takes customer keys.
    let got = encrypt_info(&cli).await;
    assert_eq!(got["algorithm"], "AES256");
    assert_eq!(got["sseCBlocked"], false);
    cli.ok(&["cp", "one.txt", "t/enc/a.txt"]).await;
    let before = records(&cli.ok(&["--json", "stat", "t/enc/a.txt"]).await).remove(0);
    assert_eq!(before["encryption"], "AES256");

    // A KMS key and a Bucket Key for new objects; customer keys refused.
    let out = cli
        .ok(&[
            "encrypt",
            "set",
            "sse-kms",
            "teifs-default",
            "t/enc",
            "--bucket-key",
            "--block-sse-c",
        ])
        .await;
    assert!(
        out.contains("t/enc: SSE-KMS, key teifs-default, bucket key on, SSE-C blocked"),
        "{out}"
    );
    let got = encrypt_info(&cli).await;
    assert_eq!(got["algorithm"], "aws:kms");
    assert_eq!(got["kmsKeyId"], "teifs-default");
    assert_eq!(got["bucketKey"], true);
    assert_eq!(got["sseCBlocked"], true);
    let text = cli.ok(&["encrypt", "info", "t/enc"]).await;
    assert!(
        text.contains("Bucket key:") && text.contains("blocked"),
        "{text}"
    );
    cli.ok(&["cp", "one.txt", "t/enc/docs/b.txt"]).await;
    let b = records(&cli.ok(&["--json", "stat", "t/enc/docs/b.txt"]).await).remove(0);
    assert_eq!(b["encryption"], "aws:kms");
    assert_eq!(b["bucketKey"], true);
    let bucket = records(&cli.ok(&["--json", "stat", "t/enc"]).await).remove(0);
    assert_eq!(
        bucket["encryption"],
        "SSE-KMS, key teifs-default, bucket key on, SSE-C blocked"
    );

    // An SSE-S3 object moves to the key by name, in place.
    let out = cli
        .ok(&[
            "encrypt",
            "update",
            "--kms-key",
            "teifs-default",
            "t/enc/a.txt",
        ])
        .await;
    assert!(
        out.contains("Encryption of t/enc/a.txt: SSE-KMS, key teifs-default"),
        "{out}"
    );
    let after = records(&cli.ok(&["--json", "stat", "t/enc/a.txt"]).await).remove(0);
    assert_eq!(after["encryption"], "aws:kms");
    assert_eq!(after["kmsKeyId"], "teifs-default");
    assert_eq!(after["etag"], before["etag"]);
    assert_eq!(after["modified"], before["modified"]);
    assert_eq!(cli.ok(&["cat", "t/enc/a.txt"]).await, "one");

    // Every object under a prefix, by the key's ARN, with a Bucket Key.
    cli.ok(&["cp", "one.txt", "t/enc/docs/c.txt"]).await;
    let arn = "arn:aws:kms:us-east-1:000000000000:key/teifs-default";
    let out = cli
        .ok(&[
            "encrypt",
            "update",
            "-r",
            "--kms-key",
            arn,
            "--bucket-key",
            "t/enc/docs/",
        ])
        .await;
    assert!(
        out.contains("docs/b.txt") && out.contains("docs/c.txt"),
        "{out}"
    );
    let c = records(&cli.ok(&["--json", "stat", "t/enc/docs/c.txt"]).await).remove(0);
    assert_eq!(c["bucketKey"], true);

    encryption_mistakes_are_refused(&cli).await;

    encryption_is_cleared_and_customer_keys_switched(&cli).await;
}

async fn encryption_is_cleared_and_customer_keys_switched(cli: &Client) {
    // Two layers (DSSE-KMS), by default and by prefix; resumable uploads check SHA-256.
    let out = cli
        .ok(&["encrypt", "set", "dsse-kms", "teifs-default", "t/enc"])
        .await;
    assert!(out.contains("t/enc: DSSE-KMS, key teifs-default"), "{out}");
    assert_eq!(encrypt_info(cli).await["algorithm"], "aws:kms:dsse");
    cli.ok(&["cp", "one.txt", "t/enc/dual.txt"]).await;
    let dual = records(&cli.ok(&["--json", "stat", "t/enc/dual.txt"]).await).remove(0);
    assert_eq!(
        (&dual["encryption"], &dual["kmsKeyId"]),
        (&"aws:kms:dsse".into(), &"teifs-default".into())
    );
    cli.ok(&["encrypt", "set", "sse-s3", "t/enc"]).await;
    cli.ok(&[
        "cp",
        "--enc-dsse",
        "t/enc/two/=teifs-default",
        "one.txt",
        "t/enc/two/one.txt",
    ])
    .await;
    let two = records(&cli.ok(&["--json", "stat", "t/enc/two/one.txt"]).await).remove(0);
    assert_eq!(two["encryption"], "aws:kms:dsse");
    assert_eq!(cli.ok(&["cat", "t/enc/two/one.txt"]).await, "one");
    let err = cli
        .fails(
            &["encrypt", "set", "dsse-kms", "k", "t/enc", "--bucket-key"],
            2,
        )
        .await;
    assert!(err.contains("DSSE-KMS"), "{err}");

    // Back to the default.
    let out = cli.ok(&["encrypt", "clear", "t/enc"]).await;
    assert!(out.contains("SSE-S3, the default"), "{out}");
    let got = encrypt_info(cli).await;
    assert_eq!(got["algorithm"], "AES256");
    assert_eq!(got["bucketKey"], false);
    assert_eq!(got["sseCBlocked"], false);
    cli.ok(&["encrypt", "set", "sse-s3", "t/enc", "--block-sse-c"])
        .await;
    assert_eq!(encrypt_info(cli).await["sseCBlocked"], true);
    cli.ok(&["encrypt", "set", "sse-s3", "t/enc"]).await;
    assert_eq!(encrypt_info(cli).await["sseCBlocked"], true);
    cli.ok(&["encrypt", "set", "sse-s3", "t/enc", "--allow-sse-c"])
        .await;
    assert_eq!(encrypt_info(cli).await["sseCBlocked"], false);

    // A folder bucket stores plain files.
    cli.ok(&["mb", "t/plain", "--layout", "folder"]).await;
    let text = cli.ok(&["encrypt", "info", "t/plain"]).await;
    assert!(text.contains("none"), "{text}");
    let bucket = records(&cli.ok(&["--json", "stat", "t/plain"]).await).remove(0);
    assert_eq!(bucket["encryption"], serde_json::Value::Null);
}

/// `teifs encrypt info t/enc`'s record.
async fn encrypt_info(cli: &Client) -> serde_json::Value {
    records(&cli.ok(&["--json", "encrypt", "info", "t/enc"]).await).remove(0)
}

async fn encryption_mistakes_are_refused(cli: &Client) {
    let err = cli.fails(&["encrypt", "set", "sse-kms", "t/enc"], 2).await;
    assert!(err.contains("sse-kms KEY ALIAS/BUCKET"), "{err}");
    cli.fails(&["encrypt", "set", "sse-s3", "k", "t/enc"], 2)
        .await;
    cli.fails(&["encrypt", "set", "sse-s3", "--bucket-key", "t/enc"], 2)
        .await;
    cli.fails(
        &[
            "encrypt",
            "set",
            "sse-s3",
            "--block-sse-c",
            "--allow-sse-c",
            "t/enc",
        ],
        2,
    )
    .await;
    let err = cli
        .fails(&["encrypt", "update", "--kms-key", "k", "t/enc"], 2)
        .await;
    assert!(err.contains("give a key"), "{err}");
    let err = cli
        .fails(
            &["encrypt", "update", "--kms-key", "nope", "t/enc/a.txt"],
            1,
        )
        .await;
    assert!(
        err.contains("can't change the encryption of t/enc/a.txt"),
        "{err}"
    );
    cli.fails(
        &[
            "encrypt",
            "update",
            "--kms-key",
            "teifs-default",
            "t/enc/none",
        ],
        5,
    )
    .await;
}

#[tokio::test]
async fn transfers_encrypt_by_prefix_and_read_with_customer_keys() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let server = start().await;
    let cli = Client::new(&server);
    let big = data(12 * MIB, 3);
    fs::write(cli.path("big.bin"), &big).unwrap();
    fs::write(cli.path("one.txt"), "one").unwrap();
    fs::write(cli.path("key"), [5_u8; 32]).unwrap();
    cli.ok(&["mb", "t/sec", "--layout", "object"]).await;
    let small = ["--part-size", "5MiB"];
    let c = ["--enc-c", "t/sec/c/=key"];
    // Uploads in one request and in parts, read back only with the key.
    cli.ok(&[
        &["cp"],
        &c[..],
        &["one.txt", "big.bin", "t/sec/c/"],
        &small[..],
    ]
    .concat())
        .await;
    let got = sse_stat(&cli, "t/sec/c/big.bin", true).await;
    assert_eq!(got["customerKeyMd5"], STANDARD.encode(md5_of(&[5; 32])));
    cli.fails(&["stat", "t/sec/c/one.txt"], 1).await;
    cli.fails(&["cat", "t/sec/c/one.txt"], 1).await;
    assert_eq!(
        cli.ok(&[&["cat"], &c[..], &["t/sec/c/one.txt"]].concat())
            .await,
        "one"
    );
    cli.ok(&[
        &["cp"],
        &c[..],
        &["t/sec/c/big.bin", "back.bin"],
        &small[..],
    ]
    .concat())
        .await;
    assert_eq!(fs::read(cli.path("back.bin")).unwrap(), big);

    // Copies by the server and through the client, from a customer key to SSE-KMS and
    // SSE-S3.
    let kms = [
        "--enc-kms",
        "t/sec/k/=teifs-default",
        "--enc-kms",
        "u/sec/k/=teifs-default",
    ];
    cli.ok(&[
        &["cp"],
        &c[..],
        &kms[..],
        &["t/sec/c/big.bin", "t/sec/k/by-server.bin"],
    ]
    .concat())
        .await;
    cli.ok(&[
        &["cp"],
        &c[..],
        &kms[..],
        &["t/sec/c/big.bin", "u/sec/k/by-client.bin"],
        &small[..],
    ]
    .concat())
        .await;
    for at in ["t/sec/k/by-server.bin", "t/sec/k/by-client.bin"] {
        let got = sse_stat(&cli, at, false).await;
        assert_eq!(got["encryption"], "aws:kms", "{at}");
        assert_eq!(got["kmsKeyId"], "teifs-default", "{at}");
    }
    for at in ["t/sec/k/by-server.bin", "t/sec/k/by-client.bin"] {
        cli.ok(&["cp", at, "copied.bin"]).await;
        assert_eq!(fs::read(cli.path("copied.bin")).unwrap(), big, "{at}");
    }
    cli.ok(&["encrypt", "set", "sse-kms", "teifs-default", "t/sec"])
        .await;
    cli.ok(&["cp", "--enc-s3", "t/sec/s3", "one.txt", "t/sec/s3/one.txt"])
        .await;
    assert_eq!(
        sse_stat(&cli, "t/sec/s3/one.txt", false).await["encryption"],
        "AES256"
    );

    customer_keys_come_from_the_environment_never_the_command_line(cli).await;
}

async fn customer_keys_come_from_the_environment_never_the_command_line(mut cli: Client) {
    use base64::{Engine, engine::general_purpose::STANDARD};
    // Standard input, and a key from TEIFS_ENC_C (padded base64) for a mirror.
    let key = STANDARD.encode([6_u8; 32]);
    let env = format!("t/sec/m/={key},t/sec/c/={}", STANDARD.encode([5_u8; 32]));
    cli.env.push(("TEIFS_ENC_C".to_owned(), env));
    let run = cli
        .run_with(&["cp", "-", "t/sec/m/in.txt"], "streamed")
        .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(cli.ok(&["cat", "t/sec/m/in.txt"]).await, "streamed");
    cli.ok(&["mirror", "t/sec/c/", "t/sec/m/c/"]).await;
    assert_eq!(cli.ok(&["cat", "t/sec/m/c/one.txt"]).await, "one");
    assert!(!sse_stat(&cli, "t/sec/m/c/one.txt", false).await["customerKeyMd5"].is_null());

    // Keys never come from the command line, and prefixes must name an alias.
    let err = cli
        .fails(
            &[
                "cp",
                "--enc-c",
                &format!("t/sec/={key}"),
                "one.txt",
                "t/sec/x",
            ],
            2,
        )
        .await;
    assert!(
        !err.contains(&key) && err.contains("never the key itself"),
        "{err}"
    );
    cli.fails(&["cp", "--enc-s3", "nope/sec", "one.txt", "t/sec/x"], 2)
        .await;
}

/// `teifs stat`'s record of `at`, with the key for `t/sec/c/` if `key`.
async fn sse_stat(cli: &Client, at: &str, key: bool) -> serde_json::Value {
    let mut args = vec!["--json", "stat", at];
    if key {
        args.extend(["--enc-c", "t/sec/c/=key"]);
    }
    records(&cli.ok(&args).await).remove(0)
}

fn md5_of(bytes: &[u8]) -> Vec<u8> {
    use md5::Digest;
    md5::Md5::digest(bytes).to_vec()
}

#[tokio::test]
async fn uploads_with_customer_keys_resume() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let server = start().await;
    let cli = Client::new(&server);
    let big = data(12 * MIB, 4);
    fs::write(cli.path("big.bin"), &big).unwrap();
    fs::write(cli.path("key"), [8_u8; 32]).unwrap();
    cli.ok(&["mb", "t/sres", "--layout", "object"]).await;
    let (key, md5) = (
        STANDARD.encode([8_u8; 32]),
        STANDARD.encode(md5_of(&[8; 32])),
    );
    // An earlier run sent the first two parts, then stopped.
    let s3 = client(&server, SECRET_KEY);
    let upload = s3
        .create_multipart_upload()
        .bucket("sres")
        .key("big.bin")
        .checksum_algorithm(ChecksumAlgorithm::Sha256)
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&key)
        .sse_customer_key_md5(&md5)
        .send()
        .await
        .unwrap();
    s3.upload_part()
        .bucket("sres")
        .key("big.bin")
        .upload_id(upload.upload_id().unwrap())
        .part_number(1)
        .checksum_algorithm(ChecksumAlgorithm::Sha256)
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&key)
        .sse_customer_key_md5(&md5)
        .body(ByteStream::from(big[..5 * MIB].to_vec()))
        .send()
        .await
        .unwrap();
    // A part of the same size with other bytes is sent again.
    s3.upload_part()
        .bucket("sres")
        .key("big.bin")
        .upload_id(upload.upload_id().unwrap())
        .part_number(2)
        .checksum_algorithm(ChecksumAlgorithm::Sha256)
        .sse_customer_algorithm("AES256")
        .sse_customer_key(&key)
        .sse_customer_key_md5(&md5)
        .body(ByteStream::from(vec![0; 5 * MIB]))
        .send()
        .await
        .unwrap();
    let run = cli
        .run(&[
            "cp",
            "--enc-c",
            "t/sres=key",
            "big.bin",
            "t/sres/big.bin",
            "--part-size",
            "5MiB",
        ])
        .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stderr.contains("1 of 3 parts are already there"),
        "{}",
        run.stderr
    );
    cli.ok(&["cp", "--enc-c", "t/sres=key", "t/sres/big.bin", "back.bin"])
        .await;
    assert_eq!(fs::read(cli.path("back.bin")).unwrap(), big);
}

/// `teifs event ACTION BUCKET` and the options in `rest`.
fn event<'a>(action: &'a str, bucket: &'a str, rest: &'a str) -> Vec<&'a str> {
    let mut args = vec!["--json", "event", action, bucket];
    args.extend(rest.split_whitespace());
    args
}

#[tokio::test(flavor = "multi_thread")]
async fn notification_rules_are_added_listed_and_removed() {
    use teifs_server::{TargetConfig, TargetKind, Webhook};
    let receiver = teifs_notify::testing::Receiver::start(0).await;
    let hook = Webhook::new(receiver.url(), None).unwrap();
    let target = TargetConfig::new("hook", TargetKind::Webhook(hook)).unwrap();
    let server = start_with(|config| config.notify = vec![target]).await;
    let cli = Client::new(&server);
    let arn = "arn:teifs:sqs::hook:webhook";
    cli.ok(&["mb", "t/events"]).await;
    let run = cli.run(&["event", "ls", "t/events"]).await;
    assert!(
        run.stderr.contains("no notification rules"),
        "{}",
        run.stderr
    );

    let logs = format!("{arn} --id logs --event put,delete --prefix logs/");
    let added = records(&cli.ok(&event("add", "t/events", &logs)).await);
    assert_eq!(added[0]["id"], "logs");
    assert_eq!(
        added[0]["events"],
        serde_json::json!(["s3:ObjectCreated:*", "s3:ObjectRemoved:*"])
    );
    assert_eq!(receiver.posts(1).await.len(), 1, "the target was tested");
    // The same rule again, under another id or none.
    cli.fails(
        &event(
            "add",
            "t/events",
            &format!("{arn} --event delete,put --prefix logs/"),
        ),
        6,
    )
    .await;
    let again = format!("{arn} --event put,delete --prefix logs/ --ignore-existing");
    assert_eq!(
        records(&cli.ok(&event("add", "t/events", &again)).await)[0]["id"],
        "logs"
    );
    cli.fails(
        &event("add", "t/events", &format!("{arn} --id logs --suffix .x")),
        6,
    )
    .await;
    // The server's checks come through: an overlapping rule, an unknown target.
    cli.fails(
        &event(
            "add",
            "t/events",
            &format!("{arn} --event put --prefix logs/a"),
        ),
        1,
    )
    .await;
    cli.fails(&event("add", "t/events", "arn:teifs:sqs::nope:webhook"), 1)
        .await;

    let images = format!("{arn} --event get --suffix .jpg");
    let made = records(&cli.ok(&event("add", "t/events", &images)).await);
    let made = made[0]["id"].as_str().unwrap().to_owned();
    assert_eq!(made.len(), 32, "made up by the server");
    let listed = records(&cli.ok(&event("ls", "t/events", "")).await);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[1]["suffix"], ".jpg");
    assert_eq!(
        listed[1]["events"],
        serde_json::json!(["s3:ObjectAccessed:*"])
    );
    let table = cli.ok(&["event", "ls", "t/events", arn]).await;
    assert!(
        table.contains("logs/*") && table.contains("*.jpg"),
        "{table}"
    );
    assert!(
        records(
            &cli.ok(&event("ls", "t/events", "arn:teifs:sqs::other:webhook"))
                .await
        )
        .is_empty()
    );

    cli.fails(&event("rm", "t/events", "--id nope"), 5).await;
    let removed = records(&cli.ok(&event("rm", "t/events", "--id logs")).await);
    assert_eq!(removed[0]["removed"], 1);
    let removed = records(&cli.ok(&event("rm", "t/events", arn)).await);
    assert_eq!(removed[0]["removed"], 1);
    cli.fails(&event("rm", "t/events", "--all --force"), 5)
        .await;
    cli.fails(&["event", "rm", "t/events"], 2).await;
    cli.fails(&["event", "ls", "t/events/key"], 2).await;
}

/// `teifs event` with AWS's destinations: a topic's or function's ARN makes the rule S3
/// is given for it, and EventBridge is turned on and off without touching the rules
/// (nor they it).
#[tokio::test(flavor = "multi_thread")]
async fn event_rules_name_aws_destinations_and_eventbridge() {
    use teifs_notify::testing::AwsServer;
    use teifs_server::{AwsCredentials, EventBridge, Lambda, Sns, TargetConfig, TargetKind};
    let aws = AwsServer::start("eu-west-1", "AKIDTEIFS", "s3cret").await;
    let keys = || {
        Some(AwsCredentials {
            access_key: "AKIDTEIFS".into(),
            secret: "s3cret".to_owned().into(),
            session_token: None,
        })
    };
    let topic = "arn:aws:sns:eu-west-1:123456789012:uploads";
    let mut sns = Sns::new(topic, Some(aws.url())).unwrap();
    sns.credentials = keys();
    let mut bus = EventBridge::new(
        "arn:aws:events:eu-west-1:123456789012:event-bus/default",
        Some(aws.url()),
        None,
    )
    .unwrap();
    bus.credentials = keys();
    let function = "arn:aws:lambda:eu-west-1:123456789012:function:thumbs";
    let mut lambda = Lambda::new(function, Some(aws.url())).unwrap();
    lambda.credentials = keys();
    let targets = vec![
        TargetConfig::new("thumbs", TargetKind::Lambda(lambda)).unwrap(),
        TargetConfig::new("uploads", TargetKind::Sns(sns)).unwrap(),
        TargetConfig::new("bus", TargetKind::EventBridge(bus)).unwrap(),
    ];
    let server = start_with(|config| config.notify = targets).await;
    let cli = Client::new(&server);
    let s3 = client(&server, SECRET_KEY);
    cli.ok(&["mb", "t/aws"]).await;

    let on = records(&cli.ok(&event("eventbridge", "t/aws", "on")).await);
    assert_eq!(on[0]["enabled"], true);
    cli.ok(&event(
        "add",
        "t/aws",
        &format!("{function} --event delete"),
    ))
    .await;
    // The server lists topics before functions: the rule added is the one shown.
    let added = records(
        &cli.ok(&event("add", "t/aws", &format!("{topic} --event put")))
            .await,
    );
    assert_eq!(added[0]["arn"], topic);
    let read = s3
        .get_bucket_notification_configuration()
        .bucket("aws")
        .send()
        .await
        .unwrap();
    assert_eq!(
        read.topic_configurations()[0].topic_arn(),
        topic,
        "a topic's rule"
    );
    assert_eq!(
        read.lambda_function_configurations()[0].lambda_function_arn(),
        function,
        "a function's rule"
    );
    assert!(read.queue_configurations().is_empty());
    assert!(read.event_bridge_configuration().is_some(), "kept by add");
    let listed = records(&cli.ok(&event("ls", "t/aws", "")).await);
    assert_eq!(listed[0]["type"], "eventBridge");
    assert_eq!(listed[1]["arn"], topic);
    assert_eq!(listed[2]["arn"], function);

    cli.ok(&event("rm", "t/aws", topic)).await;
    let read = s3
        .get_bucket_notification_configuration()
        .bucket("aws")
        .send()
        .await
        .unwrap();
    assert!(read.event_bridge_configuration().is_some(), "kept by rm");
    cli.ok(&event("add", "t/aws", &format!("{topic} --event put")))
        .await;
    let off = records(&cli.ok(&event("eventbridge", "t/aws", "off")).await);
    assert_eq!(off[0]["enabled"], false);
    let read = s3
        .get_bucket_notification_configuration()
        .bucket("aws")
        .send()
        .await
        .unwrap();
    assert!(read.event_bridge_configuration().is_none());
    assert_eq!(read.topic_configurations().len(), 1, "rules kept");
    cli.fails(&event("eventbridge", "t/aws", "maybe"), 2).await;
}
