//! The SFTP gateway, end to end: a real SSH and SFTP client (russh, russh-sftp) against a
//! server, and what it did checked over S3.

#![allow(
    clippy::unwrap_used,
    reason = "test helpers fail the test on any error"
)]

#[macro_use]
mod common;

use std::{net::SocketAddr, sync::Arc};

use aws_sdk_s3::primitives::ByteStream;
use common::{ACCESS_KEY, SECRET_KEY, Server};
use russh::keys::PublicKeyOrCertificate;
use russh_sftp::{
    client::{SftpSession, error::Error as SftpError},
    protocol::{OpenFlags, StatusCode},
};
use teifs_server::SftpConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The smallest part S3 takes: uploads bigger than it go in parts.
const PART: usize = 5 * 1024 * 1024;

struct Trusting;

impl russh::client::Handler for Trusting {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        _: &PublicKeyOrCertificate,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        std::future::ready(Ok(true))
    }
}

/// A server with the SFTP gateway on a free port, its host key in the keys folder.
async fn start() -> Server {
    start_in(teifs_store::Layout::Folder).await
}

/// [`start`], with new buckets made in `layout`.
async fn start_in(layout: teifs_store::Layout) -> Server {
    common::start_with(|config| {
        config.default_layout = layout;
        let key = config
            .kms_keyring
            .as_ref()
            .unwrap()
            .with_file_name("ssh_host_ed25519");
        let mut sftp = SftpConfig::new("127.0.0.1:0".parse().unwrap(), Some(key));
        sftp.part_size = PART;
        config.gateways.sftp = Some(sftp);
    })
    .await
}

/// Signs in over SSH with a password; the SFTP session, or why it couldn't.
async fn connect(at: SocketAddr, user: &str, password: &str) -> Result<SftpSession, String> {
    let config = Arc::new(russh::client::Config::default());
    let mut ssh = russh::client::connect(config, at, Trusting)
        .await
        .map_err(|e| e.to_string())?;
    let signed_in = ssh
        .authenticate_password(user, password)
        .await
        .map_err(|e| e.to_string())?;
    if !signed_in.success() {
        return Err("refused".into());
    }
    let channel = ssh
        .channel_open_session()
        .await
        .map_err(|e| e.to_string())?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| e.to_string())?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| e.to_string())?;
    // The SSH connection lives as long as the test.
    std::mem::forget(ssh);
    Ok(sftp)
}

fn status<T>(result: Result<T, SftpError>) -> StatusCode {
    match result {
        Err(SftpError::Status(status)) => status.status_code,
        Err(other) => panic!("expected a status, got {other}"),
        Ok(_) => panic!("expected a status, got success"),
    }
}

async fn names(sftp: &SftpSession, path: &str) -> Vec<String> {
    let mut names: Vec<String> = sftp
        .read_dir(path)
        .await
        .unwrap()
        .map(|entry| entry.file_name())
        .collect();
    names.sort();
    names
}

in_both_layouts!(files_and_folders_are_buckets_and_objects);

#[expect(
    clippy::too_many_lines,
    reason = "one walk through every file operation"
)]
async fn files_and_folders_are_buckets_and_objects(layout: teifs_store::Layout) {
    let server = start_in(layout).await;
    let s3 = common::client(&server, SECRET_KEY);
    let sftp = connect(server.sftp.unwrap(), ACCESS_KEY, SECRET_KEY)
        .await
        .unwrap();

    // `/` is the buckets; a folder made there is a bucket.
    assert_eq!(sftp.canonicalize(".").await.unwrap(), "/");
    sftp.create_dir("/photos").await.unwrap();
    s3.head_bucket().bucket("photos").send().await.unwrap();
    assert_eq!(names(&sftp, "/").await, ["photos"]);
    assert_eq!(status(sftp.create("/top.txt").await), StatusCode::Failure);

    // A file written is an object; a folder in a bucket is its keys' prefix.
    sftp.create_dir("/photos/2026").await.unwrap();
    let mut file = sftp.create("/photos/2026/a b.txt").await.unwrap();
    file.write_all(b"hello over sftp").await.unwrap();
    file.shutdown().await.unwrap();
    drop(file);
    let got = s3
        .get_object()
        .bucket("photos")
        .key("2026/a b.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(got.content_type(), Some("text/plain"));
    assert_eq!(
        got.body.collect().await.unwrap().into_bytes().as_ref(),
        b"hello over sftp"
    );
    s3.put_object()
        .bucket("photos")
        .key("2026/deep/x.bin")
        .body(ByteStream::from_static(b"xyz"))
        .send()
        .await
        .unwrap();
    assert_eq!(names(&sftp, "/photos").await, ["2026"]);
    assert_eq!(names(&sftp, "/photos/2026").await, ["a b.txt", "deep"]);
    let meta = sftp.metadata("/photos/2026/a b.txt").await.unwrap();
    assert_eq!(meta.size, Some(15));
    assert!(meta.is_regular());
    assert!(sftp.metadata("/photos/2026/deep").await.unwrap().is_dir());
    assert_eq!(
        status(sftp.metadata("/photos/nope").await),
        StatusCode::NoSuchFile
    );

    // Reading, from the start and from the middle.
    assert_eq!(
        sftp.read("/photos/2026/a b.txt").await.unwrap(),
        b"hello over sftp"
    );
    let mut file = sftp.open("/photos/2026/a b.txt").await.unwrap();
    tokio::io::AsyncSeekExt::seek(&mut file, std::io::SeekFrom::Start(6))
        .await
        .unwrap();
    let mut rest = String::new();
    file.read_to_string(&mut rest).await.unwrap();
    assert_eq!(rest, "over sftp");
    drop(file);

    // Setting times or modes is taken and ignored.
    let mut attrs = russh_sftp::protocol::FileAttributes::empty();
    attrs.mtime = Some(1);
    sftp.set_metadata("/photos/2026/a b.txt", attrs)
        .await
        .unwrap();

    // Renames: a file to a free name; not over another, not of folders.
    sftp.rename("/photos/2026/a b.txt", "/photos/2026/renamed.txt")
        .await
        .unwrap();
    assert_eq!(names(&sftp, "/photos/2026").await, ["deep", "renamed.txt"]);
    assert_eq!(
        status(
            sftp.rename("/photos/2026/renamed.txt", "/photos/2026/deep/x.bin")
                .await
        ),
        StatusCode::Failure
    );
    assert_eq!(
        status(sftp.rename("/photos/2026/deep", "/photos/elsewhere").await),
        StatusCode::OpUnsupported
    );

    // Changing a file in place isn't possible over S3.
    assert_eq!(
        status(
            sftp.open_with_flags(
                "/photos/2026/renamed.txt",
                OpenFlags::WRITE | OpenFlags::APPEND
            )
            .await
        ),
        StatusCode::OpUnsupported
    );

    // Removing: files, then empty folders; buckets only when empty.
    assert_eq!(
        status(sftp.remove_dir("/photos/2026").await),
        StatusCode::Failure
    );
    sftp.remove_file("/photos/2026/deep/x.bin").await.unwrap();
    sftp.remove_file("/photos/2026/renamed.txt").await.unwrap();
    assert_eq!(
        status(sftp.remove_file("/photos/2026/renamed.txt").await),
        StatusCode::NoSuchFile
    );
    sftp.remove_dir("/photos/2026").await.unwrap();
    sftp.remove_dir("/photos").await.unwrap();
    assert!(s3.head_bucket().bucket("photos").send().await.is_err());
}

#[tokio::test]
async fn big_files_go_up_in_parts_and_come_back_whole() {
    let server = start().await;
    let s3 = common::client(&server, SECRET_KEY);
    s3.create_bucket().bucket("big").send().await.unwrap();
    let sftp = connect(server.sftp.unwrap(), ACCESS_KEY, SECRET_KEY)
        .await
        .unwrap();
    let data: Vec<u8> = (0..(2 * PART + 12_345))
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let mut file = sftp.create("/big/blob.bin").await.unwrap();
    for chunk in data.chunks(100_000) {
        file.write_all(chunk).await.unwrap();
    }
    file.shutdown().await.unwrap();
    drop(file);
    let head = s3
        .head_object()
        .bucket("big")
        .key("blob.bin")
        .send()
        .await
        .unwrap();
    assert!(
        head.e_tag().unwrap().ends_with("-3\""),
        "{:?}",
        head.e_tag()
    );
    assert_eq!(
        head.content_length(),
        Some(i64::try_from(data.len()).unwrap())
    );
    assert_eq!(sftp.read("/big/blob.bin").await.unwrap(), data);
    let uploads = s3
        .list_multipart_uploads()
        .bucket("big")
        .send()
        .await
        .unwrap();
    assert!(uploads.uploads().is_empty());
}

#[tokio::test]
async fn sign_ins_are_checked_and_guessing_is_stopped() {
    let server = start().await;
    let at = server.sftp.unwrap();
    assert_eq!(
        connect(at, ACCESS_KEY, "wrong").await.err().unwrap(),
        "refused"
    );
    assert_eq!(
        connect(at, "nobody", SECRET_KEY).await.err().unwrap(),
        "refused"
    );
    // Ten failures from an address, and it's refused even with the right secret.
    for _ in 0..(teifs_gateway::MAX_FAILURES - 2) {
        let _ = connect(at, ACCESS_KEY, "wrong").await;
    }
    assert!(connect(at, ACCESS_KEY, SECRET_KEY).await.is_err());
}

#[tokio::test]
async fn people_can_do_what_their_policies_allow() {
    let server = start().await;
    let s3 = common::client(&server, SECRET_KEY);
    s3.create_bucket().bucket("shared").send().await.unwrap();
    s3.put_object()
        .bucket("shared")
        .key("readme.txt")
        .body(ByteStream::from_static(b"read me"))
        .send()
        .await
        .unwrap();
    server.iam.create_user("reader", None, &[], None).unwrap();
    server
        .iam
        .put_inline(
            teifs_iam::Owner::User("reader"),
            "read",
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":["s3:ListBucket","s3:GetObject"],
                 "Resource":["arn:aws:s3:::shared","arn:aws:s3:::shared/*"]}]}"#,
        )
        .unwrap();
    let key = server.iam.create_access_key("reader").unwrap();
    let sftp = connect(server.sftp.unwrap(), &key.info.id, &key.secret)
        .await
        .unwrap();
    assert_eq!(names(&sftp, "/shared").await, ["readme.txt"]);
    assert_eq!(sftp.read("/shared/readme.txt").await.unwrap(), b"read me");
    // No s3:PutObject: the upload is refused when it's made.
    let mut file = sftp.create("/shared/new.txt").await.unwrap();
    file.write_all(b"x").await.unwrap();
    assert!(file.shutdown().await.is_err());
    drop(file);
    assert_eq!(
        status(sftp.remove_file("/shared/readme.txt").await),
        StatusCode::PermissionDenied
    );
    assert_eq!(
        status(sftp.create_dir("/mine").await),
        StatusCode::PermissionDenied
    );
    assert!(
        s3.head_object()
            .bucket("shared")
            .key("new.txt")
            .send()
            .await
            .is_err()
    );
}

#[tokio::test]
async fn folders_in_folder_buckets_are_real_folders() {
    let server = start().await;
    let sftp = connect(server.sftp.unwrap(), ACCESS_KEY, SECRET_KEY)
        .await
        .unwrap();
    // The test server makes folder buckets by default.
    sftp.create_dir("/docs").await.unwrap();
    sftp.create_dir("/docs/notes").await.unwrap();
    let mut file = sftp.create("/docs/notes/two.txt").await.unwrap();
    file.write_all(b"2").await.unwrap();
    file.shutdown().await.unwrap();
    drop(file);
    let on_disk = server.dir.path().join("docs").join("notes");
    assert!(on_disk.is_dir());
    assert_eq!(std::fs::read(on_disk.join("two.txt")).unwrap(), b"2");
}

#[tokio::test]
async fn the_gateway_is_off_by_default_and_keeps_its_host_key_private() {
    let server = common::start().await;
    assert!(server.sftp.is_none());
    drop(server);

    // A host key others can read is refused, as sshd refuses it.
    let keys = tempfile::tempdir().unwrap();
    let path = keys.path().join("host_key");
    std::fs::write(&path, b"not a key").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut config = common::config(dir.path(), keys.path());
        config.gateways.sftp = Some(SftpConfig::new("127.0.0.1:0".parse().unwrap(), Some(path)));
        let err = teifs_server::Server::bind(config).await.err().unwrap();
        assert!(err.to_string().contains("chmod 600"), "{err}");
    }
}

#[tokio::test]
async fn a_new_host_key_is_made_once_and_kept() {
    let dir = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    let path = keys.path().join("ssh").join("host_key");
    let bind = || {
        let mut config = common::config(dir.path(), keys.path());
        config.gateways.sftp = Some(SftpConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            Some(path.clone()),
        ));
        teifs_server::Server::bind(config)
    };
    let first = Box::pin(bind()).await.unwrap();
    let fingerprint = first.sftp_fingerprint().unwrap();
    assert!(fingerprint.starts_with("SHA256:"), "{fingerprint}");
    drop(first);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let second = Box::pin(bind()).await.unwrap();
    assert_eq!(second.sftp_fingerprint().unwrap(), fingerprint);
}
