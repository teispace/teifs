//! The SFTP gateway: an SSH server whose only service is the `sftp` subsystem, over the
//! person's buckets. People sign in with an access key as the user name and its secret
//! as the password; no shells, commands, forwarding or agents.

use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use russh::{
    Channel, ChannelId, Disconnect, MethodKind, MethodSet,
    keys::{PrivateKey, ssh_key::LineEnding},
    server::{Auth, ChannelOpenHandle, Msg, Session},
};
use russh_sftp::{
    protocol::{
        Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
    },
    server::StatusReply,
};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    Backend, GatewayError, Key, SignInError,
    attempts::Attempts,
    files::{Entry, Files, FsError, Kind, Location, Reader, Writer},
};

/// The user agent the audit log records the gateway's requests under.
const PROTOCOL: &str = "teifs-sftp";
/// How long a client has to sign in after connecting.
const SIGN_IN_TIME: Duration = Duration::from_secs(60);
/// The most sessions (channels) one connection opens.
const MAX_CHANNELS: usize = 4;
/// The most files and folders one session holds open.
const MAX_HANDLES: usize = 64;
/// The most uploads one session has going at once (each holds up to a part).
const MAX_WRITERS: usize = 4;
/// The most a read returns, whatever is asked (OpenSSH asks for 32 KiB to 255 KiB).
const MAX_READ: u32 = 256 * 1024;
/// How long open sessions have to finish once the server stops.
const DRAIN: Duration = Duration::from_secs(10);

/// How the SFTP gateway is served.
#[derive(Debug, Clone)]
pub struct SftpConfig {
    /// The address it listens on.
    pub address: SocketAddr,
    /// The server's host key (OpenSSH format), made (Ed25519) when missing. It must be
    /// readable by its owner only. The server fills in its default when it's `None`.
    pub host_key: Option<PathBuf>,
    /// The size of an upload's parts in bytes (16 MiB by default; at least 5 MiB).
    pub part_size: usize,
    /// How long a connection may be idle before it's closed.
    pub idle_timeout: Duration,
    /// The most connections served at once.
    pub max_connections: usize,
}

impl SftpConfig {
    /// The defaults, listening on `address` with the host key at `host_key`.
    #[must_use]
    pub fn new(address: SocketAddr, host_key: Option<PathBuf>) -> Self {
        Self {
            address,
            host_key,
            part_size: 16 * 1024 * 1024,
            idle_timeout: Duration::from_secs(600),
            max_connections: 256,
        }
    }
}

/// The SFTP gateway, listening.
pub struct Sftp {
    listener: TcpListener,
    ssh: Arc<russh::server::Config>,
    shared: Arc<Shared>,
    max_connections: usize,
}

impl std::fmt::Debug for Sftp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sftp")
            .field("address", &self.listener.local_addr().ok())
            .finish_non_exhaustive()
    }
}

/// What every connection shares.
#[derive(Debug)]
struct Shared {
    backend: Backend,
    attempts: Attempts,
    part_size: usize,
}

impl Sftp {
    /// Loads (or makes) the host key and listens on `config.address`.
    ///
    /// # Errors
    ///
    /// When the host key can't be read or made, or the address can't be listened on.
    pub async fn bind(config: &SftpConfig, backend: Backend) -> Result<Self, GatewayError> {
        let path = config
            .host_key
            .as_deref()
            .ok_or_else(|| GatewayError::HostKey {
                path: PathBuf::new(),
                why: "no host key was given".into(),
            })?;
        let key = host_key(path)?;
        let listener =
            TcpListener::bind(config.address)
                .await
                .map_err(|source| GatewayError::Listen {
                    address: config.address,
                    source,
                })?;
        let ssh = russh::server::Config {
            server_id: russh::SshId::Standard("SSH-2.0-TeiFS".into()),
            methods: MethodSet::from(&[MethodKind::Password][..]),
            auth_rejection_time: Duration::from_secs(1),
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![key],
            max_auth_attempts: 3,
            inactivity_timeout: Some(config.idle_timeout),
            keepalive_interval: Some(Duration::from_secs(60)),
            nodelay: true,
            ..russh::server::Config::default()
        };
        Ok(Self {
            listener,
            ssh: Arc::new(ssh),
            shared: Arc::new(Shared {
                backend,
                attempts: Attempts::default(),
                part_size: config.part_size,
            }),
            max_connections: config.max_connections.max(1),
        })
    }

    /// The address it listens on (useful with port 0).
    ///
    /// # Errors
    ///
    /// When the system can't say.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The host key's public half, as `ssh-ed25519 AAAA…`, for people to check.
    #[must_use]
    pub fn host_key_fingerprint(&self) -> String {
        self.ssh
            .keys
            .first()
            .map(|key| {
                key.public_key()
                    .fingerprint(russh::keys::HashAlg::Sha256)
                    .to_string()
            })
            .unwrap_or_default()
    }

    /// Serves connections until `shutdown` resolves, then closes them, letting uploads
    /// finish for a few seconds.
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        let slots = Arc::new(Semaphore::new(self.max_connections));
        let stop = CancellationToken::new();
        let mut connections = tokio::task::JoinSet::new();
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            let slot = tokio::select! {
                slot = Arc::clone(&slots).acquire_owned() => slot.expect("the semaphore stays open"),
                () = shutdown.as_mut() => break,
            };
            let (socket, peer) = tokio::select! {
                accepted = self.listener.accept() => match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        tracing::warn!(error = %err, "couldn't accept an SFTP connection");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
                () = shutdown.as_mut() => break,
            };
            let _ = socket.set_nodelay(true);
            let (ssh, shared, stop) = (
                Arc::clone(&self.ssh),
                Arc::clone(&self.shared),
                stop.clone(),
            );
            connections.spawn(async move {
                let _slot = slot;
                connection(ssh, shared, socket, peer, stop).await;
            });
            // Reap the finished ones as we go.
            while connections.try_join_next().is_some() {}
        }
        stop.cancel();
        let drained = tokio::time::timeout(DRAIN, async {
            while connections.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            tracing::warn!("SFTP sessions still open after {DRAIN:?}; stopping anyway");
            connections.abort_all();
        }
    }
}

/// Serves one connection until it ends, it doesn't sign in in time, or the server stops.
async fn connection(
    ssh: Arc<russh::server::Config>,
    shared: Arc<Shared>,
    socket: tokio::net::TcpStream,
    peer: SocketAddr,
    stop: CancellationToken,
) {
    let signed_in = Arc::new(AtomicBool::new(false));
    let handler = Connection {
        peer,
        shared,
        files: None,
        channels: HashMap::new(),
        signed_in: Arc::clone(&signed_in),
    };
    let session = match russh::server::run_stream(ssh, socket, handler).await {
        Ok(session) => session,
        Err(err) => {
            tracing::debug!(error = %err, %peer, "SFTP connection ended before its session");
            return;
        }
    };
    let handle = session.handle();
    let mut session = std::pin::pin!(session);
    let deadline = tokio::time::sleep(SIGN_IN_TIME);
    let mut deadline = std::pin::pin!(deadline);
    let mut timed = true;
    loop {
        tokio::select! {
            ended = session.as_mut() => {
                if let Err(err) = ended {
                    tracing::debug!(error = %err, %peer, "SFTP session ended");
                }
                return;
            }
            () = deadline.as_mut(), if timed => {
                timed = false;
                if !signed_in.load(Ordering::Relaxed) {
                    let _ = handle
                        .disconnect(Disconnect::ByApplication, "Sign in sooner".into(), "en".into())
                        .await;
                }
            }
            () = stop.cancelled() => {
                let _ = handle
                    .disconnect(Disconnect::ByApplication, "The server is stopping".into(), "en".into())
                    .await;
                let _ = tokio::time::timeout(DRAIN, session.as_mut()).await;
                return;
            }
        }
    }
}

/// Reads the host key at `path`, or makes an Ed25519 one there when there's none.
fn host_key(path: &Path) -> Result<PrivateKey, GatewayError> {
    let bad = |why: String| GatewayError::HostKey {
        path: path.to_owned(),
        why,
    };
    match std::fs::metadata(path) {
        Ok(metadata) => {
            owner_only(&metadata).map_err(bad)?;
            let text =
                Zeroizing::new(std::fs::read_to_string(path).map_err(|e| bad(e.to_string()))?);
            let key = PrivateKey::from_openssh(text.as_bytes()).map_err(|e| bad(e.to_string()))?;
            if key.is_encrypted() {
                return Err(bad(
                    "it's encrypted with a passphrase; give it unencrypted".into()
                ));
            }
            Ok(key)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let key = new_host_key().map_err(bad)?;
            write_owner_only(path, &key).map_err(|e| bad(e.to_string()))?;
            Ok(key)
        }
        Err(err) => Err(bad(err.to_string())),
    }
}

/// A new Ed25519 key, from the system's random numbers.
fn new_host_key() -> Result<PrivateKey, String> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    aws_lc_rs::rand::fill(seed.as_mut()).map_err(|_| "no random numbers".to_owned())?;
    let pair = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
    let mut key = PrivateKey::from(pair);
    key.set_comment("teifs-sftp-host-key");
    Ok(key)
}

/// Writes `key` to a new file at `path` (and its folder) only its owner can read.
fn write_owner_only(path: &Path, key: &PrivateKey) -> std::io::Result<()> {
    let text = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut folder = std::fs::DirBuilder::new();
        folder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut folder, 0o700);
        folder.create(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    std::io::Write::write_all(&mut file, text.as_bytes())?;
    file.sync_all()
}

/// Refuses a key file others can read (as OpenSSH's `sshd` does).
fn owner_only(metadata: &std::fs::Metadata) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "others can read it (mode {:o}): make it readable by its owner only (chmod 600)",
                mode & 0o777
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    Ok(())
}

/// One SSH connection.
struct Connection {
    peer: SocketAddr,
    shared: Arc<Shared>,
    /// The person's files, once they've signed in.
    files: Option<Files>,
    channels: HashMap<ChannelId, Channel<Msg>>,
    signed_in: Arc<AtomicBool>,
}

impl Connection {
    fn client(&self) -> teifs_s3::Client {
        // SSH encrypts the connection, as TLS would.
        teifs_s3::Client {
            ip: Some(self.peer.ip()),
            secure: true,
            tls: None,
        }
    }
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "russh's handler methods are async; some answer at once"
)]
impl russh::server::Handler for Connection {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let ip = self.peer.ip();
        if !self.shared.attempts.allowed(ip) {
            tracing::info!(%ip, "SFTP sign-in refused: too many failures from this address");
            return Ok(Auth::reject());
        }
        let key = Key {
            id: user.to_owned(),
            secret: Arc::new(Zeroizing::new(password.to_owned())),
        };
        match self
            .shared
            .backend
            .sign_in(&key, self.client(), PROTOCOL)
            .await
        {
            Ok(arn) => {
                tracing::debug!(%ip, %arn, "signed in over SFTP");
                let s3 = self.shared.backend.s3(&key, self.client(), PROTOCOL);
                self.files = Some(Files::new(s3, self.shared.part_size));
                self.signed_in.store(true, Ordering::Relaxed);
                Ok(Auth::Accept)
            }
            Err(SignInError::Refused) => {
                self.shared.attempts.failed(ip);
                Ok(Auth::reject())
            }
            Err(SignInError::Unavailable(why)) => {
                tracing::warn!(error = %why, "couldn't check an SFTP sign-in");
                Ok(Auth::reject())
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.files.is_some() && self.channels.len() < MAX_CHANNELS {
            self.channels.insert(channel.id(), channel);
            reply.accept().await;
        } else {
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        match (name, self.channels.remove(&channel), &self.files) {
            ("sftp", Some(open), Some(files)) => {
                session.channel_success(channel)?;
                let handler = SftpSession {
                    files: files.clone(),
                    handles: HashMap::new(),
                    next_handle: 0,
                };
                russh_sftp::server::run(open.into_stream(), handler).await;
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.close(channel)?;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }
}

/// A file or folder a session has open.
enum Open {
    Folder {
        at: Location,
        next: Option<String>,
        done: bool,
    },
    Read(Box<Reader>),
    Write(Box<Writer>),
}

/// One SFTP session over a person's files.
struct SftpSession {
    files: Files,
    handles: HashMap<String, Open>,
    next_handle: u64,
}

/// An SFTP status for a failed file operation.
fn reply(err: &FsError) -> StatusReply {
    let code = match err {
        FsError::NotFound => StatusCode::NoSuchFile,
        FsError::Denied => StatusCode::PermissionDenied,
        FsError::Unsupported(_) => StatusCode::OpUnsupported,
        FsError::Exists | FsError::NotEmpty | FsError::Invalid(_) | FsError::Failed(_) => {
            StatusCode::Failure
        }
    };
    code.with_message(err.to_string())
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".to_owned(),
        language_tag: "en-US".to_owned(),
    }
}

/// Seconds since 1970, as SFTP version 3 has them.
fn unix_seconds(time: Option<SystemTime>) -> Option<u32> {
    time.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
}

fn attributes(entry: &Entry) -> FileAttributes {
    let mut attrs = FileAttributes::empty();
    attrs.size = Some(entry.size);
    attrs.permissions = Some(match entry.kind {
        Kind::Folder => 0o040_755,
        Kind::File => 0o100_644,
    });
    attrs.mtime = unix_seconds(entry.modified);
    attrs.atime = attrs.mtime;
    attrs
}

impl SftpSession {
    fn handle(&mut self, open: Open) -> Result<String, StatusReply> {
        if self.handles.len() >= MAX_HANDLES {
            return Err(StatusCode::Failure.with_message("Too many open files"));
        }
        let writers = self
            .handles
            .values()
            .filter(|o| matches!(o, Open::Write(_)))
            .count();
        if matches!(open, Open::Write(_)) && writers >= MAX_WRITERS {
            return Err(StatusCode::Failure.with_message("Too many uploads at once"));
        }
        self.next_handle += 1;
        let name = self.next_handle.to_string();
        self.handles.insert(name.clone(), open);
        Ok(name)
    }

    async fn open_file(&mut self, path: &str, flags: OpenFlags) -> Result<String, StatusReply> {
        let at = Location::parse(path);
        let writes = flags.contains(OpenFlags::WRITE) || flags.contains(OpenFlags::APPEND);
        if !writes {
            let reader = self.files.reader(&at).await.map_err(|e| reply(&e))?;
            return self.handle(Open::Read(Box::new(reader)));
        }
        if flags.contains(OpenFlags::READ) || flags.contains(OpenFlags::APPEND) {
            return Err(reply(&FsError::Unsupported(
                "changing a file in place: files are uploaded whole",
            )));
        }
        let existing = match self.files.stat(&at).await {
            Ok(entry) => Some(entry),
            Err(FsError::NotFound) => None,
            Err(err) => return Err(reply(&err)),
        };
        match &existing {
            Some(entry) if entry.kind == Kind::Folder => {
                return Err(reply(&FsError::Invalid("That's a folder".into())));
            }
            Some(_) if flags.contains(OpenFlags::EXCLUDE) => return Err(reply(&FsError::Exists)),
            Some(entry) if entry.size > 0 && !flags.contains(OpenFlags::TRUNCATE) => {
                return Err(reply(&FsError::Unsupported(
                    "changing a file in place: files are uploaded whole",
                )));
            }
            None if !flags.contains(OpenFlags::CREATE) => return Err(reply(&FsError::NotFound)),
            _ => {}
        }
        let upload = self
            .files
            .writer(&at, flags.contains(OpenFlags::EXCLUDE))
            .map_err(|e| reply(&e))?;
        self.handle(Open::Write(Box::new(upload)))
    }
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "russh-sftp's handler methods are async; some answer at once"
)]
impl russh_sftp::server::Handler for SftpSession {
    type Error = StatusReply;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported.into()
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Ok(Name {
            id,
            files: vec![File::dummy(Location::parse(&path).path())],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let entry = self
            .files
            .stat(&Location::parse(&path))
            .await
            .map_err(|e| reply(&e))?;
        Ok(Attrs {
            id,
            attrs: attributes(&entry),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let entry = match self.handles.get(&handle) {
            Some(Open::Read(reader)) => reader.entry().clone(),
            Some(Open::Write(writer)) => writer.entry(),
            Some(Open::Folder { at, .. }) => {
                let at = at.clone();
                self.files.stat(&at).await.map_err(|e| reply(&e))?
            }
            None => return Err(StatusCode::Failure.with_message("No such handle")),
        };
        Ok(Attrs {
            id,
            attrs: attributes(&entry),
        })
    }

    // Owners, modes and times can't be set on objects: taken and ignored, as AWS
    // Transfer Family's `SetStatOption=ENABLE_NO_OP` does, so `put -p` and the like work.
    async fn setstat(
        &mut self,
        id: u32,
        _path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        Ok(ok(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        _handle: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let at = Location::parse(&path);
        let entry = self.files.stat(&at).await.map_err(|e| reply(&e))?;
        if entry.kind != Kind::Folder {
            return Err(StatusCode::Failure.with_message("That's a file, not a folder"));
        }
        let handle = self.handle(Open::Folder {
            at,
            next: None,
            done: false,
        })?;
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let Some(Open::Folder { at, next, done }) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure.with_message("No such folder handle"));
        };
        if *done {
            return Err(StatusCode::Eof.into());
        }
        let page = self
            .files
            .list(at, next.take())
            .await
            .map_err(|e| reply(&e))?;
        *next = page.next;
        *done = next.is_none();
        if page.entries.is_empty() && *done {
            return Err(StatusCode::Eof.into());
        }
        Ok(Name {
            id,
            files: page
                .entries
                .iter()
                .map(|entry| File::new(entry.name.clone(), attributes(entry)))
                .collect(),
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let handle = self.open_file(&filename, pflags).await?;
        Ok(Handle { id, handle })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let Some(Open::Read(reader)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure.with_message("That handle isn't open to read"));
        };
        let len = usize::try_from(len.min(MAX_READ)).unwrap_or(0);
        match reader.read(offset, len).await.map_err(|e| reply(&e))? {
            Some(data) => Ok(Data {
                id,
                data: data.to_vec(),
            }),
            None => Err(StatusCode::Eof.into()),
        }
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let Some(Open::Write(writer)) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure.with_message("That handle isn't open to write"));
        };
        if let Err(err) = writer.write(offset, &data).await {
            // The upload can't go on: drop it, aborting what was sent.
            if let Some(Open::Write(writer)) = self.handles.remove(&handle) {
                writer.abort().await;
            }
            return Err(reply(&err));
        }
        Ok(ok(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        match self.handles.remove(&handle) {
            Some(Open::Write(writer)) => writer.finish().await.map_err(|e| reply(&e))?,
            Some(_) => {}
            None => return Err(StatusCode::Failure.with_message("No such handle")),
        }
        Ok(ok(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        self.files
            .remove(&Location::parse(&filename))
            .await
            .map_err(|e| reply(&e))?;
        Ok(ok(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        self.files
            .mkdir(&Location::parse(&path))
            .await
            .map_err(|e| reply(&e))?;
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        self.files
            .rmdir(&Location::parse(&path))
            .await
            .map_err(|e| reply(&e))?;
        Ok(ok(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        self.files
            .rename(
                &Location::parse(&oldpath),
                &Location::parse(&newpath),
                false,
            )
            .await
            .map_err(|e| reply(&e))?;
        Ok(ok(id))
    }
}
