//! The WebDAV gateway: the person's buckets as a WebDAV share (RFC 4918, class 1 with
//! the locks macOS and Windows need faked, as most servers over object storage do),
//! served over HTTPS. People sign in with HTTP Basic authentication: an access key as the
//! user name and its secret as the password. The protocol itself is dav-server's; the
//! files are [`Files`], S3 requests made with the person's key.

use std::{
    collections::HashMap,
    future::Future,
    io::SeekFrom,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use base64::Engine as _;
use bytes::{Buf as _, Bytes};
use dav_server::{
    DavHandler,
    davpath::DavPath,
    fakels::FakeLs,
    fs::{
        DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError as DavError, FsFuture, FsResult,
        FsStream, OpenOptions, ReadDirMeta,
    },
};
use futures::FutureExt as _;
use http::{HeaderValue, Request, Response, StatusCode, header};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    Backend, GatewayError, Key, SignInError,
    attempts::Attempts,
    files::{Entry, Files, FsError, Kind, Location, Reader, Writer},
};

/// The user agent the audit log records the gateway's requests under.
const PROTOCOL: &str = "teifs-webdav";
/// How long a checked key is taken without asking STS again. The S3 requests made with it
/// are still each checked: a key removed meanwhile stops working at once.
const SIGNED_IN_FOR: Duration = Duration::from_mins(5);
/// The most keys remembered as checked.
const MAX_SIGNED_IN: usize = 10_000;
/// How long open requests have to finish once the server stops.
const DRAIN: Duration = Duration::from_secs(10);
/// How long a client has to send a request's headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);

/// How the WebDAV gateway is served.
#[derive(Debug, Clone)]
pub struct WebDavConfig {
    /// The address it listens on.
    pub address: SocketAddr,
    /// The size of an upload's parts in bytes (16 MiB by default; at least 5 MiB).
    pub part_size: usize,
    /// The most connections served at once.
    pub max_connections: usize,
}

impl WebDavConfig {
    /// The defaults, listening on `address`.
    #[must_use]
    pub const fn new(address: SocketAddr) -> Self {
        Self {
            address,
            part_size: 16 * 1024 * 1024,
            max_connections: 1024,
        }
    }
}

/// The WebDAV gateway, listening.
pub struct WebDav {
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    shared: Arc<Shared>,
    max_connections: usize,
}

impl std::fmt::Debug for WebDav {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebDav")
            .field("address", &self.listener.local_addr().ok())
            .field("tls", &self.tls.is_some())
            .finish_non_exhaustive()
    }
}

/// What every connection shares.
struct Shared {
    backend: Backend,
    attempts: Attempts,
    part_size: usize,
    /// Keys STS took lately: the key id and its secret's SHA-256, and when.
    signed_in: Mutex<HashMap<(String, [u8; 32]), Instant>>,
}

impl WebDav {
    /// Listens on `config.address`, over TLS with `tls`.
    ///
    /// # Errors
    ///
    /// When the address can't be listened on, or it isn't a loopback address and there's
    /// no TLS (Basic authentication would send secrets in the clear).
    pub async fn bind(
        config: &WebDavConfig,
        tls: Option<Arc<rustls::ServerConfig>>,
        backend: Backend,
    ) -> Result<Self, GatewayError> {
        if tls.is_none() && !config.address.ip().is_loopback() {
            return Err(GatewayError::Plaintext {
                address: config.address,
                protocol: "WebDAV",
            });
        }
        let listener =
            TcpListener::bind(config.address)
                .await
                .map_err(|source| GatewayError::Listen {
                    address: config.address,
                    source,
                })?;
        Ok(Self {
            listener,
            tls: tls.map(TlsAcceptor::from),
            shared: Arc::new(Shared {
                backend,
                attempts: Attempts::default(),
                part_size: config.part_size,
                signed_in: Mutex::default(),
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

    /// Whether it's served over HTTPS.
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Serves connections until `shutdown` resolves, then lets open requests finish for
    /// a few seconds.
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
                        tracing::warn!(error = %err, "couldn't accept a WebDAV connection");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
                () = shutdown.as_mut() => break,
            };
            let _ = socket.set_nodelay(true);
            let (shared, tls, stop) = (Arc::clone(&self.shared), self.tls.clone(), stop.clone());
            connections.spawn(async move {
                let _slot = slot;
                connection(shared, tls, socket, peer, stop).await;
            });
            while connections.try_join_next().is_some() {}
        }
        stop.cancel();
        let drained = tokio::time::timeout(DRAIN, async {
            while connections.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            tracing::warn!("WebDAV requests still open after {DRAIN:?}; stopping anyway");
            connections.abort_all();
        }
    }
}

/// Serves one connection, over TLS when `tls` is set.
async fn connection(
    shared: Arc<Shared>,
    tls: Option<TlsAcceptor>,
    socket: tokio::net::TcpStream,
    peer: SocketAddr,
    stop: CancellationToken,
) {
    let mut http = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    http.http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT);
    let client = teifs_s3::Client {
        ip: Some(peer.ip()),
        secure: false,
        tls: None,
    };
    let Some(tls) = tls else {
        serve(&http, TokioIo::new(socket), shared, client, stop).await;
        return;
    };
    let Ok(Ok(stream)) = tokio::time::timeout(HEADER_TIMEOUT, tls.accept(socket)).await else {
        return;
    };
    let version = match stream.get_ref().1.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => Some("1.3"),
        Some(rustls::ProtocolVersion::TLSv1_2) => Some("1.2"),
        _ => None,
    };
    let client = teifs_s3::Client {
        secure: true,
        tls: version,
        ..client
    };
    serve(&http, TokioIo::new(stream), shared, client, stop).await;
}

async fn serve<I>(
    http: &hyper_util::server::conn::auto::Builder<TokioExecutor>,
    io: I,
    shared: Arc<Shared>,
    client: teifs_s3::Client,
    stop: CancellationToken,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
        let shared = Arc::clone(&shared);
        async move { Ok::<_, std::convert::Infallible>(answer(&shared, client, req).await) }
    });
    let connection = http.serve_connection(io, service);
    let mut connection = std::pin::pin!(connection);
    tokio::select! {
        served = connection.as_mut() => {
            if let Err(err) = served {
                tracing::debug!(error = %err, "a WebDAV connection ended with an error");
            }
        }
        () = stop.cancelled() => {
            connection.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(DRAIN, connection).await;
        }
    }
}

/// The answer to a request: asks for credentials, refuses them, or hands the request to
/// dav-server over the person's files.
async fn answer(
    shared: &Shared,
    client: teifs_s3::Client,
    req: Request<Incoming>,
) -> Response<dav_server::body::Body> {
    let ip = client.ip.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into());
    let Some(key) = basic_key(req.headers()) else {
        return unauthorized();
    };
    if !shared.attempts.allowed(ip) {
        return plain(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed sign-ins from this address: try again later.\n",
        );
    }
    if !shared.recently_signed_in(&key) {
        match shared.backend.sign_in(&key, client, PROTOCOL).await {
            Ok(_) => shared.remember(&key),
            Err(SignInError::Refused) => {
                shared.attempts.failed(ip);
                return unauthorized();
            }
            Err(SignInError::Unavailable(why)) => {
                tracing::warn!(error = %why, "couldn't check a WebDAV sign-in");
                return plain(StatusCode::SERVICE_UNAVAILABLE, "Try again later.\n");
            }
        }
    }
    let files = Files::new(shared.backend.s3(&key, client, PROTOCOL), shared.part_size);
    let dav = DavHandler::builder()
        .filesystem(Box::new(DavFiles { files }))
        .locksystem(FakeLs::new())
        .principal(key.id.clone())
        .build_handler();
    let mut response = dav.handle(req).await;
    response.headers_mut().insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
}

impl Shared {
    fn secret_hash(key: &Key) -> [u8; 32] {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, key.secret.as_bytes());
        let mut hash = [0; 32];
        hash.copy_from_slice(digest.as_ref());
        hash
    }

    fn recently_signed_in(&self, key: &Key) -> bool {
        let signed_in = self
            .signed_in
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        signed_in
            .get(&(key.id.clone(), Self::secret_hash(key)))
            .is_some_and(|at| at.elapsed() < SIGNED_IN_FOR)
    }

    fn remember(&self, key: &Key) {
        let mut signed_in = self
            .signed_in
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if signed_in.len() >= MAX_SIGNED_IN {
            signed_in.retain(|_, at| at.elapsed() < SIGNED_IN_FOR);
            if signed_in.len() >= MAX_SIGNED_IN {
                signed_in.clear();
            }
        }
        signed_in.insert((key.id.clone(), Self::secret_hash(key)), Instant::now());
    }
}

/// The access key and secret of an `Authorization: Basic` header.
fn basic_key(headers: &http::HeaderMap) -> Option<Key> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?,
    );
    let text = std::str::from_utf8(&decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    (!id.is_empty()).then(|| Key {
        id: id.to_owned(),
        secret: Arc::new(Zeroizing::new(secret.to_owned())),
    })
}

fn plain(status: StatusCode, text: &'static str) -> Response<dav_server::body::Body> {
    let mut response = Response::new(dav_server::body::Body::from(text));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn unauthorized() -> Response<dav_server::body::Body> {
    let mut response = plain(
        StatusCode::UNAUTHORIZED,
        "Sign in with an access key and its secret.\n",
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"TeiFS\", charset=\"UTF-8\""),
    );
    response
}

/// What dav-server's errors are for a file operation's.
fn dav_error(err: &FsError) -> DavError {
    match err {
        FsError::NotFound => DavError::NotFound,
        FsError::Denied => DavError::Forbidden,
        FsError::Exists => DavError::Exists,
        FsError::Unsupported(_) => DavError::NotImplemented,
        FsError::NotEmpty | FsError::Invalid(_) | FsError::Failed(_) => {
            tracing::debug!(error = %err, "a WebDAV request failed");
            DavError::GeneralFailure
        }
    }
}

fn location(path: &DavPath) -> Location {
    Location::parse(&String::from_utf8_lossy(path.as_bytes()))
}

/// The person's files, as dav-server sees a file system.
#[derive(Clone)]
struct DavFiles {
    files: Files,
}

/// A file or folder's metadata, as dav-server reads it.
#[derive(Debug, Clone)]
struct Meta(Entry);

impl DavMetaData for Meta {
    fn len(&self) -> u64 {
        self.0.size
    }

    fn modified(&self) -> FsResult<SystemTime> {
        self.0.modified.ok_or(DavError::NotImplemented)
    }

    fn is_dir(&self) -> bool {
        self.0.kind == Kind::Folder
    }

    fn is_symlink(&self) -> bool {
        false
    }
}

impl DavDirEntry for Meta {
    fn name(&self) -> Vec<u8> {
        self.0.name.as_bytes().to_vec()
    }

    fn metadata(&self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        let meta: Box<dyn DavMetaData> = Box::new(self.clone());
        std::future::ready(Ok(meta)).boxed()
    }
}

impl DavFileSystem for DavFiles {
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        async move {
            let at = location(path);
            if !options.write {
                let reader = self.files.reader(&at).await.map_err(|e| dav_error(&e))?;
                let file: Box<dyn DavFile> = Box::new(DavFileHandle::read(reader));
                return Ok(file);
            }
            if options.append || options.read {
                return Err(DavError::NotImplemented);
            }
            let existing = match self.files.stat(&at).await {
                Ok(entry) => Some(entry),
                Err(FsError::NotFound) => None,
                Err(err) => return Err(dav_error(&err)),
            };
            match existing {
                Some(entry) if entry.kind == Kind::Folder => return Err(DavError::Forbidden),
                Some(_) if options.create_new => return Err(DavError::Exists),
                Some(entry) if entry.size > 0 && !options.truncate => {
                    return Err(DavError::NotImplemented);
                }
                None if !options.create => return Err(DavError::NotFound),
                _ => {}
            }
            let writer = self
                .files
                .writer(&at, options.create_new)
                .map_err(|e| dav_error(&e))?;
            let file: Box<dyn DavFile> = Box::new(DavFileHandle::write(writer));
            Ok(file)
        }
        .boxed()
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        async move {
            let at = location(path);
            let files = self.files.clone();
            // The first page now, so a missing folder fails here; the rest as read.
            let first = files.list(&at, None).await.map_err(|e| dav_error(&e))?;
            let pages =
                futures::stream::unfold((Some(first), files, at), |(page, files, at)| async move {
                    let page = page?;
                    let next = match page.next {
                        Some(token) => match files.list(&at, Some(token)).await {
                            Ok(next) => Some(next),
                            Err(err) => {
                                tracing::debug!(error = %err, "a WebDAV listing stopped");
                                None
                            }
                        },
                        None => None,
                    };
                    let entries: Vec<FsResult<Box<dyn DavDirEntry>>> = page
                        .entries
                        .into_iter()
                        .map(|entry| Ok(Box::new(Meta(entry)) as Box<dyn DavDirEntry>))
                        .collect();
                    Some((futures::stream::iter(entries), (next, files, at)))
                });
            let stream: FsStream<Box<dyn DavDirEntry>> =
                Box::pin(futures::StreamExt::flatten(pages));
            Ok(stream)
        }
        .boxed()
    }

    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        async move {
            let entry = self
                .files
                .stat(&location(path))
                .await
                .map_err(|e| dav_error(&e))?;
            let meta: Box<dyn DavMetaData> = Box::new(Meta(entry));
            Ok(meta)
        }
        .boxed()
    }

    // There are no links: a path is what it names.
    fn symlink_metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        self.metadata(path)
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            self.files
                .mkdir(&location(path))
                .await
                .map_err(|e| dav_error(&e))
        }
        .boxed()
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            self.files
                .rmdir(&location(path))
                .await
                .map_err(|e| dav_error(&e))
        }
        .boxed()
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            self.files
                .remove(&location(path))
                .await
                .map_err(|e| dav_error(&e))
        }
        .boxed()
    }

    // dav-server has applied `Overwrite` (removing what was there) by now.
    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            self.files
                .rename(&location(from), &location(to), true)
                .await
                .map_err(|e| dav_error(&e))
        }
        .boxed()
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        async move {
            self.files
                .copy(&location(from), &location(to), true)
                .await
                .map_err(|e| dav_error(&e))
        }
        .boxed()
    }

    // Times can't be set on objects: taken and ignored, as over SFTP.
    fn set_modified<'a>(&'a self, _path: &'a DavPath, _time: SystemTime) -> FsFuture<'a, ()> {
        std::future::ready(Ok(())).boxed()
    }
}

/// An open file: a download or an upload.
#[derive(Debug)]
struct DavFileHandle(tokio::sync::Mutex<Handle>);

#[derive(Debug)]
enum Handle {
    Read { reader: Box<Reader>, position: u64 },
    Write(Option<Box<Writer>>),
}

impl DavFileHandle {
    fn read(reader: Reader) -> Self {
        Self(tokio::sync::Mutex::new(Handle::Read {
            reader: Box::new(reader),
            position: 0,
        }))
    }

    fn write(writer: Writer) -> Self {
        Self(tokio::sync::Mutex::new(Handle::Write(Some(Box::new(
            writer,
        )))))
    }
}

impl DavFile for DavFileHandle {
    fn metadata(&mut self) -> FsFuture<'_, Box<dyn DavMetaData>> {
        async move {
            let entry = match &*self.0.lock().await {
                Handle::Read { reader, .. } => reader.entry().clone(),
                Handle::Write(Some(writer)) => writer.entry(),
                Handle::Write(None) => return Err(DavError::GeneralFailure),
            };
            let meta: Box<dyn DavMetaData> = Box::new(Meta(entry));
            Ok(meta)
        }
        .boxed()
    }

    fn write_buf(&mut self, mut buf: Box<dyn bytes::Buf + Send>) -> FsFuture<'_, ()> {
        let bytes = buf.copy_to_bytes(buf.remaining());
        self.write_bytes(bytes)
    }

    fn write_bytes(&mut self, buf: Bytes) -> FsFuture<'_, ()> {
        async move {
            let mut handle = self.0.lock().await;
            let Handle::Write(Some(writer)) = &mut *handle else {
                return Err(DavError::Forbidden);
            };
            let offset = writer.entry().size;
            if let Err(err) = writer.write(offset, &buf).await {
                if let Handle::Write(writer) = &mut *handle
                    && let Some(writer) = writer.take()
                {
                    writer.abort().await;
                }
                return Err(dav_error(&err));
            }
            Ok(())
        }
        .boxed()
    }

    fn read_bytes(&mut self, count: usize) -> FsFuture<'_, Bytes> {
        async move {
            let mut handle = self.0.lock().await;
            let Handle::Read { reader, position } = &mut *handle else {
                return Err(DavError::Forbidden);
            };
            let mut out = bytes::BytesMut::with_capacity(count.min(1024 * 1024));
            while out.len() < count {
                match reader
                    .read(*position, count - out.len())
                    .await
                    .map_err(|e| dav_error(&e))?
                {
                    Some(chunk) => {
                        *position += chunk.len() as u64;
                        out.extend_from_slice(&chunk);
                    }
                    None => break,
                }
            }
            Ok(out.freeze())
        }
        .boxed()
    }

    fn seek(&mut self, pos: SeekFrom) -> FsFuture<'_, u64> {
        async move {
            let mut handle = self.0.lock().await;
            match &mut *handle {
                Handle::Read { reader, position } => {
                    let size = reader.entry().size;
                    let to = match pos {
                        SeekFrom::Start(to) => Some(to),
                        SeekFrom::End(by) => size.checked_add_signed(by),
                        SeekFrom::Current(by) => position.checked_add_signed(by),
                    };
                    *position = to.ok_or(DavError::GeneralFailure)?;
                    Ok(*position)
                }
                // Uploads go in order: only where they are.
                Handle::Write(Some(writer)) => {
                    let at = writer.entry().size;
                    match pos {
                        SeekFrom::Start(to) if to == at => Ok(at),
                        SeekFrom::Current(0) => Ok(at),
                        _ => Err(DavError::NotImplemented),
                    }
                }
                Handle::Write(None) => Err(DavError::GeneralFailure),
            }
        }
        .boxed()
    }

    fn flush(&mut self) -> FsFuture<'_, ()> {
        async move {
            let mut handle = self.0.lock().await;
            match &mut *handle {
                Handle::Write(writer) => match writer.take() {
                    Some(writer) => writer.finish().await.map_err(|e| dav_error(&e)),
                    None => Err(DavError::GeneralFailure),
                },
                Handle::Read { .. } => Ok(()),
            }
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests fail on any error")]

    use super::*;

    #[test]
    fn basic_credentials_are_read() {
        let mut headers = http::HeaderMap::new();
        assert!(basic_key(&headers).is_none());
        let encoded = base64::engine::general_purpose::STANDARD.encode("AKIA:se:cret");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        let key = basic_key(&headers).unwrap();
        assert_eq!(key.id, "AKIA");
        assert_eq!(key.secret.as_str(), "se:cret");
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer x"));
        assert!(basic_key(&headers).is_none());
    }
}
