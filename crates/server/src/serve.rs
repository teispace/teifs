//! Serving the S3 service over HTTP/1.1 and HTTP/2, plain or over TLS, with bounds on
//! what one client can hold: connections, time to send headers (and finish a TLS
//! handshake), and (in the S3 service) stalled bodies.

use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::{
        conn::auto::Builder,
        graceful::{GracefulShutdown, Watcher},
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};
use tokio_rustls::TlsAcceptor;

use crate::Tls;

/// The first byte of a TLS connection (a handshake record).
const TLS_HANDSHAKE: u8 = 0x16;

/// The answer to plain HTTP on a TLS listener, as Go's servers give it.
const PLAIN_HTTP_ON_TLS: &[u8] = b"HTTP/1.0 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\nClient sent an HTTP request to an HTTPS server.\n";

/// How long open requests may take to finish once shutdown starts.
pub const DRAIN: Duration = Duration::from_secs(10);

/// Bounds on what clients can make the server hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How long a client has to send a request's headers, from connecting or from its
    /// previous response; an idle connection closes after it too (slow-header attacks).
    pub header_timeout: Duration,
    /// How long a request body may stop arriving before the request fails with
    /// `RequestTimeout` (as S3 does for a stalled upload).
    pub body_timeout: Duration,
    /// The most connections served at once; more wait in the system's queue until one
    /// closes.
    pub max_connections: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            header_timeout: Duration::from_secs(30),
            body_timeout: Duration::from_secs(60),
            max_connections: 4096,
        }
    }
}

/// Serves `service` on `listener` (over TLS with `tls`) until `shutdown` resolves, then
/// lets open requests finish for up to [`DRAIN`].
pub async fn serve(
    listener: TcpListener,
    service: teifs_s3::Service,
    limits: Limits,
    tls: Option<Arc<Tls>>,
    shutdown: impl Future<Output = ()>,
) {
    let acceptor = tls.map(|tls| TlsAcceptor::from(tls.config()));
    let mut http = Builder::new(TokioExecutor::new());
    http.http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout);
    http.http2()
        .timer(TokioTimer::new())
        // Pings find peers that went away without closing.
        .keep_alive_interval(limits.header_timeout)
        .keep_alive_timeout(limits.header_timeout);
    let http = Arc::new(http);
    let graceful = GracefulShutdown::new();
    let slots = Arc::new(Semaphore::new(limits.max_connections.max(1)));
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        // Waiting for a free slot before accepting leaves extra clients in the system's
        // queue rather than holding their sockets.
        let slot = tokio::select! {
            slot = Arc::clone(&slots).acquire_owned() => slot.expect("the semaphore stays open"),
            () = shutdown.as_mut() => break,
        };
        let (socket, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    tracing::warn!(error = %err, "couldn't accept a connection");
                    // Out of file descriptors and the like: don't spin.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = shutdown.as_mut() => break,
        };
        let _ = socket.set_nodelay(true);
        let connection = Connection {
            http: Arc::clone(&http),
            service: service.clone(),
            watcher: graceful.watcher(),
            peer,
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _slot = slot;
            connection
                .run(socket, acceptor, limits.header_timeout)
                .await;
        });
    }
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(DRAIN) => tracing::warn!("requests still open after {DRAIN:?}; stopping anyway"),
    }
}

/// One accepted connection, before it's served.
struct Connection {
    http: Arc<Builder<TokioExecutor>>,
    service: teifs_s3::Service,
    watcher: Watcher,
    peer: SocketAddr,
}

impl Connection {
    async fn run(self, socket: TcpStream, tls: Option<TlsAcceptor>, timeout: Duration) {
        // Telling HTTP/1 from HTTP/2, and TLS from plain HTTP, waits for the first
        // bytes: bound that wait too.
        let mut first = [0; 1];
        match tokio::time::timeout(timeout, socket.peek(&mut first)).await {
            Ok(Ok(n)) if n > 0 => {}
            _ => return,
        }
        let Some(tls) = tls else {
            return self.serve(socket, None).await;
        };
        if first[0] != TLS_HANDSHAKE {
            return refuse_plain_http(socket).await;
        }
        match tokio::time::timeout(timeout, tls.accept(socket)).await {
            Ok(Ok(stream)) => {
                let version = match stream.get_ref().1.protocol_version() {
                    Some(rustls::ProtocolVersion::TLSv1_3) => Some("1.3"),
                    Some(rustls::ProtocolVersion::TLSv1_2) => Some("1.2"),
                    _ => None,
                };
                self.serve(stream, version).await;
            }
            Ok(Err(err)) => {
                tracing::debug!(peer = %self.peer, error = %err, "TLS handshake failed");
            }
            Err(_) => tracing::debug!(peer = %self.peer, "TLS handshake timed out"),
        }
    }

    /// Serves one connection; `tls` is its TLS version, none for plain HTTP.
    async fn serve<I>(self, io: I, tls: Option<&'static str>)
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let service = self.service.for_client(teifs_s3::Client {
            ip: Some(self.peer.ip()),
            secure: tls.is_some(),
            tls,
        });
        let connection = self.http.serve_connection(TokioIo::new(io), service);
        if let Err(err) = self.watcher.watch(connection.into_owned()).await {
            tracing::debug!(error = %err, "connection ended with an error");
        }
    }
}

/// Answers plain HTTP on a TLS listener with a hint, then closes. What the client sent
/// is read (briefly) first, so closing doesn't reset the connection before the answer
/// arrives.
async fn refuse_plain_http(mut socket: TcpStream) {
    if socket.write_all(PLAIN_HTTP_ON_TLS).await.is_err() || socket.shutdown().await.is_err() {
        return;
    }
    let mut sink = [0; 4096];
    let drain = async {
        let mut left: usize = 64 * 1024;
        while left > 0 {
            match socket.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(n) => left = left.saturating_sub(n),
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(1), drain).await;
}
