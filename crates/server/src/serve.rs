//! Serving the S3 service over HTTP/1.1 and HTTP/2, with bounds on what one client can
//! hold: connections, time to send headers, and (in the S3 service) stalled bodies.

use std::{future::Future, sync::Arc, time::Duration};

use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::{conn::auto::Builder, graceful::GracefulShutdown},
};
use tokio::{net::TcpListener, sync::Semaphore};

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

/// Serves `service` on `listener` until `shutdown` resolves, then lets open requests
/// finish for up to [`DRAIN`].
pub async fn serve(
    listener: TcpListener,
    service: teifs_s3::Service,
    limits: Limits,
    shutdown: impl Future<Output = ()>,
) {
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
        let http = Arc::clone(&http);
        // TLS comes later; until then every connection is plain HTTP.
        let service = service.for_client(teifs_s3::Client {
            ip: Some(peer.ip()),
            secure: false,
        });
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let _slot = slot;
            // Telling HTTP/1 from HTTP/2 waits for the first bytes: bound that wait too.
            let mut first = [0; 1];
            match tokio::time::timeout(limits.header_timeout, socket.peek(&mut first)).await {
                Ok(Ok(n)) if n > 0 => {}
                _ => return,
            }
            let connection = http.serve_connection(TokioIo::new(socket), service);
            if let Err(err) = watcher.watch(connection.into_owned()).await {
                tracing::debug!(error = %err, "connection ended with an error");
            }
        });
    }
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(DRAIN) => tracing::warn!("requests still open after {DRAIN:?}; stopping anyway"),
    }
}
