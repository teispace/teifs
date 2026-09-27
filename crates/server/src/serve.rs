//! Serving the S3 service over HTTP/1.1 and HTTP/2.

use std::{future::Future, time::Duration};

use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::{conn::auto::Builder, graceful::GracefulShutdown},
};
use s3s::service::S3Service;
use tokio::net::TcpListener;

/// How long open requests may take to finish once shutdown starts.
pub const DRAIN: Duration = Duration::from_secs(10);

/// Serves `service` on `listener` until `shutdown` resolves, then lets open requests
/// finish for up to [`DRAIN`].
pub async fn serve(listener: TcpListener, service: S3Service, shutdown: impl Future<Output = ()>) {
    let http = Builder::new(TokioExecutor::new());
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let socket = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((socket, _)) => socket,
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
        let connection = http
            .serve_connection(TokioIo::new(socket), service.clone())
            .into_owned();
        let connection = graceful.watch(connection);
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::debug!(error = %err, "connection ended with an error");
            }
        });
    }
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(DRAIN) => tracing::warn!("requests still open after {DRAIN:?}; stopping anyway"),
    }
}
