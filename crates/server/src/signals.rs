//! Signals the server acts on.

/// `SIGHUP`s, where the system has them.
pub(crate) struct Hangups {
    #[cfg(unix)]
    signal: Option<tokio::signal::unix::Signal>,
}

impl Hangups {
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(unix)]
            signal: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok(),
        }
    }

    /// The next one; never, without them.
    pub(crate) async fn next(&mut self) {
        #[cfg(unix)]
        if let Some(signal) = &mut self.signal
            && signal.recv().await.is_some()
        {
            return;
        }
        std::future::pending::<()>().await;
    }
}
