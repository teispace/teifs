//! `teifs health`: asks a TeiFS server for its health check, for container health checks
//! and scripts (distroless images have no curl). Plain HTTP only: it's for the server's
//! own machine or container.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    error::{Error, Kind},
    ui,
};

/// `teifs health`'s arguments.
#[derive(clap::Args)]
pub(crate) struct HealthArgs {
    /// The server's address (`teifs serve --listen`'s), or its `http://` URL.
    #[arg(default_value = "127.0.0.1:9000", env = "TEIFS_LISTEN")]
    address: String,
    /// How long to wait for an answer.
    #[arg(long, default_value = "5s", value_parser = crate::units::parse_duration)]
    timeout: Duration,
}

pub(crate) async fn health(args: &HealthArgs) -> Result<(), Error> {
    let target = target(&args.address)?;
    let url = format!("http://{target}{}", teifs_server::HEALTH_PATH);
    let started = Instant::now();
    let status = tokio::time::timeout(args.timeout, ask(&target))
        .await
        .map_err(|_| {
            Error::new(
                Kind::Network,
                format!(
                    "{url} didn't answer within {:.1} s",
                    args.timeout.as_secs_f64()
                ),
            )
        })?
        .map_err(|e| {
            Error::new(Kind::Network, format!("can't reach {url}: {e}"))
                .with_hint("check the address, and that `teifs serve` is running")
        })?;
    if status != 200 {
        return Err(
            Error::new(Kind::General, format!("{url} answered {status}, not 200"))
                .with_hint("is that a TeiFS server?"),
        );
    }
    let elapsed = started.elapsed();
    ui::done(
        format!("{url} is healthy ({} ms)", elapsed.as_millis()),
        || serde_json::json!({"type": "health", "url": url, "healthy": true, "ms": elapsed.as_millis()}),
    );
    Ok(())
}

/// `host:port` from an address or `http://` URL; an unspecified address (`0.0.0.0`)
/// means this machine.
fn target(address: &str) -> Result<String, Error> {
    if address.starts_with("https://") {
        return Err(Error::usage("`teifs health` speaks plain HTTP")
            .with_hint("ask the server's own address, like 127.0.0.1:9000"));
    }
    let bare = address.trim_start_matches("http://").trim_end_matches('/');
    if bare.is_empty() || bare.contains('/') {
        return Err(Error::usage(format!(
            "`{address}` isn't an address like 127.0.0.1:9000"
        )));
    }
    Ok(match bare.parse::<SocketAddr>() {
        Ok(socket) => crate::announce_address(socket).to_string(),
        Err(_) if bare.contains(':') => bare.to_owned(),
        Err(_) => format!("{bare}:9000"),
    })
}

/// The status of `GET` for the health check.
async fn ask(target: &str) -> std::io::Result<u16> {
    let mut socket = TcpStream::connect(target).await?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n",
        teifs_server::HEALTH_PATH
    );
    socket.write_all(request.as_bytes()).await?;
    // The status line is all that's needed.
    let mut head = [0; 64];
    let mut read = 0;
    while read < 12 {
        let n = socket.read(&mut head[read..]).await?;
        if n == 0 {
            break;
        }
        read += n;
    }
    std::str::from_utf8(&head[..read])
        .ok()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "not an HTTP answer"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_become_host_and_port() {
        assert_eq!(target("127.0.0.1:9000").unwrap(), "127.0.0.1:9000");
        assert_eq!(target("0.0.0.0:9100").unwrap(), "127.0.0.1:9100");
        assert_eq!(target("[::]:9100").unwrap(), "[::1]:9100");
        assert_eq!(target("http://localhost:9000/").unwrap(), "localhost:9000");
        assert_eq!(target("teifs").unwrap(), "teifs:9000");
        assert!(target("https://s3.example.com").is_err());
        assert!(target("http://host:9000/path").is_err());
        assert!(target("").is_err());
    }
}
