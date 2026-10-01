//! systemd's readiness protocol (`sd_notify`): run with `Type=notify`, `teifs serve`
//! says when it's ready (listening) and when it's stopping, on the socket systemd names
//! in `NOTIFY_SOCKET`. Without that variable (outside systemd, or on Windows) nothing
//! is sent.

/// Tells systemd `state` (`READY=1`, `STOPPING=1`), if it's listening.
pub(crate) fn notify(state: &str) {
    #[cfg(unix)]
    if let Some(socket) = std::env::var_os("NOTIFY_SOCKET")
        && let Err(err) = send(&socket, state)
    {
        tracing::warn!(error = %err, "can't tell systemd {state}");
    }
    #[cfg(not(unix))]
    let _ = state;
}

/// Sends `state` to the datagram socket at `socket`: a path, or `@` and an abstract
/// name (Linux).
#[cfg(unix)]
fn send(socket: &std::ffi::OsStr, state: &str) -> std::io::Result<()> {
    use std::{
        io::{Error, ErrorKind},
        os::unix::{ffi::OsStrExt, net::UnixDatagram},
    };
    let sender = UnixDatagram::unbound()?;
    match socket.as_bytes() {
        [b'/', ..] => sender.send_to(state.as_bytes(), socket).map(|_| ()),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        [b'@', name @ ..] => {
            use std::os::{linux::net::SocketAddrExt, unix::net::SocketAddr};
            let address = SocketAddr::from_abstract_name(name)?;
            sender.send_to_addr(state.as_bytes(), &address).map(|_| ())
        }
        _ => Err(Error::new(
            ErrorKind::InvalidInput,
            "NOTIFY_SOCKET is neither a path nor an abstract name",
        )),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::net::UnixDatagram;

    use super::*;

    #[test]
    fn states_reach_the_socket_named() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let systemd = UnixDatagram::bind(&path).unwrap();
        send(path.as_os_str(), "READY=1").unwrap();
        let mut got = [0; 64];
        let n = systemd.recv(&mut got).unwrap();
        assert_eq!(&got[..n], b"READY=1");
        assert!(send("relative".as_ref(), "READY=1").is_err());
        assert!(send(dir.path().join("gone").as_os_str(), "READY=1").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn abstract_sockets_are_reached_too() {
        use std::os::{linux::net::SocketAddrExt, unix::net::SocketAddr};
        let name = format!("teifs-test-{}", std::process::id());
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let systemd = UnixDatagram::bind_addr(&address).unwrap();
        send(format!("@{name}").as_ref(), "STOPPING=1").unwrap();
        let mut got = [0; 64];
        let n = systemd.recv(&mut got).unwrap();
        assert_eq!(&got[..n], b"STOPPING=1");
    }
}
