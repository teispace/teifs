//! WebSocket (RFC 6455) client connections, for targets reached through an HTTP server
//! or a proxy that only passes WebSocket connections: after the upgrade, what's written goes in
//! binary frames, masked as a client's must be, and the data frames read come back as
//! one stream of bytes. Pings are answered; a close ends the stream.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zeroize::{Zeroize, Zeroizing};

use crate::net::Stream;

/// The GUID the server hashes the client's key with (RFC 6455, section 1.3).
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// The longest answer to the upgrade read.
const MAX_HEAD: usize = 8 * 1024;
/// The longest frame read: the targets only acknowledge.
const MAX_FRAME: usize = 1 << 20;

/// A frame's opcode, in the low nibble of its first byte.
pub(crate) mod opcode {
    pub const CONTINUATION: u8 = 0x0;
    pub const TEXT: u8 = 0x1;
    pub const BINARY: u8 = 0x2;
    pub const CLOSE: u8 = 0x8;
    pub const PING: u8 = 0x9;
    pub const PONG: u8 = 0xa;
}

/// Upgrades `stream` to a WebSocket at `path` on `host` (`HOST:PORT`, the `Host` header)
/// that speaks `protocol`, and returns it as a stream of bytes.
pub(crate) async fn open(
    mut stream: Stream,
    host: &str,
    path: &str,
    protocol: &str,
) -> Result<Stream, String> {
    let lost = |e: io::Error| format!("the connection failed: {e}");
    let mut nonce = [0; 16];
    aws_lc_rs::rand::fill(&mut nonce).map_err(|_| "no randomness".to_owned())?;
    let key = STANDARD.encode(nonce);
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: {protocol}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.map_err(lost)?;
    stream.flush().await.map_err(lost)?;
    // Byte by byte, so nothing after the head is taken from the frames.
    let mut head = Vec::with_capacity(256);
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD {
            return Err("its answer to the WebSocket upgrade is too long".to_owned());
        }
        let byte = stream.read_u8().await;
        head.push(byte.map_err(|e| format!("it didn't answer the WebSocket upgrade: {e}"))?);
    }
    upgraded(&head, &key, protocol)?;
    Ok(Box::new(WebSocket::new(stream)))
}

/// Checks the server's answer, `head`, to an upgrade asked for with `key` and `protocol`.
fn upgraded(head: &[u8], key: &str, protocol: &str) -> Result<(), String> {
    let not_http = || "it didn't answer the WebSocket upgrade with HTTP".to_owned();
    let head = std::str::from_utf8(head).map_err(|_| not_http())?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let code = status
        .strip_prefix("HTTP/1.1 ")
        .and_then(|rest| rest.get(..3))
        .ok_or_else(not_http)?;
    if code != "101" {
        return Err(format!(
            "it refused the WebSocket upgrade: {}",
            status.trim_start_matches("HTTP/1.1 ")
        ));
    }
    let header = |name: &str| {
        head.split("\r\n").skip(1).find_map(|line| {
            let (n, value) = line.split_once(':')?;
            n.trim().eq_ignore_ascii_case(name).then(|| value.trim())
        })
    };
    let is = |name: &str, token: &str| {
        header(name).is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    };
    if !is("Upgrade", "websocket") || !is("Connection", "upgrade") {
        return Err("it didn't upgrade the connection to a WebSocket".to_owned());
    }
    if header("Sec-WebSocket-Accept") != Some(accept(key).as_str()) {
        return Err("its WebSocket upgrade isn't an answer to the one asked for".to_owned());
    }
    match header("Sec-WebSocket-Protocol") {
        Some(chosen) if chosen == protocol => Ok(()),
        Some(chosen) => Err(format!(
            "it chose the WebSocket protocol `{chosen}`, not `{protocol}`"
        )),
        None => Err(format!(
            "it didn't take the WebSocket protocol `{protocol}`"
        )),
    }
}

/// The `Sec-WebSocket-Accept` a server answers `key` with.
fn accept(key: &str) -> String {
    let digest = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}{GUID}").as_bytes(),
    );
    STANDARD.encode(digest.as_ref())
}

/// A frame the server sent.
#[derive(Debug, PartialEq, Eq)]
enum Frame {
    /// Data: a message, or a piece of one.
    Data(Vec<u8>),
    Ping(Vec<u8>),
    Pong,
    Close,
}

/// The frame at the start of `bytes` and its size, or none until more is read.
fn parse(bytes: &[u8]) -> Result<Option<(Frame, usize)>, String> {
    let bad = |what: &str| format!("it sent a WebSocket frame {what}");
    let [first, second, ..] = *bytes else {
        return Ok(None);
    };
    if first & 0x70 != 0 {
        return Err(bad("with an extension it wasn't asked for"));
    }
    if second & 0x80 != 0 {
        return Err(bad("masked, as only a client's are"));
    }
    let (size, at) = match second & 0x7f {
        126 => match bytes.get(2..4) {
            Some(b) => (u64::from(u16::from_be_bytes([b[0], b[1]])), 4),
            None => return Ok(None),
        },
        127 => match bytes.get(2..10) {
            Some(b) => (u64::from_be_bytes(b.try_into().expect("eight bytes")), 10),
            None => return Ok(None),
        },
        size => (u64::from(size), 2),
    };
    let size = usize::try_from(size)
        .ok()
        .filter(|&s| s <= MAX_FRAME)
        .ok_or_else(|| bad("larger than expected"))?;
    let (fin, code) = (first & 0x80 != 0, first & 0x0f);
    if code >= opcode::CLOSE && (!fin || size > 125) {
        return Err(bad("that isn't a whole control frame"));
    }
    let Some(payload) = bytes.get(at..at + size) else {
        return Ok(None);
    };
    let frame = match code {
        opcode::CONTINUATION | opcode::BINARY => Frame::Data(payload.to_vec()),
        opcode::CLOSE => Frame::Close,
        opcode::PING => Frame::Ping(payload.to_vec()),
        opcode::PONG => Frame::Pong,
        opcode::TEXT => return Err(bad("of text, not binary data")),
        _ => return Err(bad("of a kind WebSocket doesn't have")),
    };
    Ok(Some((frame, at + size)))
}

/// Appends a whole frame of `code` carrying `payload`, masked with `mask`.
fn put_frame(out: &mut Vec<u8>, code: u8, payload: &[u8], mask: [u8; 4]) {
    out.push(0x80 | code);
    // The mask bit, then the length: in 7 bits, or 126 and 16 bits, or 127 and 64 bits.
    let size = payload.len();
    match (u8::try_from(size), u16::try_from(size)) {
        (Ok(n), _) if n < 0x7e => out.push(0x80 | n),
        (_, Ok(n)) => {
            out.push(0xfe);
            out.extend_from_slice(&n.to_be_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&u64::try_from(size).expect("fits").to_be_bytes());
        }
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().zip(mask.iter().cycle()).map(|(b, m)| b ^ m));
}

/// A WebSocket, read and written as a stream of bytes.
struct WebSocket {
    inner: Stream,
    /// Bytes read that aren't a whole frame yet.
    read: Vec<u8>,
    /// A data frame's payload, and how much of it was read.
    data: Vec<u8>,
    taken: usize,
    /// Frames to send (wiped once sent: they carry credentials), and how much was sent.
    out: Zeroizing<Vec<u8>>,
    sent: usize,
    /// Whether the server closed it.
    closed: bool,
}

impl WebSocket {
    fn new(inner: Stream) -> Self {
        Self {
            inner,
            read: Vec::new(),
            data: Vec::new(),
            taken: 0,
            out: Zeroizing::new(Vec::new()),
            sent: 0,
            closed: false,
        }
    }

    /// Queues a frame of `code` with `payload`.
    fn queue(&mut self, code: u8, payload: &[u8]) -> io::Result<()> {
        let mut mask = [0; 4];
        aws_lc_rs::rand::fill(&mut mask).map_err(|_| io::Error::other("no randomness"))?;
        put_frame(&mut self.out, code, payload, mask);
        Ok(())
    }

    /// Sends what's queued.
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.sent < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.sent..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.sent += n;
        }
        self.out.zeroize();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for WebSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.taken < this.data.len() {
                let n = buf.remaining().min(this.data.len() - this.taken);
                buf.put_slice(&this.data[this.taken..this.taken + n]);
                this.taken += n;
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            if let Some((frame, size)) = parse(&this.read).map_err(io::Error::other)? {
                this.read.drain(..size);
                match frame {
                    Frame::Data(data) => (this.data, this.taken) = (data, 0),
                    Frame::Ping(payload) => {
                        this.queue(opcode::PONG, &payload)?;
                        // Sent now if it can be, else with what's written next.
                        if let Poll::Ready(Err(e)) = this.poll_send(cx) {
                            return Poll::Ready(Err(e));
                        }
                    }
                    Frame::Pong => {}
                    Frame::Close => this.closed = true,
                }
                continue;
            }
            let mut chunk = [0; 4096];
            let mut filled = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut filled))?;
            if filled.filled().is_empty() {
                if !this.read.is_empty() {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.closed = true;
            }
            this.read.extend_from_slice(filled.filled());
        }
    }
}

impl AsyncWrite for WebSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_send(cx))?;
        this.queue(opcode::BINARY, buf)?;
        if let Poll::Ready(Err(e)) = this.poll_send(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_accept_key_is_rfc_6455s() {
        assert_eq!(
            accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// A server's frame: unmasked.
    fn server_frame(first: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_frame(&mut out, first & 0x0f, payload, [0; 4]);
        // Unmasked: drop the mask bit and the (zero) mask.
        out[0] = first;
        out[1] &= 0x7f;
        let at = match out[1] {
            126 => 4,
            127 => 10,
            _ => 2,
        };
        out.drain(at..at + 4);
        out
    }

    #[test]
    fn frames_are_read_whatever_their_length() {
        for size in [0, 125, 126, 65_535, 65_536] {
            let payload = vec![7; size];
            let frame = server_frame(0x82, &payload);
            assert_eq!(
                parse(&frame).unwrap(),
                Some((Frame::Data(payload.clone()), frame.len())),
                "{size}"
            );
            // Nothing until all of it is there.
            for cut in [1, frame.len() - 1] {
                if cut < frame.len() {
                    assert_eq!(parse(&frame[..cut]).unwrap(), None, "{size} cut at {cut}");
                }
            }
        }
        assert_eq!(
            parse(&server_frame(0x00, b"ab")).unwrap().unwrap().0,
            Frame::Data(b"ab".to_vec())
        );
        assert_eq!(
            parse(&server_frame(0x89, b"p")).unwrap().unwrap().0,
            Frame::Ping(b"p".to_vec())
        );
        assert_eq!(
            parse(&server_frame(0x8a, b"")).unwrap().unwrap().0,
            Frame::Pong
        );
        assert_eq!(
            parse(&server_frame(0x88, &[3, 232])).unwrap().unwrap().0,
            Frame::Close
        );
    }

    #[test]
    fn frames_a_client_mustnt_take_are_refused() {
        let mut masked = Vec::new();
        put_frame(&mut masked, opcode::BINARY, b"x", [1, 2, 3, 4]);
        for bad in [
            masked,
            server_frame(0x81, b"text"),
            server_frame(0xc2, b"rsv1"),
            server_frame(0x83, b"reserved opcode"),
            server_frame(0x09, b"a fragmented ping"),
            server_frame(0x89, &[0; 126]),
            vec![0x82, 127, 0, 0, 0, 0, 0, 0x10, 0, 1],
        ] {
            assert!(parse(&bad).is_err(), "{bad:02x?}");
        }
    }

    /// Data frames read as one stream, a ping answered with a masked pong, and a close
    /// ending it, though the connection stays open.
    #[tokio::test]
    async fn frames_read_as_a_stream_until_a_close() {
        let (ours, mut theirs) = tokio::io::duplex(1 << 16);
        let mut socket = WebSocket::new(Box::new(ours));
        let frames = [
            server_frame(0x02, b"ab"),
            server_frame(0x89, b"hi"),
            server_frame(0x80, b"c"),
            server_frame(0x88, b""),
            server_frame(0x82, b"after the close"),
        ]
        .concat();
        theirs.write_all(&frames).await.unwrap();
        let mut read = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.read_to_end(&mut read),
        )
        .await
        .expect("the close ends it")
        .unwrap();
        assert_eq!(read, b"abc");
        let mut pong = [0; 8];
        theirs.read_exact(&mut pong).await.unwrap();
        assert_eq!(pong[..2], [0x8a, 0x82]);
        let mask = [pong[2], pong[3], pong[4], pong[5]];
        assert_eq!([pong[6] ^ mask[0], pong[7] ^ mask[1]], *b"hi");
        socket.write_all(b"xyz").await.unwrap();
        socket.flush().await.unwrap();
        let mut sent = [0; 9];
        theirs.read_exact(&mut sent).await.unwrap();
        assert_eq!(sent[..2], [0x82, 0x83]);
        // A connection closed in the middle of a frame is an error.
        let (ours, mut theirs) = tokio::io::duplex(64);
        let mut cut = WebSocket::new(Box::new(ours));
        theirs
            .write_all(&server_frame(0x82, b"abc")[..3])
            .await
            .unwrap();
        drop(theirs);
        assert!(cut.read_to_end(&mut Vec::new()).await.is_err());
    }

    #[test]
    fn a_clients_frames_are_masked() {
        let mut out = Vec::new();
        put_frame(&mut out, opcode::BINARY, b"abc", [1, 2, 3, 4]);
        assert_eq!(out, [0x82, 0x83, 1, 2, 3, 4, b'a' ^ 1, b'b' ^ 2, b'c' ^ 3]);
        let mut long = Vec::new();
        put_frame(&mut long, opcode::BINARY, &[0; 300], [0; 4]);
        assert_eq!(long[..4], [0x82, 0xfe, 1, 44]);
        assert_eq!(long.len(), 4 + 4 + 300);
    }

    #[test]
    fn only_an_upgrade_that_answers_the_key_and_protocol_is_taken() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let head = |status: &str, headers: &str| {
            format!("HTTP/1.1 {status}\r\n{headers}\r\n").into_bytes()
        };
        let good = "Upgrade: WebSocket\r\nConnection: keep-alive, Upgrade\r\n\
                    Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
                    sec-websocket-protocol: mqtt\r\n";
        upgraded(&head("101 Switching Protocols", good), key, "mqtt").unwrap();
        for (status, headers, error) in [
            (
                "404 Not Found",
                good,
                "refused the WebSocket upgrade: 404 Not Found",
            ),
            (
                "101 Switching Protocols",
                &good.replace("s3pP", "xxxx"),
                "isn't an answer",
            ),
            (
                "101 Switching Protocols",
                &good.replace("mqtt", "wamp"),
                "`wamp`, not `mqtt`",
            ),
            (
                "101 Switching Protocols",
                &good.replace("sec-websocket-protocol: mqtt\r\n", ""),
                "didn't take the WebSocket protocol",
            ),
            (
                "101 Switching Protocols",
                &good.replace("Upgrade: WebSocket", "Upgrade: h2c"),
                "didn't upgrade",
            ),
        ] {
            let err = upgraded(&head(status, headers), key, "mqtt").unwrap_err();
            assert!(err.contains(error), "{err}");
        }
        assert!(upgraded(b"SSH-2.0-OpenSSH\r\n\r\n", key, "mqtt").is_err());
    }
}
