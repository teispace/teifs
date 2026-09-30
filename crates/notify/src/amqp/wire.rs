//! AMQP 0-9-1's wire format: frames, methods and their argument types, content headers.

use tokio::io::{AsyncRead, AsyncReadExt};

/// What a connection starts with.
pub(crate) const PROTOCOL_HEADER: &[u8; 8] = b"AMQP\x00\x00\x09\x01";
/// What every frame ends with.
const FRAME_END: u8 = 0xce;
/// What an answer that can't be read is.
pub(crate) const GARBLED: &str = "it answered with something that isn't AMQP 0-9-1";

/// Frame types.
pub(crate) mod frame {
    pub const METHOD: u8 = 1;
    pub const HEADER: u8 = 2;
    pub const BODY: u8 = 3;
    pub const HEARTBEAT: u8 = 8;
}

/// Methods, as `(class, method)`.
pub(crate) mod method {
    pub const CONNECTION_START: (u16, u16) = (10, 10);
    pub const CONNECTION_START_OK: (u16, u16) = (10, 11);
    pub const CONNECTION_TUNE: (u16, u16) = (10, 30);
    pub const CONNECTION_TUNE_OK: (u16, u16) = (10, 31);
    pub const CONNECTION_OPEN: (u16, u16) = (10, 40);
    pub const CONNECTION_OPEN_OK: (u16, u16) = (10, 41);
    pub const CONNECTION_CLOSE: (u16, u16) = (10, 50);
    pub const CHANNEL_OPEN: (u16, u16) = (20, 10);
    pub const CHANNEL_OPEN_OK: (u16, u16) = (20, 11);
    pub const CHANNEL_CLOSE: (u16, u16) = (20, 40);
    pub const EXCHANGE_DECLARE: (u16, u16) = (40, 10);
    pub const EXCHANGE_DECLARE_OK: (u16, u16) = (40, 11);
    pub const BASIC_PUBLISH: (u16, u16) = (60, 40);
    pub const BASIC_RETURN: (u16, u16) = (60, 50);
    pub const BASIC_ACK: (u16, u16) = (60, 80);
    pub const BASIC_NACK: (u16, u16) = (60, 120);
    pub const CONFIRM_SELECT: (u16, u16) = (85, 10);
    pub const CONFIRM_SELECT_OK: (u16, u16) = (85, 11);
}

/// The basic class, whose content messages are.
pub(crate) const BASIC: u16 = 60;

/// A method's or header's arguments, written in AMQP's types.
#[derive(Default)]
pub(crate) struct Writer(pub Vec<u8>);

impl Writer {
    /// A method's arguments, after its class and id.
    pub(crate) fn method((class, id): (u16, u16)) -> Self {
        let mut out = Self::default();
        out.short(class).short(id);
        out
    }

    pub(crate) fn octet(&mut self, n: u8) -> &mut Self {
        self.0.push(n);
        self
    }

    pub(crate) fn short(&mut self, n: u16) -> &mut Self {
        self.0.extend_from_slice(&n.to_be_bytes());
        self
    }

    pub(crate) fn long(&mut self, n: u32) -> &mut Self {
        self.0.extend_from_slice(&n.to_be_bytes());
        self
    }

    pub(crate) fn longlong(&mut self, n: u64) -> &mut Self {
        self.0.extend_from_slice(&n.to_be_bytes());
        self
    }

    /// Up to 255 bytes, their length an octet first.
    pub(crate) fn shortstr(&mut self, text: &str) -> Result<&mut Self, String> {
        let size = u8::try_from(text.len())
            .map_err(|_| format!("`{text}` is longer than AMQP's 255 bytes"))?;
        self.octet(size).0.extend_from_slice(text.as_bytes());
        Ok(self)
    }

    /// Bytes, their length a long first.
    pub(crate) fn longstr(&mut self, bytes: &[u8]) -> Result<&mut Self, String> {
        let size = u32::try_from(bytes.len()).map_err(|_| "larger than AMQP takes")?;
        self.long(size).0.extend_from_slice(bytes);
        Ok(self)
    }

    /// Bits, packed into one octet, the first the lowest.
    pub(crate) fn bits(&mut self, bits: &[bool]) -> &mut Self {
        let packed = bits
            .iter()
            .enumerate()
            .fold(0u8, |out, (i, bit)| out | (u8::from(*bit) << i));
        self.octet(packed)
    }

    /// A field table of strings, booleans and tables.
    pub(crate) fn table(&mut self, fields: &[(&str, Field<'_>)]) -> Result<&mut Self, String> {
        let mut body = Self::default();
        for (name, value) in fields {
            body.shortstr(name)?;
            match value {
                Field::Str(text) => {
                    body.octet(b'S').longstr(text.as_bytes())?;
                }
                Field::Bool(bit) => {
                    body.octet(b't').octet(u8::from(*bit));
                }
                Field::Table(fields) => {
                    body.octet(b'F').table(fields)?;
                }
            }
        }
        self.longstr(&body.0)
    }
}

/// A field table's value.
pub(crate) enum Field<'a> {
    Str(&'a str),
    Bool(bool),
    Table(&'a [(&'a str, Field<'a>)]),
}

/// A frame: its type, channel and payload, ready to write.
pub(crate) fn frame(kind: u8, channel: u16, payload: &[u8]) -> Result<Vec<u8>, String> {
    let size = u32::try_from(payload.len()).map_err(|_| "larger than AMQP takes")?;
    let mut out = Vec::with_capacity(payload.len() + 8);
    out.push(kind);
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(payload);
    out.push(FRAME_END);
    Ok(out)
}

/// A frame read: its type, channel and payload.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    pub kind: u8,
    pub channel: u16,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Its method, when it's a method frame, and the method's arguments.
    pub(crate) fn method(&self) -> Option<((u16, u16), Reader<'_>)> {
        if self.kind != frame::METHOD {
            return None;
        }
        let mut reader = Reader::new(&self.payload);
        let class = reader.short().ok()?;
        let id = reader.short().ok()?;
        Some(((class, id), reader))
    }
}

/// Reads one frame, no larger than `max`.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    stream: &mut R,
    max: usize,
) -> Result<Frame, String> {
    let lost = |e: std::io::Error| format!("the connection failed: {e}");
    let mut head = [0; 7];
    stream.read_exact(&mut head).await.map_err(lost)?;
    if &head[..4] == b"AMQP" {
        // The server's own protocol header: it speaks another version.
        return Err("it doesn't speak AMQP 0-9-1".to_owned());
    }
    let size = usize::try_from(u32::from_be_bytes([head[3], head[4], head[5], head[6]]))
        .ok()
        .filter(|n| *n <= max)
        .ok_or_else(|| "it sent a frame larger than agreed".to_owned())?;
    let mut payload = vec![0; size + 1];
    stream.read_exact(&mut payload).await.map_err(lost)?;
    if payload.pop() != Some(FRAME_END) {
        return Err(GARBLED.to_owned());
    }
    Ok(Frame {
        kind: head[0],
        channel: u16::from_be_bytes([head[1], head[2]]),
        payload,
    })
}

/// A method's arguments, read in order.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let (head, rest) = self.bytes.split_at_checked(n).ok_or(GARBLED)?;
        self.bytes = rest;
        Ok(head)
    }

    pub(crate) fn octet(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn short(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn long(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn longlong(&mut self) -> Result<u64, String> {
        let b = self.take(8)?;
        let mut n = [0; 8];
        n.copy_from_slice(b);
        Ok(u64::from_be_bytes(n))
    }

    pub(crate) fn shortstr(&mut self) -> Result<&'a str, String> {
        let n = usize::from(self.octet()?);
        std::str::from_utf8(self.take(n)?).map_err(|_| GARBLED.to_owned())
    }

    pub(crate) fn longstr(&mut self) -> Result<&'a [u8], String> {
        let n = usize::try_from(self.long()?).map_err(|_| GARBLED)?;
        self.take(n)
    }

    /// A field table, skipped: only its size is read.
    pub(crate) fn skip_table(&mut self) -> Result<(), String> {
        self.longstr().map(drop)
    }

    /// What's left.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) const fn rest(&self) -> &'a [u8] {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_are_read_as_written() {
        let written = frame(frame::METHOD, 1, &[0, 10, 0, 11, 7]).unwrap();
        assert_eq!(written, [1, 0, 1, 0, 0, 0, 5, 0, 10, 0, 11, 7, 0xce]);
        let read = read_frame(&mut &written[..], 16).await.unwrap();
        assert_eq!((read.kind, read.channel), (frame::METHOD, 1));
        let (method, mut args) = read.method().unwrap();
        assert_eq!(method, method::CONNECTION_START_OK);
        assert_eq!(args.octet(), Ok(7));
        assert!(
            read_frame(&mut &written[..], 4).await.is_err(),
            "larger than agreed"
        );
        let mut unended = written.clone();
        *unended.last_mut().unwrap() = 0;
        assert_eq!(
            read_frame(&mut &unended[..], 16).await,
            Err(GARBLED.to_owned())
        );
        let err = read_frame(&mut &b"AMQP\x00\x00\x09\x00"[..], 16)
            .await
            .unwrap_err();
        assert!(err.contains("doesn't speak AMQP 0-9-1"), "{err}");
        assert!(
            read_frame(&mut &written[..6], 16).await.is_err(),
            "cut short"
        );
    }

    #[test]
    fn arguments_are_written_in_amqps_types() {
        let mut out = Writer::method(method::BASIC_PUBLISH);
        out.short(0)
            .shortstr("ex")
            .unwrap()
            .bits(&[true, false, true])
            .longlong(1);
        assert_eq!(
            out.0,
            [
                0, 60, 0, 40, 0, 0, 2, b'e', b'x', 0b101, 0, 0, 0, 0, 0, 0, 0, 1
            ]
        );
        assert!(Writer::default().shortstr(&"x".repeat(256)).is_err());
        let mut table = Writer::default();
        table
            .table(&[
                ("a", Field::Str("b")),
                ("c", Field::Table(&[("d", Field::Bool(true))])),
            ])
            .unwrap();
        assert_eq!(
            table.0,
            [
                0, 0, 0, 19, // the table's size
                1, b'a', b'S', 0, 0, 0, 1, b'b', // a = "b"
                1, b'c', b'F', 0, 0, 0, 4, 1, b'd', b't', 1, // c = {d = true}
            ]
        );
    }

    #[test]
    fn arguments_are_read_only_as_far_as_they_go() {
        let mut reader = Reader::new(&[2, b'o', b'k', 0, 0, 0, 1, 9, 0, 0, 0, 0, 0, 0, 0, 5]);
        assert_eq!(reader.shortstr(), Ok("ok"));
        assert_eq!(reader.longstr(), Ok(&[9][..]));
        assert_eq!(reader.longlong(), Ok(5));
        assert!(reader.octet().is_err());
        assert!(Reader::new(&[0, 0, 0, 9, 1]).skip_table().is_err());
        assert!(Reader::new(&[3, b'a']).shortstr().is_err());
    }
}
