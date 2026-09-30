//! MQTT targets, as `MinIO`'s: each event, as a webhook is sent it, published to a
//! topic on a broker over MQTT 3.1.1, with `QoS` 0 (confirmed by a ping), 1 (the broker's
//! `PUBACK`) or 2 (its `PUBREC`, then `PUBCOMP`). One connection with a clean session,
//! made again after a failure; TLS when asked for; a user and password.

use std::{fmt, fmt::Write as _, future::Future, sync::Arc};

use rustls::ClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

use crate::net::{self, Kept, Stream};

/// The longest packet read: a broker only acknowledges.
const MAX_PACKET: usize = 1 << 16;
/// How long the broker waits for a packet before it drops the connection, in seconds,
/// by default (it waits one and a half times this).
pub const KEEP_ALIVE: u16 = 60;

/// A packet's type, in the high nibble of its first byte.
pub(crate) mod packet {
    pub const CONNECT: u8 = 1;
    pub const CONNACK: u8 = 2;
    pub const PUBLISH: u8 = 3;
    pub const PUBACK: u8 = 4;
    pub const PUBREC: u8 = 5;
    pub const PUBREL: u8 = 6;
    pub const PUBCOMP: u8 = 7;
    pub const PINGREQ: u8 = 12;
    pub const PINGRESP: u8 = 13;
}

/// A topic events are published to.
#[derive(Clone)]
pub struct Mqtt {
    /// The broker, `HOST:PORT`.
    pub address: String,
    /// The topic.
    pub topic: String,
    /// 0, 1 or 2.
    pub qos: u8,
    /// Seconds the broker waits for a packet before it drops the connection; 0 for never.
    pub keep_alive: u16,
    /// The user its password is for.
    pub user: Option<String>,
    /// Its password.
    pub password: Option<Zeroizing<String>>,
    /// TLS, and how the broker is verified; none for plain TCP.
    pub tls: Option<Arc<ClientConfig>>,
    connection: Kept<Connection>,
}

impl Mqtt {
    /// Events for `topic` on the broker at `address` (`HOST:PORT`), with quality of service `qos`.
    ///
    /// # Errors
    ///
    /// When `address` isn't `HOST:PORT`, `topic` can't be published to, or `qos` isn't
    /// 0, 1 or 2.
    pub fn new(address: &str, topic: &str, qos: u8) -> Result<Self, String> {
        let address = address.trim();
        if !net::is_address(address) {
            return Err(format!("`{address}` isn't HOST:PORT"));
        }
        if topic.is_empty()
            || topic.len() > usize::from(u16::MAX)
            || topic.contains(['+', '#', '\0'])
        {
            return Err(format!(
                "`{topic}` can't be published to: give a topic without the wildcards `+` and `#`"
            ));
        }
        if qos > 2 {
            return Err(format!("QoS is 0, 1 or 2, not {qos}"));
        }
        Ok(Self {
            address: address.to_owned(),
            topic: topic.to_owned(),
            qos,
            keep_alive: KEEP_ALIVE,
            user: None,
            password: None,
            tls: None,
            connection: Kept::new(),
        })
    }

    /// Where it publishes.
    #[must_use]
    pub fn shown(&self) -> String {
        format!(
            "{}://{} topic {} (QoS {})",
            if self.tls.is_some() { "mqtts" } else { "mqtt" },
            self.address,
            self.topic,
            self.qos
        )
    }

    /// Publishes `body`.
    pub(crate) async fn send(&self, body: &[u8]) -> Result<(), String> {
        let request = (self.topic.as_str(), self.qos, body);
        self.connection
            .run(self, false, &request, |open, (topic, qos, body)| {
                Box::pin(open.publish(topic, *qos, body))
            })
            .await
    }

    /// Checks that the broker takes the connection, without publishing.
    pub(crate) async fn test(&self) -> Result<(), String> {
        self.connection
            .run(self, true, &(), |open, ()| Box::pin(open.ping()))
            .await
    }

    /// Connects with a clean session and waits for the broker's `CONNACK`.
    async fn open(&self) -> Result<Connection, String> {
        let tcp = net::connect(&self.address).await?;
        let stream = net::secure(tcp, &self.address, self.tls.as_ref()).await?;
        let mut connection = Connection {
            stream: BufReader::new(stream),
            next: 0,
        };
        let command = self.connect_packet()?;
        connection.write(&command).await?;
        let (kind, body) = connection.read().await?;
        if kind >> 4 != packet::CONNACK || body.len() != 2 {
            return Err("it answered with something that isn't MQTT".to_owned());
        }
        match body[1] {
            0 => Ok(connection),
            1 => Err("it doesn't speak MQTT 3.1.1".to_owned()),
            2 => Err("it refused the client id".to_owned()),
            3 => Err("it's unavailable".to_owned()),
            4 => Err("it refused the user or password".to_owned()),
            5 => Err("it didn't authorize the connection".to_owned()),
            code => Err(format!("it refused the connection ({code})")),
        }
    }

    /// `CONNECT`: MQTT 3.1.1, a clean session, a random client id, and the user and
    /// password, written only into memory that's wiped.
    fn connect_packet(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut flags = 0b0000_0010;
        if self.user.is_some() {
            flags |= 0b1000_0000;
        }
        if self.password.is_some() {
            flags |= 0b0100_0000;
        }
        let mut body = Zeroizing::new(Vec::with_capacity(128));
        put_str(&mut body, b"MQTT")?;
        body.push(4);
        body.push(flags);
        body.extend_from_slice(&self.keep_alive.to_be_bytes());
        put_str(&mut body, client_id()?.as_bytes())?;
        if let Some(user) = &self.user {
            put_str(&mut body, user.as_bytes())?;
        }
        if let Some(password) = &self.password {
            put_str(&mut body, password.as_bytes())?;
        }
        frame(packet::CONNECT << 4, &body)
    }
}

impl net::Connects for Mqtt {
    type Connection = Connection;

    fn connect(&self) -> impl Future<Output = Result<Connection, String>> + Send {
        self.open()
    }
}

impl fmt::Debug for Mqtt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mqtt")
            .field("at", &self.shown())
            .finish_non_exhaustive()
    }
}

/// A client id every broker takes: up to 23 letters and digits.
fn client_id() -> Result<String, String> {
    let mut bytes = [0; 8];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| "no randomness".to_owned())?;
    Ok(bytes.iter().fold(String::from("teifs"), |mut id, b| {
        let _ = write!(id, "{b:02x}");
        id
    }))
}

/// Appends `bytes` with their length first, as MQTT's strings are.
fn put_str(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let size = u16::try_from(bytes.len()).map_err(|_| "a string longer than MQTT takes")?;
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// A packet: its first byte, the length of `body`, and `body`.
pub(crate) fn frame(first: u8, body: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() + 5));
    out.push(first);
    let mut size = body.len();
    if size > 268_435_455 {
        return Err("the event is larger than MQTT takes".to_owned());
    }
    loop {
        let mut byte = u8::try_from(size % 128).expect("under 128");
        size /= 128;
        if size > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if size == 0 {
            break;
        }
    }
    out.extend_from_slice(body);
    Ok(out)
}

/// Reads one packet: its first byte and its body.
pub(crate) async fn read_packet<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
    max: usize,
) -> Result<(u8, Vec<u8>), String> {
    let lost = |e: std::io::Error| format!("the connection failed: {e}");
    let first = stream.read_u8().await.map_err(lost)?;
    let mut size = 0usize;
    for shift in 0..4 {
        let byte = stream.read_u8().await.map_err(lost)?;
        size |= usize::from(byte & 0x7f) << (7 * shift);
        if byte & 0x80 == 0 {
            if size > max {
                return Err("it sent a packet larger than expected".to_owned());
            }
            let mut body = vec![0; size];
            stream.read_exact(&mut body).await.map_err(lost)?;
            return Ok((first, body));
        }
    }
    Err("it answered with something that isn't MQTT".to_owned())
}

/// A connection to a broker.
pub(crate) struct Connection {
    stream: BufReader<Stream>,
    /// The last packet id used.
    next: u16,
}

impl Connection {
    async fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        let lost = |e: std::io::Error| format!("the connection failed: {e}");
        let stream = self.stream.get_mut();
        stream.write_all(bytes).await.map_err(lost)?;
        stream.flush().await.map_err(lost)
    }

    async fn read(&mut self) -> Result<(u8, Vec<u8>), String> {
        read_packet(&mut self.stream, MAX_PACKET).await
    }

    /// Reads until a packet of `kind` for packet id `id`, skipping pings' answers.
    async fn expect(&mut self, kind: u8, id: u16) -> Result<(), String> {
        loop {
            let (first, body) = self.read().await?;
            match first >> 4 {
                k if k == kind && body.len() >= 2 && body[..2] == id.to_be_bytes() => {
                    return Ok(());
                }
                // An answer to an earlier publish that timed out, or a ping's.
                packet::PUBACK | packet::PUBREC | packet::PUBCOMP | packet::PINGRESP => {}
                _ => return Err("it answered with something that isn't MQTT".to_owned()),
            }
        }
    }

    /// Asks for the broker's `PINGRESP`: everything sent before was read.
    async fn ping(&mut self) -> Result<(), String> {
        self.write(&[packet::PINGREQ << 4, 0]).await?;
        loop {
            let (first, _) = self.read().await?;
            match first >> 4 {
                packet::PINGRESP => return Ok(()),
                packet::PUBACK | packet::PUBREC | packet::PUBCOMP => {}
                _ => return Err("it answered with something that isn't MQTT".to_owned()),
            }
        }
    }

    /// Publishes `body` to `topic` with `qos`, and waits for the broker to take it.
    async fn publish(&mut self, topic: &str, qos: u8, body: &[u8]) -> Result<(), String> {
        self.next = self.next.checked_add(1).unwrap_or(1);
        let id = self.next;
        let mut packet = Vec::with_capacity(topic.len() + body.len() + 4);
        put_str(&mut packet, topic.as_bytes())?;
        if qos > 0 {
            packet.extend_from_slice(&id.to_be_bytes());
        }
        packet.extend_from_slice(body);
        let packet = frame((packet::PUBLISH << 4) | (qos << 1), &packet)?;
        self.write(&packet).await?;
        match qos {
            0 => self.ping().await,
            1 => self.expect(packet::PUBACK, id).await,
            _ => {
                self.expect(packet::PUBREC, id).await?;
                let mut release = vec![(packet::PUBREL << 4) | 0b0010, 2];
                release.extend_from_slice(&id.to_be_bytes());
                self.write(&release).await?;
                self.expect(packet::PUBCOMP, id).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn packets_are_framed_as_mqtt_does() {
        for size in [0, 1, 127, 128, 16_383, 16_384, 2_097_151, 2_097_152] {
            let packet = frame(0x30, &vec![7; size]).unwrap();
            let expected_header = match size {
                0..=127 => 2,
                128..=16_383 => 3,
                16_384..=2_097_151 => 4,
                _ => 5,
            };
            assert_eq!(packet.len(), size + expected_header, "{size}");
            let (first, body) = read_packet(&mut &packet[..], usize::MAX).await.unwrap();
            assert_eq!((first, body.len()), (0x30, size));
        }
        assert_eq!(&frame(0x30, &[0; 321]).unwrap()[..3], [0x30, 0xc1, 0x02]);
        let read = |bytes: &'static [u8]| async move { read_packet(&mut &bytes[..], 16).await };
        assert!(
            read(&[0x20, 0x80, 0x80, 0x80, 0x80, 0x01]).await.is_err(),
            "five bytes"
        );
        assert!(read(&[0x20, 17]).await.is_err(), "larger than asked for");
        assert!(read(&[0x20, 2, 0]).await.is_err(), "cut short");
        assert_eq!(read(&[0xd0, 0]).await, Ok((0xd0, vec![])));
    }

    #[test]
    fn topics_qos_and_addresses_are_checked() {
        assert!(Mqtt::new("h:1883", "s3/events", 1).is_ok());
        for bad in ["", "a/+/b", "a/#", "a\0b"] {
            assert!(Mqtt::new("h:1883", bad, 1).is_err(), "{bad:?}");
        }
        assert!(Mqtt::new("h:1883", "t", 3).is_err());
        assert!(Mqtt::new("h", "t", 1).is_err());
        assert_eq!(
            Mqtt::new("h:1883", "s3/events", 2).unwrap().shown(),
            "mqtt://h:1883 topic s3/events (QoS 2)"
        );
    }

    #[test]
    fn client_ids_are_ones_every_broker_takes() {
        let (a, b) = (client_id().unwrap(), client_id().unwrap());
        assert_ne!(a, b);
        assert!(
            a.len() <= 23 && a.bytes().all(|c| c.is_ascii_alphanumeric()),
            "{a}"
        );
    }

    #[test]
    fn connect_carries_the_credentials_it_has() {
        let mut mqtt = Mqtt::new("h:1883", "t", 1).unwrap();
        let bare = mqtt.connect_packet().unwrap();
        assert_eq!(bare[0], 0x10);
        // Name "MQTT", level 4, then flags: a clean session only.
        assert_eq!(&bare[2..10], [0, 4, b'M', b'Q', b'T', b'T', 4, 0b10]);
        assert_eq!(&bare[10..12], KEEP_ALIVE.to_be_bytes());
        mqtt.user = Some("teifs".into());
        mqtt.password = Some(Zeroizing::new("pw".into()));
        let full = mqtt.connect_packet().unwrap();
        assert_eq!(full[9], 0b1100_0010);
        assert!(full.ends_with(b"\0\x05teifs\0\x02pw"));
        assert!(!format!("{mqtt:?}").contains("pw"));
    }
}
