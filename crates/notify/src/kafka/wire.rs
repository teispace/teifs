//! Kafka's wire format: requests and their header, the primitive types answers are read
//! in, record batches (v2, the only kind Kafka 4 takes) and the partition a key goes to.

use std::io::Write as _;

/// The APIs used, by key.
pub(crate) mod api {
    pub const PRODUCE: i16 = 0;
    pub const METADATA: i16 = 3;
    pub const SASL_HANDSHAKE: i16 = 17;
    pub const API_VERSIONS: i16 = 18;
    pub const SASL_AUTHENTICATE: i16 = 36;
}

/// The name brokers log requests under.
const CLIENT_ID: &str = "teifs";

/// What an answer that can't be read is.
pub(crate) const GARBLED: &str = "it answered with something that isn't Kafka";

/// How a batch's records are compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// Not.
    None,
    /// With gzip.
    Gzip,
    /// With Snappy, as one block (as librdkafka and Sarama write it).
    Snappy,
    /// With LZ4, in LZ4's frame format with independent 64 KiB blocks, as Kafka reads it.
    Lz4,
    /// With Zstandard; Kafka takes it from 2.1 (Produce v7).
    Zstd,
}

impl Compression {
    /// Reads `none`, `gzip`, `snappy`, `lz4` or `zstd`.
    ///
    /// # Errors
    ///
    /// When it's none of them.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "gzip" => Ok(Self::Gzip),
            "snappy" => Ok(Self::Snappy),
            "lz4" => Ok(Self::Lz4),
            "zstd" => Ok(Self::Zstd),
            _ => Err(format!(
                "`{text}` isn't a compression: give none, gzip, snappy, lz4 or zstd"
            )),
        }
    }

    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Snappy => "snappy",
            Self::Lz4 => "lz4",
            Self::Zstd => "zstd",
        }
    }

    /// The Produce version that takes it: 7 for zstd (Kafka 2.1), else 3 (Kafka 0.11).
    pub(crate) const fn produce_version(self) -> i16 {
        match self {
            Self::Zstd => 7,
            _ => 3,
        }
    }

    /// Its code, in a batch's attributes.
    const fn code(self) -> i16 {
        match self {
            Self::None => 0,
            Self::Gzip => 1,
            Self::Snappy => 2,
            Self::Lz4 => 3,
            Self::Zstd => 4,
        }
    }

    /// `records`, compressed.
    fn compress(self, records: Vec<u8>) -> Result<Vec<u8>, String> {
        let failed = |e: &dyn std::fmt::Display| format!("can't compress it: {e}");
        match self {
            Self::None => Ok(records),
            Self::Gzip => {
                let mut gzip =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                gzip.write_all(&records)
                    .and_then(|()| gzip.finish())
                    .map_err(|e| failed(&e))
            }
            Self::Snappy => snap::raw::Encoder::new()
                .compress_vec(&records)
                .map_err(|e| failed(&e)),
            Self::Lz4 => {
                let frame = lz4_flex::frame::FrameInfo::new()
                    .block_size(lz4_flex::frame::BlockSize::Max64KB)
                    .block_mode(lz4_flex::frame::BlockMode::Independent);
                let mut lz4 = lz4_flex::frame::FrameEncoder::with_frame_info(frame, Vec::new());
                lz4.write_all(&records).map_err(|e| failed(&e))?;
                lz4.finish().map_err(|e| failed(&e))
            }
            Self::Zstd => zstd::bulk::compress(&records, 0).map_err(|e| failed(&e)),
        }
    }

    /// `packed`, a batch's records compressed with the codec `code`, uncompressed.
    #[cfg(any(test, feature = "testing"))]
    fn uncompress(code: i16, packed: &[u8]) -> Result<Vec<u8>, String> {
        use std::io::Read as _;
        let unreadable = |e: &dyn std::fmt::Display| format!("its compression can't be read: {e}");
        let mut out = Vec::new();
        match code {
            0 => out.extend_from_slice(packed),
            1 => {
                flate2::read::GzDecoder::new(packed)
                    .read_to_end(&mut out)
                    .map_err(|e| unreadable(&e))?;
            }
            2 => {
                out = snap::raw::Decoder::new()
                    .decompress_vec(packed)
                    .map_err(|e| unreadable(&e))?;
            }
            3 => {
                lz4_flex::frame::FrameDecoder::new(packed)
                    .read_to_end(&mut out)
                    .map_err(|e| unreadable(&e))?;
            }
            4 => out = zstd::stream::decode_all(packed).map_err(|e| unreadable(&e))?,
            codec => return Err(format!("compression {codec} isn't Kafka's")),
        }
        Ok(out)
    }
}

/// A request's or record's bytes, written in Kafka's types.
#[derive(Default)]
pub(crate) struct Writer(pub Vec<u8>);

impl Writer {
    pub(crate) fn i8(&mut self, n: i8) -> &mut Self {
        self.0.extend_from_slice(&n.to_be_bytes());
        self
    }

    pub(crate) fn i16(&mut self, n: i16) -> &mut Self {
        self.0.extend_from_slice(&n.to_be_bytes());
        self
    }

    pub(crate) fn i32(&mut self, n: i32) -> &mut Self {
        self.0.extend_from_slice(&n.to_be_bytes());
        self
    }

    pub(crate) fn i64(&mut self, n: i64) -> &mut Self {
        self.0.extend_from_slice(&n.to_be_bytes());
        self
    }

    /// A string, its length an `i16` first; `None` is null.
    pub(crate) fn string(&mut self, text: Option<&str>) -> Result<&mut Self, String> {
        match text {
            None => Ok(self.i16(-1)),
            Some(text) => {
                let size =
                    i16::try_from(text.len()).map_err(|_| "a name longer than Kafka takes")?;
                self.i16(size).0.extend_from_slice(text.as_bytes());
                Ok(self)
            }
        }
    }

    /// Bytes, their length an `i32` first.
    pub(crate) fn bytes(&mut self, bytes: &[u8]) -> Result<&mut Self, String> {
        self.i32(size(bytes.len())?).0.extend_from_slice(bytes);
        Ok(self)
    }

    /// A signed number as a zig-zag varint (a record's fields).
    pub(crate) fn varlong(&mut self, n: i64) -> &mut Self {
        #[expect(clippy::cast_sign_loss, reason = "zig-zag encoding")]
        let mut zigzag = ((n << 1) ^ (n >> 63)) as u64;
        loop {
            let byte = u8::try_from(zigzag & 0x7f).expect("seven bits");
            zigzag >>= 7;
            if zigzag == 0 {
                self.0.push(byte);
                return self;
            }
            self.0.push(byte | 0x80);
        }
    }

    /// Bytes as a record carries them: their length a varint first, `-1` for none.
    fn var_bytes(&mut self, bytes: Option<&[u8]>) -> &mut Self {
        match bytes {
            None => self.varlong(-1),
            Some(bytes) => {
                self.varlong(i64::try_from(bytes.len()).unwrap_or(i64::MAX))
                    .0
                    .extend_from_slice(bytes);
                self
            }
        }
    }
}

/// `n` as a Kafka length.
fn size(n: usize) -> Result<i32, String> {
    i32::try_from(n).map_err(|_| "larger than Kafka takes".to_owned())
}

/// A request, ready to write: its size, then header v1 (the API, its version, the
/// correlation id and the client's id), then `body`.
pub(crate) fn request(
    api: i16,
    version: i16,
    correlation: i32,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let mut header = Writer::default();
    header
        .i16(api)
        .i16(version)
        .i32(correlation)
        .string(Some(CLIENT_ID))?;
    let mut out = Writer(Vec::with_capacity(4 + header.0.len() + body.len()));
    out.i32(size(header.0.len() + body.len())?);
    out.0.extend_from_slice(&header.0);
    out.0.extend_from_slice(body);
    Ok(out.0)
}

/// An answer's fields, read in order.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let (head, rest) = self.bytes.split_first_chunk::<N>().ok_or(GARBLED)?;
        self.bytes = rest;
        Ok(*head)
    }

    fn slice(&mut self, n: usize) -> Result<&'a [u8], String> {
        let (head, rest) = self.bytes.split_at_checked(n).ok_or(GARBLED)?;
        self.bytes = rest;
        Ok(head)
    }

    pub(crate) fn i8(&mut self) -> Result<i8, String> {
        self.take().map(i8::from_be_bytes)
    }

    pub(crate) fn i16(&mut self) -> Result<i16, String> {
        self.take().map(i16::from_be_bytes)
    }

    pub(crate) fn i32(&mut self) -> Result<i32, String> {
        self.take().map(i32::from_be_bytes)
    }

    pub(crate) fn i64(&mut self) -> Result<i64, String> {
        self.take().map(i64::from_be_bytes)
    }

    /// A string; `None` when it's null.
    pub(crate) fn string(&mut self) -> Result<Option<&'a str>, String> {
        let Ok(n) = usize::try_from(self.i16()?) else {
            return Ok(None);
        };
        std::str::from_utf8(self.slice(n)?)
            .map(Some)
            .map_err(|_| GARBLED.to_owned())
    }

    /// Bytes; `None` when they're null.
    pub(crate) fn bytes(&mut self) -> Result<Option<&'a [u8]>, String> {
        let Ok(n) = usize::try_from(self.i32()?) else {
            return Ok(None);
        };
        self.slice(n).map(Some)
    }

    /// An array's length: each element must take at least `least` bytes, so a length
    /// larger than what's left is refused before anything is made for it.
    pub(crate) fn array(&mut self, least: usize) -> Result<usize, String> {
        let n = usize::try_from(self.i32()?).unwrap_or(0);
        if n.saturating_mul(least.max(1)) > self.bytes.len() {
            return Err(GARBLED.to_owned());
        }
        Ok(n)
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn varlong(&mut self) -> Result<i64, String> {
        let mut zigzag = 0u64;
        for shift in (0..70).step_by(7) {
            let [byte] = self.take()?;
            zigzag |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                #[expect(clippy::cast_possible_wrap, reason = "zig-zag decoding")]
                return Ok((zigzag >> 1) as i64 ^ -((zigzag & 1) as i64));
            }
        }
        Err(GARBLED.to_owned())
    }

    #[cfg(any(test, feature = "testing"))]
    fn var_bytes(&mut self) -> Result<Option<&'a [u8]>, String> {
        match usize::try_from(self.varlong()?) {
            Ok(n) => self.slice(n).map(Some),
            Err(_) => Ok(None),
        }
    }

    /// What's left.
    #[cfg(any(test, feature = "testing"))]
    pub(crate) const fn rest(&self) -> &'a [u8] {
        self.bytes
    }
}

/// Kafka's murmur2 (its Java client's, which picks a keyed record's partition).
pub(crate) fn murmur2(data: &[u8]) -> i32 {
    const M: u32 = 0x5bd1_e995;
    #[expect(clippy::cast_possible_truncation, reason = "as Java does")]
    let mut h = 0x9747_b28c_u32 ^ data.len() as u32;
    let (chunks, tail) = data.as_chunks::<4>();
    for chunk in chunks {
        let mut k = u32::from_le_bytes(*chunk);
        k = k.wrapping_mul(M);
        k ^= k >> 24;
        k = k.wrapping_mul(M);
        h = h.wrapping_mul(M) ^ k;
    }
    if !tail.is_empty() {
        for (i, byte) in tail.iter().enumerate().rev() {
            h ^= u32::from(*byte) << (8 * i);
        }
        h = h.wrapping_mul(M);
    }
    h ^= h >> 13;
    h = h.wrapping_mul(M);
    h ^= h >> 15;
    #[expect(clippy::cast_possible_wrap, reason = "Java's int")]
    let h = h as i32;
    h
}

/// The partition, of `partitions`, a record keyed `key` goes to: as Kafka's own clients
/// place it, so each object's events stay in order on one partition.
pub(crate) fn partition(key: &[u8], partitions: usize) -> usize {
    let positive = usize::try_from(murmur2(key) & 0x7fff_ffff).unwrap_or(0);
    positive % partitions.max(1)
}

/// A batch (v2) of one record, `key` and `value`, made at `timestamp` (milliseconds since
/// the epoch), its records compressed with `compression`.
pub(crate) fn record_batch(
    key: Option<&[u8]>,
    value: &[u8],
    timestamp: i64,
    compression: Compression,
) -> Result<Vec<u8>, String> {
    let mut record = Writer::default();
    record
        .i8(0) // attributes
        .varlong(0) // timestamp delta
        .varlong(0) // offset delta
        .var_bytes(key)
        .var_bytes(Some(value))
        .varlong(0); // headers
    let mut records = Writer::default();
    records
        .varlong(i64::try_from(record.0.len()).unwrap_or(i64::MAX))
        .0
        .extend_from_slice(&record.0);
    let records = compression.compress(records.0)?;
    // What the CRC covers: from the attributes to the end.
    let mut covered = Writer::default();
    covered
        .i16(compression.code())
        .i32(0) // last offset delta
        .i64(timestamp)
        .i64(timestamp)
        .i64(-1) // producer id
        .i16(-1) // producer epoch
        .i32(-1) // base sequence
        .i32(1); // records
    covered.0.extend_from_slice(&records);
    let crc = crc32c(&covered.0);
    let mut batch = Writer(Vec::with_capacity(covered.0.len() + 21));
    batch
        .i64(0) // base offset
        .i32(size(covered.0.len() + 9)?) // from the leader epoch to the end
        .i32(-1) // partition leader epoch
        .i8(2) // magic
        .0
        .extend_from_slice(&crc.to_be_bytes());
    batch.0.extend_from_slice(&covered.0);
    Ok(batch.0)
}

/// CRC-32C, as record batches are checked with.
fn crc32c(bytes: &[u8]) -> u32 {
    let mut digest = crc_fast::Digest::new(crc_fast::CrcAlgorithm::Crc32Iscsi);
    digest.update(bytes);
    u32::try_from(digest.finalize()).unwrap_or_default()
}

/// A record read back: its key and value.
#[cfg(any(test, feature = "testing"))]
pub(crate) type Record = (Option<Vec<u8>>, Option<Vec<u8>>);

/// The records of the batches in `bytes`, each batch's CRC checked and its records
/// uncompressed, as a broker reads them.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn read_batches(bytes: &[u8]) -> Result<Vec<Record>, String> {
    let mut records = Vec::new();
    let mut reader = Reader::new(bytes);
    while !reader.rest().is_empty() {
        let _base_offset = reader.i64()?;
        let length = usize::try_from(reader.i32()?).map_err(|_| GARBLED)?;
        let mut batch = Reader::new(reader.slice(length)?);
        let _leader_epoch = batch.i32()?;
        if batch.i8()? != 2 {
            return Err("not a v2 record batch".to_owned());
        }
        let crc = u32::from_be_bytes(batch.take()?);
        if crc32c(batch.rest()) != crc {
            return Err("its CRC doesn't match".to_owned());
        }
        let attributes = batch.i16()?;
        let _ = (batch.i32()?, batch.i64()?, batch.i64()?);
        let _ = (batch.i64()?, batch.i16()?, batch.i32()?);
        let count = batch.i32()?;
        let unpacked = Compression::uncompress(attributes & 7, batch.rest())?;
        let mut body = Reader::new(&unpacked);
        for _ in 0..count {
            let length = usize::try_from(body.varlong()?).map_err(|_| GARBLED)?;
            let mut record = Reader::new(body.slice(length)?);
            let _attributes = record.i8()?;
            let _ = (record.varlong()?, record.varlong()?);
            let key = record.var_bytes()?.map(<[u8]>::to_vec);
            let value = record.var_bytes()?.map(<[u8]>::to_vec);
            records.push((key, value));
        }
        if !body.rest().is_empty() {
            return Err("more records than the batch counts".to_owned());
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vectors of Kafka's own tests (`UtilsTest.java`).
    #[test]
    fn murmur2_is_kafkas() {
        for (key, hash) in [
            ("21", -973_932_308),
            ("foobar", -790_332_482),
            ("a-little-bit-long-string", -985_981_536),
            ("a-little-bit-longer-string", -1_486_304_829),
            (
                "lkjh234lh9fiuh90y23oiuhsafujhadof229phr9h19h89h8",
                -58_897_971,
            ),
            ("abc", 479_470_107),
        ] {
            assert_eq!(murmur2(key.as_bytes()), hash, "{key}");
        }
        assert_eq!(
            partition(b"21", 1000),
            1_173_551_340 % 1000,
            "made positive first"
        );
        assert_eq!(partition(b"abc", 1), 0);
        assert_eq!(partition(b"abc", 0), 0, "no partitions reads as one");
    }

    #[test]
    fn varints_are_zig_zag() {
        for (n, bytes) in [
            (0, &[0x00][..]),
            (-1, &[0x01]),
            (1, &[0x02]),
            (63, &[0x7e]),
            (-64, &[0x7f]),
            (64, &[0x80, 0x01]),
            (300, &[0xd8, 0x04]),
        ] {
            let mut out = Writer::default();
            out.varlong(n);
            assert_eq!(out.0, bytes, "{n}");
            assert_eq!(Reader::new(bytes).varlong(), Ok(n));
        }
        for n in [i64::MIN, i64::MAX, i64::from(i32::MIN)] {
            let mut out = Writer::default();
            out.varlong(n);
            assert_eq!(Reader::new(&out.0).varlong(), Ok(n));
        }
        assert!(Reader::new(&[0x80; 11]).varlong().is_err(), "too long");
        assert!(Reader::new(&[0x80]).varlong().is_err(), "cut short");
    }

    #[test]
    fn requests_carry_their_header() {
        let request = request(api::METADATA, 1, 7, &[9, 9]).unwrap();
        assert_eq!(
            request,
            [
                0, 0, 0, 17, // size
                0, 3, 0, 1, 0, 0, 0, 7, // api, version, correlation id
                0, 5, b't', b'e', b'i', b'f', b's', // client id
                9, 9
            ]
        );
    }

    #[test]
    fn answers_are_read_only_as_far_as_they_go() {
        let mut reader = Reader::new(&[0, 2, b'o', b'k', 0xff, 0xff, 0, 0, 0, 9]);
        assert_eq!(reader.string(), Ok(Some("ok")));
        assert_eq!(reader.string(), Ok(None));
        assert!(reader.array(1).is_err(), "nine elements in no bytes");
        assert!(Reader::new(&[0, 3, b'a']).string().is_err());
        assert!(Reader::new(&[0, 0, 0, 5, 1]).bytes().is_err());
        assert_eq!(Reader::new(&[0xff, 0xff, 0xff, 0xff]).bytes(), Ok(None));
    }

    #[test]
    fn batches_are_read_back_as_written() {
        for compression in ALL {
            let batch =
                record_batch(Some(b"b/k"), b"{\"a\":1}", 1_700_000_000_000, compression).unwrap();
            assert_eq!(batch[22] & 7, compression.name_code(), "{compression:?}");
            assert_eq!(batch[16], 2, "magic");
            assert_eq!(
                i32::from_be_bytes(batch[8..12].try_into().unwrap()),
                i32::try_from(batch.len() - 12).unwrap()
            );
            let read = read_batches(&batch).unwrap();
            assert_eq!(
                read,
                [(Some(b"b/k".to_vec()), Some(b"{\"a\":1}".to_vec()))],
                "{compression:?}"
            );
            let mut broken = batch.clone();
            *broken.last_mut().unwrap() ^= 1;
            assert!(read_batches(&broken).is_err(), "the CRC");
        }
        let keyless = record_batch(None, b"v", 0, Compression::None).unwrap();
        assert_eq!(
            read_batches(&keyless).unwrap(),
            [(None, Some(b"v".to_vec()))]
        );
    }

    /// A batch as Kafka's Java client writes it: the record's fields and the CRC of the
    /// bytes it covers, checked against values worked out by hand.
    #[test]
    fn batches_are_laid_out_as_kafka_writes_them() {
        let batch = record_batch(Some(b"k"), b"v", 1, Compression::None).unwrap();
        let expected_record = [
            0x10, // length 8
            0x00, // attributes
            0x00, 0x00, // timestamp and offset deltas
            0x02, b'k', // key
            0x02, b'v', // value
            0x00, // headers
        ];
        assert!(batch.ends_with(&expected_record), "{batch:?}");
        assert_eq!(batch.len(), 61 + expected_record.len());
        assert_eq!(&batch[21..23], [0, 0], "no compression");
        assert_eq!(crc32c(b"123456789"), 0xe306_9283, "CRC-32C's check value");
    }

    const ALL: [Compression; 5] = [
        Compression::None,
        Compression::Gzip,
        Compression::Snappy,
        Compression::Lz4,
        Compression::Zstd,
    ];

    impl Compression {
        fn name_code(self) -> u8 {
            u8::try_from(self.code()).unwrap()
        }
    }

    /// Each codec's output is what Kafka's own readers take: a Snappy block, an LZ4 frame
    /// of independent 64 KiB blocks (Kafka refuses linked ones), a Zstandard frame; and
    /// records larger than a block come back whole.
    #[test]
    fn records_are_compressed_as_kafka_reads_them() {
        let records: Vec<u8> = (0..300_000u32)
            .flat_map(|n| (n % 251).to_be_bytes())
            .collect();
        for compression in ALL {
            let packed = compression.compress(records.clone()).unwrap();
            if compression != Compression::None {
                assert!(
                    packed.len() < records.len() / 2,
                    "{compression:?} compresses"
                );
            }
            let code = compression.code();
            assert_eq!(Compression::uncompress(code, &packed).unwrap(), records);
        }
        let lz4 = Compression::Lz4.compress(records.clone()).unwrap();
        assert_eq!(lz4[..4], [0x04, 0x22, 0x4d, 0x18], "LZ4's frame magic");
        assert_eq!(
            lz4[4] & 0b1110_0011,
            0b0110_0000,
            "version 1, independent blocks"
        );
        assert_eq!(lz4[5], 0x40, "64 KiB blocks");
        let zstd = Compression::Zstd.compress(records.clone()).unwrap();
        assert_eq!(
            zstd[..4],
            [0x28, 0xb5, 0x2f, 0xfd],
            "Zstandard's frame magic"
        );
        let snappy = Compression::Snappy.compress(records).unwrap();
        assert_ne!(snappy[0], 0x82, "a block, not xerial's framing");
        assert!(Compression::uncompress(5, b"").is_err());
        assert_eq!(Compression::Zstd.produce_version(), 7);
        assert_eq!(Compression::Lz4.produce_version(), 3);
    }

    #[test]
    fn compressions_are_named() {
        assert_eq!(Compression::parse("GZIP"), Ok(Compression::Gzip));
        assert_eq!(
            Compression::parse("none").map(Compression::name),
            Ok("none")
        );
        assert!(Compression::parse("zip").is_err());
        for compression in ALL {
            assert_eq!(Compression::parse(compression.name()), Ok(compression));
        }
    }
}
