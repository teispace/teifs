//! `aws-chunked` request bodies (streaming SigV4 uploads, signed and unsigned, with
//! trailers), decoded by s3s as the server has it decode them. The first byte sets
//! whether chunks are signed and how the body arrives in pieces; the next two the length
//! the request declares.
#![no_main]

use bytes::Bytes;
use futures::{StreamExt, executor::block_on, stream};
use libfuzzer_sys::fuzz_target;
use s3s::{AmzDate, Sha256Sum, auth::SecretKey, stream::aws_chunked_stream::AwsChunkedStream};

/// The largest chunk s3s takes by default, which TeiFS keeps.
const MAX_CHUNK: usize = 256 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let [flags, len_hi, len_lo, body @ ..] = data else {
        return;
    };
    let unsigned = flags & 1 == 1;
    let piece = usize::from(flags >> 1).max(1);
    let declared = usize::from(u16::from_be_bytes([*len_hi, *len_lo]));
    let pieces: Vec<Result<Bytes, s3s::StdError>> = body
        .chunks(piece)
        .map(|p| Ok(Bytes::copy_from_slice(p)))
        .collect();
    let seed =
        Sha256Sum::from_hex("4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
            .expect("a valid SHA-256 in hex");
    let date = AmzDate::parse("20130524T000000Z").expect("a valid x-amz-date");
    let decoded = AwsChunkedStream::new(
        stream::iter(pieces),
        seed,
        date,
        "us-east-1".into(),
        "s3".into(),
        SecretKey::from("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        declared,
        unsigned,
        MAX_CHUNK,
    );
    block_on(async move {
        let mut decoded = std::pin::pin!(decoded);
        while let Some(item) = decoded.next().await {
            if item.is_err() {
                break;
            }
        }
    });
});
