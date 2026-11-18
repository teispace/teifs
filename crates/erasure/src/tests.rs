#![allow(clippy::cast_possible_truncation)] // test bytes are made by truncating on purpose

use std::io::{Cursor, Read, Seek, SeekFrom};

use proptest::prelude::*;

use crate::{Error, Geometry, HASH_LEN, HEADER_LEN, Header, Reader, encode, verify};

const ID: [u8; 16] = *b"0123456789abcdef";

fn bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((i * 31 + i / 251) % 256).unwrap())
        .collect()
}

fn shards(geometry: Geometry, data: &[u8]) -> Vec<Vec<u8>> {
    let mut sinks: Vec<Option<Vec<u8>>> = vec![Some(Vec::new()); geometry.shards()];
    let errors = encode(geometry, ID, data.len() as u64, &mut &data[..], &mut sinks).unwrap();
    assert!(errors.iter().all(Option::is_none));
    sinks.into_iter().map(Option::unwrap).collect()
}

fn reader(geometry: Geometry, shards: &[Vec<u8>], lost: &[usize]) -> Reader<Cursor<Vec<u8>>> {
    let sources = shards
        .iter()
        .enumerate()
        .map(|(i, s)| (!lost.contains(&i)).then(|| Cursor::new(s.clone())))
        .collect();
    Reader::open(ID, geometry, sources).unwrap()
}

fn read_all(mut r: impl Read) -> Vec<u8> {
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    out
}

#[test]
fn geometries_are_checked() {
    assert!(Geometry::new(0, 1, 16).is_err());
    assert!(Geometry::new(4, 0, 16).is_err());
    assert!(Geometry::new(200, 57, 16).is_err());
    assert!(Geometry::new(4, 2, 0).is_err());
    assert!(Geometry::new(4, 2, (64 << 20) + 1).is_err());
    assert!(Geometry::new(255, 1, 16).is_ok());
}

#[test]
fn shard_files_have_the_documented_length() {
    let g = Geometry::new(4, 2, 1000).unwrap();
    for len in [0usize, 1, 7, 999, 1000, 1001, 4321] {
        for shard in shards(g, &bytes(len)) {
            assert_eq!(shard.len() as u64, g.shard_file_len(len as u64), "{len}");
        }
    }
    // 1001 bytes: a block of 1000 (pieces of 250) and one of 1 (a piece of 2).
    assert_eq!(
        g.shard_file_len(1001),
        (HEADER_LEN + HASH_LEN + 250 + HASH_LEN + 2) as u64
    );
}

#[test]
fn headers_round_trip_and_damage_is_refused() {
    let header = Header {
        id: ID,
        index: 5,
        geometry: Geometry::new(4, 2, 1 << 20).unwrap(),
        len: 123_456_789,
    };
    let bytes = header.encode();
    assert_eq!(Header::decode(&bytes).unwrap(), header);
    for i in 0..HEADER_LEN {
        let mut bad = bytes;
        bad[i] ^= 0x40;
        assert!(Header::decode(&bad).is_err(), "byte {i}");
    }
    assert!(Header::decode(&bytes[..HEADER_LEN - 1]).is_err());
}

#[test]
fn losing_any_parity_count_of_shards_still_reads() {
    let g = Geometry::new(4, 2, 4096).unwrap();
    let data = bytes(3 * 4096 + 17);
    let all = shards(g, &data);
    for a in 0..6 {
        for b in a..6 {
            let mut r = reader(g, &all, &[a, b]);
            assert_eq!(read_all(&mut r), data, "lost {a} and {b}");
            let mut damaged = r.damaged().to_vec();
            damaged.sort_unstable();
            damaged.dedup();
            let mut lost = vec![a, b];
            lost.dedup();
            assert_eq!(damaged, lost);
        }
    }
}

#[test]
fn one_more_lost_shard_than_parity_fails() {
    let g = Geometry::new(4, 2, 4096).unwrap();
    let all = shards(g, &bytes(10_000));
    let sources = all
        .iter()
        .enumerate()
        .map(|(i, s)| (i >= 3).then(|| Cursor::new(s.clone())))
        .collect();
    match Reader::open(ID, g, sources) {
        Err(Error::NotEnoughShards {
            needed: 4,
            found: 3,
        }) => {}
        other => panic!("expected NotEnoughShards, got {other:?}"),
    }
}

#[test]
fn a_damaged_piece_is_found_and_read_around() {
    let g = Geometry::new(3, 2, 300).unwrap();
    let data = bytes(1000);
    let mut all = shards(g, &data);
    // Flip a byte of block 2's piece in data shard 1.
    let at = usize::try_from(g.piece_offset(2)).unwrap() + HASH_LEN + 7;
    all[1][at] ^= 1;
    let mut r = reader(g, &all, &[]);
    assert_eq!(read_all(&mut r), data);
    assert_eq!(r.damaged(), &[1]);
    let mut broken = Cursor::new(all[1].clone());
    assert!(matches!(verify(ID, g, &mut broken), Err(Error::Shard(_))));
    let mut good = Cursor::new(all[0].clone());
    assert_eq!(verify(ID, g, &mut good).unwrap().len, 1000);
}

#[test]
fn shards_in_the_wrong_place_or_of_another_file_are_handled() {
    let g = Geometry::new(2, 2, 64).unwrap();
    let data = bytes(500);
    let mut all = shards(g, &data);
    all.reverse();
    // Order doesn't matter: each header says which shard it is.
    assert_eq!(read_all(reader(g, &all, &[])), data);
    // Another file's shards are ignored.
    let other = {
        let mut sinks: Vec<Option<Vec<u8>>> = vec![Some(Vec::new()); 4];
        encode(g, *b"fedcba9876543210", 500, &mut &data[..], &mut sinks).unwrap();
        sinks.into_iter().map(Option::unwrap).collect::<Vec<_>>()
    };
    let mixed = vec![
        Some(Cursor::new(all[0].clone())),
        Some(Cursor::new(other[1].clone())),
        Some(Cursor::new(other[2].clone())),
        Some(Cursor::new(all[3].clone())),
    ];
    let r = Reader::open(ID, g, mixed).unwrap();
    assert_eq!(r.damaged().len(), 2);
    assert_eq!(read_all(r), data);
    // A truncated shard is damaged, and the others carry the read.
    let mut cut = all.clone();
    let half = cut[0].len() / 2;
    cut[0].truncate(half);
    let mut r = reader(g, &cut, &[]);
    assert_eq!(read_all(&mut r), data);
    let mut trailing = Cursor::new([all[1].clone(), vec![0]].concat());
    assert!(verify(ID, g, &mut trailing).is_err());
}

#[test]
fn a_stale_shard_of_another_length_is_outvoted() {
    let g = Geometry::new(2, 1, 64).unwrap();
    let new = bytes(200);
    let old = bytes(150);
    let mut all = shards(g, &new);
    all[2] = shards(g, &old)[2].clone();
    let r = reader(g, &all, &[]);
    assert_eq!(r.len(), 200);
    assert_eq!(r.damaged(), &[2]);
    assert_eq!(read_all(r), new);
}

#[test]
fn seeks_read_ranges() {
    let g = Geometry::new(4, 2, 1024).unwrap();
    let data = bytes(10_000);
    let all = shards(g, &data);
    let mut r = reader(g, &all, &[0, 5]);
    for (start, len) in [
        (0usize, 10usize),
        (1020, 10),
        (4096, 3000),
        (9990, 10),
        (9999, 1),
    ] {
        r.seek(SeekFrom::Start(start as u64)).unwrap();
        let mut out = vec![0; len];
        r.read_exact(&mut out).unwrap();
        assert_eq!(out, &data[start..start + len]);
    }
    assert_eq!(r.seek(SeekFrom::End(-1)).unwrap(), 9999);
    r.seek(SeekFrom::Start(20_000)).unwrap();
    assert_eq!(read_all(&mut r), Vec::<u8>::new());
    assert!(r.seek(SeekFrom::Current(-30_000)).is_err());
}

#[test]
fn missing_shards_are_rebuilt_byte_for_byte() {
    let g = Geometry::new(4, 2, 1000).unwrap();
    let all = shards(g, &bytes(4500));
    for lost in [[0, 1], [1, 4], [4, 5]] {
        let mut r = reader(g, &all, &lost);
        for i in lost {
            let mut out = Vec::new();
            r.write_shard(i, &mut out).unwrap();
            assert_eq!(out, all[i], "shard {i}");
        }
    }
}

#[test]
fn an_empty_file_is_headers_only() {
    let g = Geometry::new(2, 2, 1 << 20).unwrap();
    let all = shards(g, &[]);
    assert!(all.iter().all(|s| s.len() == HEADER_LEN));
    let r = reader(g, &all, &[0, 1]);
    assert!(r.is_empty());
    assert_eq!(read_all(r), Vec::<u8>::new());
}

#[test]
fn a_failing_writer_is_dropped_and_the_rest_written() {
    struct Full;
    impl std::io::Write for Full {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("full"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    enum Sink {
        Ok(Vec<u8>),
        Full(Full),
    }
    impl std::io::Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            match self {
                Self::Ok(v) => v.write(b),
                Self::Full(f) => f.write(b),
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let g = Geometry::new(2, 1, 64).unwrap();
    let data = bytes(300);
    let mut sinks = vec![
        Some(Sink::Ok(Vec::new())),
        Some(Sink::Full(Full)),
        Some(Sink::Ok(Vec::new())),
    ];
    let errors = encode(g, ID, 300, &mut &data[..], &mut sinks).unwrap();
    assert!(errors[0].is_none() && errors[1].is_some() && errors[2].is_none());
    assert!(sinks[1].is_none());
    let sources = sinks
        .into_iter()
        .map(|s| match s {
            Some(Sink::Ok(v)) => Some(Cursor::new(v)),
            _ => None,
        })
        .collect();
    assert_eq!(read_all(Reader::open(ID, g, sources).unwrap()), data);
    // A source that ends early fails the encoding.
    let mut sinks: Vec<Option<Vec<u8>>> = vec![Some(Vec::new()); 3];
    assert!(encode(g, ID, 301, &mut &data[..], &mut sinks).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn any_geometry_survives_losing_parity_shards(
        data in 1usize..=12,
        parity in 1usize..=4,
        block in 1usize..=700,
        len in 0usize..3000,
        seed in any::<u64>(),
    ) {
        let g = Geometry::new(data, parity, block).unwrap();
        let bytes: Vec<u8> = (0..len).map(|i| (seed.rotate_left(i as u32 % 64) as u8) ^ (i as u8)).collect();
        let all = shards(g, &bytes);
        // Lose `parity` shards picked by the seed.
        let mut lost = Vec::new();
        let mut s = seed;
        while lost.len() < parity {
            let i = usize::try_from(s % g.shards() as u64).unwrap();
            if !lost.contains(&i) {
                lost.push(i);
            }
            s = s.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        }
        prop_assert_eq!(read_all(reader(g, &all, &lost)), bytes);
    }
}
