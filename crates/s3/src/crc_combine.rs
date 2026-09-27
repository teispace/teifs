//! Combining the CRCs of consecutive pieces into the CRC of the whole, without the bytes:
//! how a multipart upload gets a full-object CRC32, CRC32C or CRC64NVME from its parts'
//! (which also works when the parts are stored encrypted). The method is zlib's
//! `crc32_combine` (multiplication modulo the polynomial), for any reflected CRC whose
//! initial value and final XOR are all ones, as these three are.

/// A reflected CRC: its width in bits and its reversed polynomial.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Crc {
    width: u32,
    poly: u64,
}

pub(crate) const CRC32: Crc = Crc {
    width: 32,
    poly: 0xEDB8_8320,
};
pub(crate) const CRC32C: Crc = Crc {
    width: 32,
    poly: 0x82F6_3B78,
};
pub(crate) const CRC64NVME: Crc = Crc {
    width: 64,
    poly: 0x9A6C_9329_AC4B_C9B5,
};

impl Crc {
    /// The CRC for an S3 algorithm name, if it can be combined.
    pub(crate) fn for_algorithm(name: &str) -> Option<Self> {
        match name {
            "CRC32" => Some(CRC32),
            "CRC32C" => Some(CRC32C),
            "CRC64NVME" => Some(CRC64NVME),
            _ => None,
        }
    }

    /// Its size in bytes.
    pub(crate) fn bytes(self) -> usize {
        (self.width / 8) as usize
    }

    /// `x^0`, in the reflected representation (the top bit).
    fn one(self) -> u64 {
        1 << (self.width - 1)
    }

    /// `a * b` modulo the polynomial.
    fn multiply(self, a: u64, mut b: u64) -> u64 {
        let mut m = self.one();
        let mut product = 0;
        loop {
            if a & m != 0 {
                product ^= b;
                if a & (m - 1) == 0 {
                    break;
                }
            }
            m >>= 1;
            if m == 0 {
                break;
            }
            b = if b & 1 == 1 {
                (b >> 1) ^ self.poly
            } else {
                b >> 1
            };
        }
        product
    }

    /// `x^(8·len)` modulo the polynomial: the shift over `len` bytes.
    fn shift(self, len: u64) -> u64 {
        // x^(2^k), starting at x^(2^3) = x^8 (one byte).
        let mut power = self.one() >> 1; // x^1
        for _ in 0..3 {
            power = self.multiply(power, power);
        }
        let mut result = self.one();
        let mut n = len;
        while n != 0 {
            if n & 1 == 1 {
                result = self.multiply(power, result);
            }
            n >>= 1;
            power = self.multiply(power, power);
        }
        result
    }

    /// The CRC of `a` then `b`, from the CRC of `a`, the CRC of `b` and `b`'s length.
    pub(crate) fn combine(self, crc_a: u64, crc_b: u64, len_b: u64) -> u64 {
        self.multiply(self.shift(len_b), crc_a) ^ crc_b
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};

    use super::*;
    use crate::checksums;

    const ALL: [(&str, Crc); 3] = [
        ("CRC32", CRC32),
        ("CRC32C", CRC32C),
        ("CRC64NVME", CRC64NVME),
    ];

    fn crc_of(algorithm: &str, bytes: &[u8]) -> u64 {
        let mut hasher = checksums::hasher(&checksums::Sums::new(), Some(algorithm)).unwrap();
        hasher.update(bytes);
        let b64 = checksums::from_dto(&hasher.finalize())
            .remove(algorithm)
            .unwrap();
        STANDARD
            .decode(b64)
            .unwrap()
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
    }

    #[test]
    fn combined_crcs_equal_the_crc_of_the_joined_bytes() {
        let data: Vec<u8> = (0..70_000u32).map(|i| (i * 31 % 251) as u8).collect();
        for (name, crc) in ALL {
            for split in [0, 1, 7, 4096, 65_536, data.len()] {
                let (a, b) = data.split_at(split);
                let combined = crc.combine(crc_of(name, a), crc_of(name, b), b.len() as u64);
                assert_eq!(combined, crc_of(name, &data), "{name} split at {split}");
            }
        }
    }

    #[test]
    fn many_pieces_combine_in_order() {
        let pieces: [&[u8]; 4] = [b"hello ", b"", b"multipart ", b"world"];
        let whole: Vec<u8> = pieces.concat();
        for (name, crc) in ALL {
            let mut acc = crc_of(name, pieces[0]);
            for piece in &pieces[1..] {
                acc = crc.combine(acc, crc_of(name, piece), piece.len() as u64);
            }
            assert_eq!(acc, crc_of(name, &whole));
        }
    }
}
