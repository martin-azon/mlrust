//! Generic hash and XOF wrappers.
//!
//! This module provides small allocation-free wrappers around the RustCrypto
//! SHA3 and SHAKE implementations.

use sha3::{Digest as Sha3Digest, Sha3_256, Sha3_512};
use shake::{
    Shake128, Shake256,
    digest::{ExtendableOutput, Update as XofUpdate, XofReader},
};

/// Computes SHA3-256 over `input`.
pub fn sha3_256(input: &[u8], output: &mut [u8; 32]) {
    let mut hasher = Sha3_256::new();

    Sha3Digest::update(&mut hasher, input);

    let digest = hasher.finalize();
    output.copy_from_slice(&digest);
}

/// Computes SHA3-512 over `input`.
pub fn sha3_512(input: &[u8], output: &mut [u8; 64]) {
    let mut hasher = Sha3_512::new();

    Sha3Digest::update(&mut hasher, input);

    let digest = hasher.finalize();
    output.copy_from_slice(&digest);
}

/// Computes SHAKE128 over `input` and writes `output.len()` bytes.
#[allow(dead_code)]
pub fn shake128(input: &[u8], output: &mut [u8]) {
    let mut hasher = Shake128::default();
    XofUpdate::update(&mut hasher, input);

    let mut reader = hasher.finalize_xof();
    reader.read(output)
}

/// Computes SHAKE256 over `input` and writes `output.len()` bytes.
pub fn shake256(input: &[u8], output: &mut [u8]) {
    let mut hasher = Shake256::default();
    XofUpdate::update(&mut hasher, input);

    let mut reader = hasher.finalize_xof();
    reader.read(output)
}

/// SHAKE128 reader after absorption has been finalized.
pub type Shake128Reader = <Shake128 as ExtendableOutput>::Reader;

/// Initializes SHAKE128 and absorbs `input`.
#[must_use]
pub fn shake128_absorb(input: &[u8]) -> Shake128Reader {
    let mut hasher = Shake128::default();

    XofUpdate::update(&mut hasher, input);

    hasher.finalize_xof()
}

/// Squeezes bytes from a SHAKE128 reader.
pub fn shake128_squeeze(reader: &mut Shake128Reader, output: &mut [u8]) {
    reader.read(output);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex byte"),
        }
    }

    fn assert_hex_eq(actual: &[u8], expected_hex: &str) {
        assert_eq!(expected_hex.len(), 2 * actual.len());

        for (i, pair) in expected_hex.as_bytes().chunks_exact(2).enumerate() {
            let expected = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);

            assert_eq!(
                actual[i], expected,
                "byte mismatch at index {i}: got {:02x}, expected {:02x}",
                actual[i], expected
            );
        }
    }

    #[test]
    fn sha3_256_empty_matches_known_vector() {
        let mut out = [0u8; 32];

        sha3_256(b"", &mut out);

        assert_hex_eq(
            &out,
            "a7ffc6f8bf1ed76651c14756a061d662\
             f580ff4de43b49fa82d80a4b80f8434a",
        );
    }

    #[test]
    fn sha3_512_empty_matches_known_vector() {
        let mut out = [0u8; 64];

        sha3_512(b"", &mut out);

        assert_hex_eq(
            &out,
            "a69f73cca23a9ac5c8b567dc185a756e\
             97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558\
             f500199d95b6d3e301758586281dcd26",
        );
    }

    #[test]
    fn shake128_empty_32_bytes_matches_known_vector() {
        let mut out = [0u8; 32];

        shake128(b"", &mut out);

        assert_hex_eq(
            &out,
            "7f9c2ba4e88f827d616045507605853e\
             d73b8093f6efbc88eb1a6eacfa66ef26",
        );
    }

    #[test]
    fn shake256_empty_64_bytes_matches_known_vector() {
        let mut out = [0u8; 64];

        shake256(b"", &mut out);

        assert_hex_eq(
            &out,
            "46b9dd2b0ba88d13233b3feb743eeb24\
             3fcd52ea62b81b82b50c27646ed5762f\
             d75dc4ddd8c0f200cb05019d67b592f6\
             fc821c49479ab48640292eacb3b7c4be",
        );
    }

    #[test]
    fn shake128_absorb_squeeze_matches_one_shot() {
        let input = b"mlrust shake128 test input";

        let mut one_shot = [0u8; 96];
        shake128(input, &mut one_shot);

        let mut reader = shake128_absorb(input);
        let mut streamed = [0u8; 96];

        shake128_squeeze(&mut reader, &mut streamed);

        assert_eq!(streamed, one_shot);
    }

    #[test]
    fn shake128_multiple_squeezes_match_single_squeeze() {
        let input = b"mlrust shake128 streaming test";

        let mut one_shot = [0u8; 96];
        shake128(input, &mut one_shot);

        let mut reader = shake128_absorb(input);

        let mut first = [0u8; 32];
        let mut second = [0u8; 64];

        shake128_squeeze(&mut reader, &mut first);
        shake128_squeeze(&mut reader, &mut second);

        assert_eq!(&one_shot[..32], &first);
        assert_eq!(&one_shot[32..], &second);
    }

    #[test]
    fn shake_outputs_respect_requested_length() {
        let input = b"same input";

        let mut short = [0u8; 16];
        let mut long = [0u8; 64];

        shake256(input, &mut short);
        shake256(input, &mut long);

        assert_eq!(&short, &long[..16]);
    }

    #[test]
    fn fixed_output_hashes_are_deterministic() {
        let input = b"determinism test";

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];

        sha3_256(input, &mut a);
        sha3_256(input, &mut b);

        assert_eq!(a, b);

        let mut c = [0u8; 64];
        let mut d = [0u8; 64];

        sha3_512(input, &mut c);
        sha3_512(input, &mut d);

        assert_eq!(c, d);
    }
}
