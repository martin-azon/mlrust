//! ML-KEM symmetric primitives.
//!
//! This module provides the hash, XOF, PRF, and KDF-style wrappers used by
//! ML-KEM.
//!
//! The wrappers keep the rest of the implementation independent of the
//! concrete RustCrypto API and make the FIPS-level functions explicit.

use crate::symmetric::generic_funcs::{
    Shake128Reader, sha3_256, sha3_512, shake128_absorb_once, shake128_squeeze, shake256,
};

/// ML-KEM PRF.
///
/// Computes SHAKE256 over:
///
/// ```text
/// seed || nonce
/// ```
///
/// and writes `64 * ETA` bytes into `output`.
pub fn prf<const ETA: usize>(seed: &[u8; 32], nonce: u8, output: &mut [u8]) {
    assert_eq!(output.len(), 64 * ETA);

    let mut input = [0u8; 33];
    input[..32].copy_from_slice(seed);
    input[32] = nonce;
    shake256(&input, output);
}

/// ML-KEM hash function `H`.
///
/// Computes SHA3-256.
pub fn h(input: &[u8], output: &mut [u8; 32]) {
    sha3_256(input, output);
}

/// ML-KEM function `J`.
///
/// Computes SHAKE256 and writes 32 bytes.
pub fn j(input: &[u8], output: &mut [u8; 32]) {
    shake256(input, output);
}

/// ML-KEM function `J` over two input slices.
///
/// Computes SHAKE256 over:
///
/// ```text
/// left || right
/// ```
///
/// and writes 32 bytes.
pub fn j_concat(left: &[u8], right: &[u8], output: &mut [u8; 32]) {
    use shake::{
        Shake256,
        digest::{ExtendableOutput, Update as XofUpdate, XofReader},
    };

    let mut hasher = Shake256::default();

    XofUpdate::update(&mut hasher, left);
    XofUpdate::update(&mut hasher, right);

    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

/// ML-KEM hash function `G`.
///
/// Computes SHA3-512 and splits the 64-byte digest into two 32-byte outputs.
pub fn g(input: &[u8], output_left: &mut [u8; 32], output_right: &mut [u8; 32]) {
    let mut output = [0u8; 64];

    sha3_512(input, &mut output);

    output_left.copy_from_slice(&output[..32]);
    output_right.copy_from_slice(&output[32..]);
}

/// ML-KEM function `XOF.Absorb()`
pub fn xof_absorb(seed: &[u8]) -> Shake128Reader {
    shake128_absorb_once(seed)
}

/// ML-KEM function `XOF.Squeeze()`
pub fn xof_squeeze(reader: &mut Shake128Reader, output: &mut [u8]) {
    shake128_squeeze(reader, output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symmetric::generic_funcs::{sha3_256, sha3_512, shake128, shake256};

    #[test]
    fn h_matches_sha3_256() {
        let input = b"ML-KEM H test input";

        let mut got = [0u8; 32];
        let mut expected = [0u8; 32];

        h(input, &mut got);
        sha3_256(input, &mut expected);

        assert_eq!(got, expected);
    }

    #[test]
    fn g_matches_sha3_512_split() {
        let input = b"ML-KEM G test input";

        let mut left = [0u8; 32];
        let mut right = [0u8; 32];

        g(input, &mut left, &mut right);

        let mut digest = [0u8; 64];
        sha3_512(input, &mut digest);

        assert_eq!(&left[..], &digest[..32]);
        assert_eq!(&right[..], &digest[32..]);
    }

    #[test]
    fn j_matches_first_32_bytes_of_shake256() {
        let input = b"ML-KEM J test input";

        let mut got = [0u8; 32];
        let mut expected = [0u8; 32];

        j(input, &mut got);
        shake256(input, &mut expected);

        assert_eq!(got, expected);
    }

    #[test]
    fn prf_eta2_matches_shake256_seed_nonce() {
        let seed = [0x42u8; 32];
        let nonce = 7u8;

        let mut got = [0u8; 128];
        prf::<2>(&seed, nonce, &mut got);

        let mut input = [0u8; 33];
        input[..32].copy_from_slice(&seed);
        input[32] = nonce;

        let mut expected = [0u8; 128];
        shake256(&input, &mut expected);

        assert_eq!(got, expected);
    }

    #[test]
    fn prf_eta3_matches_shake256_seed_nonce() {
        let mut seed = [0u8; 32];

        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let nonce = 255u8;

        let mut got = [0u8; 192];
        prf::<3>(&seed, nonce, &mut got);

        let mut input = [0u8; 33];
        input[..32].copy_from_slice(&seed);
        input[32] = nonce;

        let mut expected = [0u8; 192];
        shake256(&input, &mut expected);

        assert_eq!(got, expected);
    }

    #[test]
    #[should_panic]
    fn prf_rejects_wrong_output_length() {
        let seed = [0u8; 32];
        let nonce = 0u8;

        let mut output = [0u8; 127];

        prf::<2>(&seed, nonce, &mut output);
    }

    #[test]
    fn xof_absorb_squeeze_matches_shake128_one_shot() {
        let input = b"ML-KEM XOF input";

        let mut got = [0u8; 96];

        let mut reader = xof_absorb(input);
        xof_squeeze(&mut reader, &mut got);

        let mut expected = [0u8; 96];
        shake128(input, &mut expected);

        assert_eq!(got, expected);
    }

    #[test]
    fn xof_multiple_squeezes_match_single_shake128_output() {
        let input = b"ML-KEM XOF streaming input";

        let mut expected = [0u8; 80];
        shake128(input, &mut expected);

        let mut reader = xof_absorb(input);

        let mut first = [0u8; 16];
        let mut second = [0u8; 64];

        xof_squeeze(&mut reader, &mut first);
        xof_squeeze(&mut reader, &mut second);

        assert_eq!(&first, &expected[..16]);
        assert_eq!(&second, &expected[16..]);
    }

    #[test]
    fn different_prf_nonces_give_different_outputs() {
        let seed = [0x13u8; 32];

        let mut out0 = [0u8; 128];
        let mut out1 = [0u8; 128];

        prf::<2>(&seed, 0, &mut out0);
        prf::<2>(&seed, 1, &mut out1);

        assert_ne!(out0, out1);
    }

    #[test]
    fn different_xof_inputs_give_different_outputs() {
        let mut out0 = [0u8; 64];
        let mut out1 = [0u8; 64];

        let mut reader0 = xof_absorb(b"input A");
        let mut reader1 = xof_absorb(b"input B");

        xof_squeeze(&mut reader0, &mut out0);
        xof_squeeze(&mut reader1, &mut out1);

        assert_ne!(out0, out1);
    }
}
