//! Bit and byte conversion helpers.
//!
//! This module contains low-level helpers corresponding to the `BitsToBytes`
//! and `BytesToBits` operations used in the FIPS specifications.
//!
//! Bits are packed little-endian within each byte: bit index `i` is stored at
//! byte `i / 8`, bit position `i % 8`.

/// Returns the number of bits needed to represent `x`.
///
/// This uses the convention `bitlen(0) = 1`.
#[must_use]
pub const fn bitlen_u32(x: u32) -> usize {
    if x == 0 {
        1
    } else {
        32usize - x.leading_zeros() as usize
    }
}

/// Converts a bit slice into bytes.
///
/// # Panics
///
/// Panics if `bits.len() != 8 * out.len()`, or if some bit is not `0` or `1`.
pub fn bits_to_bytes(bits: &[u8], out: &mut [u8]) {
    assert_eq!(bits.len(), 8 * out.len());

    out.fill(0);

    for (i, bit) in bits.iter().enumerate() {
        assert!(bit <= &1);
        out[i / 8] |= bit << (i % 8);
    }
}

/// Converts a byte slice into bits.
///
/// # Panics
///
/// Panics if `out.len()` is not exactly `8 * bytes.len()`.
pub fn bytes_to_bits(bytes: &[u8], out: &mut [u8]) {
    assert_eq!(8 * bytes.len(), out.len());

    for (i, bit) in out.iter_mut().enumerate() {
        *bit = (bytes[i / 8] >> (i % 8)) & 1;
    }
}

/// Returns bit `bit_index` from `bytes`, using little-endian bit order.
///
/// # Panics
///
/// Panics if `bit_index >= 8 * bytes_input.len()`.
#[must_use]
pub fn get_bit(bytes: &[u8], bit_index: usize) -> u8 {
    assert!(bit_index < 8 * bytes.len());
    bytes[bit_index / 8] >> (bit_index % 8) & 1
}

/// Writes the `alpha` least significant bits of `x` into `out`.
///
/// # Panics
///
/// Panics if `alpha == 0`, `alpha > 32`, or `out.len() != alpha`.
pub fn int_to_bits(x: u32, alpha: usize, out: &mut [u8]) {
    assert_eq!(out.len(), alpha);
    assert!(alpha > 0);
    assert!(alpha <= 32);

    for (j, bit) in out.iter_mut().enumerate() {
        *bit = ((x >> j) & 1) as u8;
    }
}

/// Interprets `bits` as a little-endian bit string.
///
/// `bits[0]` is the least significant bit.
///
/// # Panics
///
/// Panics if `bits.len() > 32`, or if some bit is not `0` or `1`.
#[must_use]
pub fn bits_to_int(bits: &[u8]) -> u32 {
    assert!(bits.len() <= 32);

    let mut x = 0u32;

    for (j, &bit) in bits.iter().enumerate() {
        assert!(bit <= 1);
        x |= (bit as u32) << j;
    }

    x
}

/// Writes the `alpha` least significant bytes of `x` into `out`.
///
/// # Panics
///
/// Panics if `alpha == 0`, `alpha > 4` or `out.len() != alpha`.
pub fn int_to_bytes(x: u32, alpha: usize, out: &mut [u8]) {
    assert!(alpha > 0);
    assert!(alpha <= 4);
    assert_eq!(out.len(), alpha);

    for (j, byte) in out.iter_mut().enumerate() {
        *byte = ((x >> (8 * j)) & 0xff) as u8;
    }
}

/// Packs fixed-width nonnegative integers into bytes.
///
/// Each integer is encoded using exactly `D` bits, least-significant bit first.
/// The resulting bit stream is then packed little-endian into bytes.
///
/// This is the common low-level operation behind:
///
/// - ML-KEM `ByteEncode_d`;
/// - ML-DSA `SimpleBitPack`;
/// - ML-DSA `BitPack`.
///
/// # Panics
///
/// Panics if:
///
/// - `D == 0`;
/// - `D > 31`;
/// - `values.len() * D != out.len() * 8`;
/// - any value is outside `[0, 2^D)`.
pub fn bit_pack<const D: usize>(values: &[i32], out: &mut [u8]) {
    assert!(D > 0);
    assert!(D <= 30);
    assert_eq!(values.len() * D, out.len() * 8);

    out.fill(0);

    let upper = 1i64 << D;
    let mut bit_pos = 0usize;

    for &value in values {
        assert!(value >= 0);
        assert!((value as i64) < upper);

        let x = value as u32;

        for j in 0..D {
            let bit = ((x >> j) & 1) as u8;
            out[bit_pos / 8] |= bit << (bit_pos % 8);
            bit_pos += 1;
        }
    }
}

/// Unpacks fixed-width nonnegative integers from bytes.
///
/// This is the inverse of `bit_pack`.
///
/// # Panics
///
/// Panics if:
///
/// - `D == 0`;
/// - `D > 31`;
/// - `input.len() * 8 != out.len() * D`.
pub fn bit_unpack<const D: usize>(input: &[u8], out: &mut [i32]) {
    assert!(D > 0);
    assert!(D <= 31);
    assert_eq!(input.len() * 8, out.len() * D);

    let mut bit_pos = 0usize;

    for value in out.iter_mut() {
        let mut acc = 0i32;

        for j in 0..D {
            let bit = (input[bit_pos / 8] >> (bit_pos % 8)) & 1;
            acc |= (bit as i32) << j;
            bit_pos += 1;
        }

        *value = acc;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitlen_u32_examples() {
        assert_eq!(bitlen_u32(0), 1);
        assert_eq!(bitlen_u32(1), 1);
        assert_eq!(bitlen_u32(2), 2);
        assert_eq!(bitlen_u32(3), 2);
        assert_eq!(bitlen_u32(4), 3);
        assert_eq!(bitlen_u32(1023), 10);
        assert_eq!(bitlen_u32(1024), 11);
    }

    #[test]
    fn bits_to_bytes_known_pattern() {
        let bits = [1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1];
        let mut out = [0u8; 2];

        bits_to_bytes(&bits, &mut out);

        assert_eq!(out, [0b0101_0101, 0b1010_1010]);
    }

    #[test]
    fn bytes_to_bits_known_pattern() {
        let bytes = [0b0101_0101u8, 0b1010_1010u8];
        let mut bits = [0u8; 16];

        bytes_to_bits(&bytes, &mut bits);

        assert_eq!(bits, [1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1,]);
    }

    #[test]
    fn bytes_bits_roundtrip() {
        let bytes = [0x00, 0x01, 0x80, 0xff, 0x42];
        let mut bits = [0u8; 40];
        let mut roundtrip = [0u8; 5];

        bytes_to_bits(&bytes, &mut bits);
        bits_to_bytes(&bits, &mut roundtrip);

        assert_eq!(roundtrip, bytes);
    }

    #[test]
    fn int_to_bits_and_bits_to_int_roundtrip() {
        let x = 0b1011_0010u32;
        let mut bits = [0u8; 8];

        int_to_bits(x, 8, &mut bits);

        assert_eq!(bits, [0, 1, 0, 0, 1, 1, 0, 1]);
        assert_eq!(bits_to_int(&bits), x);
    }

    #[test]
    fn int_to_bytes_little_endian() {
        let mut out = [0u8; 4];

        int_to_bytes(0x1234_5678, 4, &mut out);

        assert_eq!(out, [0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn bit_pack_known_values_d2() {
        let values = [1, 2, 3, 0];
        let mut out = [0u8; 1];

        bit_pack::<2>(&values, &mut out);

        // Values:
        // 1 -> bits 1,0
        // 2 -> bits 0,1
        // 3 -> bits 1,1
        // 0 -> bits 0,0
        //
        // Bit stream: 1,0,0,1,1,1,0,0
        assert_eq!(out, [0b0011_1001]);
    }

    #[test]
    fn bit_pack_and_unpack_roundtrip_d10() {
        let values = [0, 1, 2, 3, 17, 255, 511, 1023];
        let mut bytes = [0u8; 10];
        let mut decoded = [0i32; 8];

        bit_pack::<10>(&values, &mut bytes);
        bit_unpack::<10>(&bytes, &mut decoded);

        assert_eq!(decoded, values);
    }

    #[test]
    #[should_panic]
    fn bit_pack_rejects_negative_value() {
        let values = [0, -1, 2, 3];
        let mut out = [0u8; 1];

        bit_pack::<2>(&values, &mut out);
    }

    #[test]
    #[should_panic]
    fn bit_pack_rejects_value_too_large() {
        let values = [0, 1, 2, 4];
        let mut out = [0u8; 1];

        bit_pack::<2>(&values, &mut out);
    }
}
