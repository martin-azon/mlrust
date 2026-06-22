//! Bit and byte conversion helpers.
//!
//! This module contains low-level helpers corresponding to the `BitsToBytes`
//! and `BytesToBits` operations used in the FIPS specifications.
//!
//! Bits are packed little-endian within each byte: bit index `i` is stored at
//! byte `i / 8`, bit position `i % 8`.

/// Converts a bit slice into bytes.
///
/// # Panics
///
/// Panics if `bits.len()` is not exactly `8 * out.len()`.
pub fn bits_to_bytes(bits: &[u8], out: &mut [u8]) {
    assert_eq!(bits.len(), 8 * out.len());

    out.fill(0);

    for (i, bit) in bits.iter().enumerate() {
        debug_assert!(bit <= &1);

        let byte_index = i / 8;
        let bit_index = i % 8;
        out[byte_index] |= (bit & 1) << bit_index;
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
        let byte_index = i / 8;
        let bit_index = i % 8;

        *bit = (bytes[byte_index] >> bit_index) & 1;
    }
}

/// Returns the bit that would be at position `bit_index` in the array of bits
/// obtained by applying `bytes_to_bits` to the bytes array `bytes_input`.
///
/// # Panics
///
/// Panics if `bit_index >= 8 * bytes_input.len()`.
pub fn get_bit(bytes_input: &[u8], bit_index: usize) -> u8 {
    bytes_input[bit_index / 8] >> (bit_index % 8) & 1
}

/// Writes the `d` least significant bits of `x` into `out`,
/// least-significant bit first.
///
/// # Panics
///
/// Panics if `out.len() != d`.
pub fn int_to_bits(x: u32, alpha: usize, out: &mut [u8]) {
    assert_eq!(out.len(), alpha);
    assert!(alpha > 0);
    assert!(alpha <= 32);

    for (j, bit) in out.iter_mut().enumerate() {
        *bit = ((x >> j) & 1) as u8;
    }
}

/// Interprets `bits` as a little-endian bit string and returns the integer.
///
/// `bits[0]` is the least significant bit.
pub fn bits_to_int(bits: &[u8]) -> u32 {
    assert!(bits.len() <= 32);

    let mut x = 0u32;

    for (j, &bit) in bits.iter().enumerate() {
        assert!(bit <= 1);
        x |= ((bit & 1) as u32) << j;
    }

    x
}


pub fn int_to_bytes(x: u32, alpha: usize, out: &mut [u8]) {
    assert_eq!(out.len(), alpha);
    assert!(alpha > 0);

    for (j, byte) in out.iter_mut().enumerate() {
        *byte = ((x >> j) & 8) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
