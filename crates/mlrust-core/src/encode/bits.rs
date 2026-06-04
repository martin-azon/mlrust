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

    for i in 0..bits.len() {
        let byte_index = i / 8;
        let bit_index = i % 8;
        out[byte_index] |= (bits[i] & 1) << bit_index;

    }
}


/// Converts a byte slice into bits.
///
/// # Panics
///
/// Panics if `bits.len()` is not exactly `8 * out.len()`.
pub fn bytes_to_bits(bytes: &[u8], out: &mut [u8]) {
    assert_eq!(8 * bytes.len(), out.len());

    for (i, bit) in out.iter_mut().enumerate() {
        let byte_index = i / 8;
        let bit_index = i % 8;

        *bit = (bytes[byte_index] >> bit_index) & 1;
    }
}


/// Writes the `d` least significant bits of `x` into `out`,
/// least-significant bit first.
///
/// # Panics
///
/// Panics if `out.len() != d`.
pub fn int_to_bits(x: u32, d: usize, out: &mut [u8]) {
    assert_eq!(out.len(), d);

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
        x |= ((bit & 1) as u32) << j;
    }

    x
}


pub fn pack_bits<const D: usize>(
    values: &[u32],
    out: &mut [u8],
) {
    assert_eq!(values.len(), 8 * out.len());

    // let mut bits = [0u8; 256 * D];

    for i in 0..256 {
        let mut a = values[i];
        for j in 0..D {

        }
    }
}

























