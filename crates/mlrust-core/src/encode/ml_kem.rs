//! ML-KEM coefficient compression and decompression.
//!
//! This module implements the coefficient-level compression primitives used by
//! ML-KEM over the modulus `q = 3329`.
//!
//! These operations are lossy for `D < 12`. They are used by ML-KEM ciphertext
//! compression and by the byte encoding of compressed polynomial coefficients.


use crate::params::{RingParams, Q3329};


/// Packs fixed-width unsigned integers into a byte slice.
///
/// This corresponds to the function ByteEncode_d from FIPS 203
///
/// # Panics
///
/// Panics if:
///
/// - `D == 0`;
/// - `D > 12`;
/// - `int_values.len() * D != output_bytes.len() * 8`.
pub fn pack_bits<const D: usize>(
    int_values: &[u32],
    output_bytes: &mut [u8],
) {
    assert!(D > 0);
    assert!(D <= 12);
    assert_eq!(int_values.len() * D, output_bytes.len() * 8);

    output_bytes.fill(0);
    let mut bit_pos = 0usize;

    for &value in int_values {
        debug_assert!(value < (1u32 << D));

        for j in 0..D {
            let bit = (value >> j) & 1;
            let byte_index = bit_pos / 8;
            let bit_index = bit_pos % 8;

            output_bytes[byte_index] |= (bit as u8) << bit_index;
            bit_pos += 1;
        }
    }
}


/// Unpacks fixed-width unsigned values from a byte slice.
///
/// This corresponds to the function ByteDecode_d from FIPS 203
pub fn unpack_bits<const D: usize> (
    byt_values: &[u8],
    output_ints: &mut [u32],
) {
    assert!(D > 0);
    assert!(D <= 12);
    assert_eq!(byt_values.len() * 8, output_ints.len() * D);

    let mut bit_pos = 0usize;

    for intg in output_ints.iter_mut() {
        let mut acc = 0u32;

        for k in 0..D {
            let byte_index = bit_pos / 8;
            let bit_index = bit_pos % 8;

            let bit = (byt_values[byte_index] >> bit_index) & 1;
            acc |= (bit as u32) << k;

            bit_pos += 1;
        }

        *intg = acc;
    }
}


fn round_div_u64(num: u64, den: u64) -> u64 {
    assert_ne!(den, 0);

    (num + den / 2) / den
}

/// Helper function that compresses an integer modulo `q` to `D` bits.
fn compress_q<const D: usize, P: RingParams> (x: i32) -> u16 {
    assert!(D > 0);
    assert!(D <= 16);

    let q = P::Q as u64;
    let x = P::freeze(x) as u64;
    let scale = 1u64 << D;

    let rounded = round_div_u64(scale * x , q);

    (rounded & (scale - 1)) as u16
}

/// Helper function that decompresses `D` bits into an integer modulo `q`.
fn decompress_q<const D: usize, P: RingParams> (y: u16) -> i32 {
    debug_assert!(D > 0);
    debug_assert!(D <= 16);

    let q = P::Q as u64;
    let scale = 1u64 << D;
    let y = (y as u64) & (scale - 1);

    round_div_u64(q * y, scale) as i32
}


/// Compresses a `q = 3329` coefficient to `D` bits.
///
/// ```text
/// Compress_d(x) = round((2^d / q) * x) mod 2^d
/// ```
#[must_use]
pub fn compress_q3329<const D: usize>(x: i32) -> u16 {
    compress_q::<D, Q3329>(x)
}

/// Decompresses a `D`-bit value to a `q = 3329` coefficient.
///
/// ```text
/// Decompress_d(y) = round((q / 2^d) * y)
/// ```
#[must_use]
pub fn decompress_q3329<const D: usize>(y: u16) -> i32 {
    decompress_q::<D, Q3329>(y)
}



#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn pack_unpack_bits_d1() {
        let values = [0u32, 1, 1, 0, 1, 0, 0, 1];
        let mut bytes = [0u8; 1];
        let mut recovered = [0u32; 8];

        pack_bits::<1>(&values, &mut bytes);
        unpack_bits::<1>(&bytes, &mut recovered);

        assert_eq!(recovered, values);
    }

    #[test]
    fn pack_unpack_bits_d4() {
        let values = [0u32, 1, 2, 3, 4, 5, 14, 15];
        let mut bytes = [0u8; 4];
        let mut recovered = [0u32; 8];

        pack_bits::<4>(&values, &mut bytes);
        unpack_bits::<4>(&bytes, &mut recovered);

        assert_eq!(recovered, values);
    }

    #[test]
    fn pack_unpack_bits_d10() {
        let values = [0u32, 1, 2, 511, 512, 777, 1022, 1023];
        let mut bytes = [0u8; 10];
        let mut recovered = [0u32; 8];

        pack_bits::<10>(&values, &mut bytes);
        unpack_bits::<10>(&bytes, &mut recovered);

        assert_eq!(recovered, values);
    }

    #[test]
    fn pack_bits_d4_known_output() {
        let values = [0x1u32, 0x2, 0x3, 0x4];
        let mut bytes = [0u8; 2];

        pack_bits::<4>(&values, &mut bytes);

        // Low nibble is first value, high nibble is second value.
        assert_eq!(bytes, [0x21, 0x43]);
    }

    #[test]
    fn compress_q3329_outputs_fit_in_d_bits() {
        for d in [1usize, 4, 5, 10, 11, 12] {
            for x in 0..Q3329::Q {
                let c = match d {
                    1 => compress_q3329::<1>(x),
                    4 => compress_q3329::<4>(x),
                    5 => compress_q3329::<5>(x),
                    10 => compress_q3329::<10>(x),
                    11 => compress_q3329::<11>(x),
                    12 => compress_q3329::<12>(x),
                    _ => unreachable!(),
                };

                assert!(c < (1u16 << d), "d = {d}, x = {x}, c = {c}");
            }
        }
    }

    #[test]
    fn decompress_q3329_outputs_in_range() {
        for y in 0..(1u16 << 12) {
            let x = decompress_q3329::<12>(y);

            assert!(0 <= x && x <= Q3329::Q);
        }
    }

    #[test]
    fn compress_decompress_are_reasonable_q3329() {
        for d in [1usize, 4, 5, 10, 11] {
            let max = 1u16 << d;

            for y in 0..max {
                let x = match d {
                    1 => decompress_q3329::<1>(y),
                    4 => decompress_q3329::<4>(y),
                    5 => decompress_q3329::<5>(y),
                    10 => decompress_q3329::<10>(y),
                    11 => decompress_q3329::<11>(y),
                    _ => unreachable!(),
                };

                let y2 = match d {
                    1 => compress_q3329::<1>(x),
                    4 => compress_q3329::<4>(x),
                    5 => compress_q3329::<5>(x),
                    10 => compress_q3329::<10>(x),
                    11 => compress_q3329::<11>(x),
                    _ => unreachable!(),
                };

                assert_eq!(y2, y, "d = {d}, y = {y}, x = {x}");
            }
        }
    }
}