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
        debug_assert!(bits[i] <= 1);

        let byte_index = i / 8;
        let bit_index = i % 8;
        out[byte_index] |= (bits[i] & 1) << bit_index;

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


/// Writes the `d` least significant bits of `x` into `out`,
/// least-significant bit first.
///
/// # Panics
///
/// Panics if `out.len() != d`.
pub fn int_to_bits(x: u32, d: usize, out: &mut [u8]) {
    assert_eq!(out.len(), d);
    assert!(d <= 32);

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



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_to_bytes_known_pattern() {
        let bits = [
            1, 0, 1, 0, 1, 0, 1, 0,
            0, 1, 0, 1, 0, 1, 0, 1,
        ];
        let mut out = [0u8; 2];

        bits_to_bytes(&bits, &mut out);

        assert_eq!(out, [0b0101_0101, 0b1010_1010]);
    }

    #[test]
    fn bytes_to_bits_known_pattern() {
        let bytes = [0b0101_0101u8, 0b1010_1010u8];
        let mut bits = [0u8; 16];

        bytes_to_bits(&bytes, &mut bits);

        assert_eq!(
            bits,
            [
                1, 0, 1, 0, 1, 0, 1, 0,
                0, 1, 0, 1, 0, 1, 0, 1,
            ]
        );
    }

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
}