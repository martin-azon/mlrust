//! ML-DSA bit packing and unpacking. 


use crate::params::{Q8380417, N};
use crate::encode::bits::{bit_pack, bit_unpack, bitlen_u32};
use crate::poly::Poly;


/// FIPS 204 `SimpleBitPack(w, b)`.
///
/// Packs 256 coefficients in `[0, b]`, using `D = bitlen(b)` bits per
/// coefficient.
///
/// This writes directly to `out`; it does not allocate the intermediate bit
/// string from the FIPS pseudocode.
///
/// # Panics
///
/// Panics if:
///
/// - `b <= 0`;
/// - `D != bitlen(b)`;
/// - `out.len() != 32 * D`;
/// - some coefficient is outside `[0, b]`.
pub fn simple_bit_pack_q8380417<const D: usize>(
    coeffs: &[i32; N],
    b: i32,
    out: &mut [u8]
) {
    assert!(b > 0);
    assert_eq!(D, bitlen_u32(b as u32));
    assert_eq!(out.len(), 32 * D);

    for &c in coeffs {
        assert!(0 <= c);
        assert!(c <= b);
    }

    bit_pack::<D>(coeffs, out);
}



/// FIPS 204 `BitPack(w, a, b)`.
///
/// Packs 256 coefficients in `[-a, b]`, using `D = bitlen(a + b)` bits per
/// coefficient.
///
/// Each coefficient `w_i` is first mapped to the nonnegative integer:
///
/// ```text
/// y_i = b - w_i
/// ```
///
/// Then the `y_i` are packed using the shared fixed-width bit packer.
///
/// # Panics
///
/// Panics if:
///
/// - `a < 0` or `b < 0`;
/// - `a + b <= 0`;
/// - `D != bitlen(a + b)`;
/// - `out.len() != 32 * D`;
/// - some coefficient is outside `[-a, b]`.
pub fn bit_pack_signed_q8380417<const D: usize>(
    coeffs: &[i32; N],
    a: i32,
    b: i32,
    out: &mut [u8]
) {
    assert!(a >= 0);
    assert!(b >= 0);
    assert!(a + b > 0);
    assert_eq!(D, bitlen_u32((a + b) as u32));
    assert_eq!(out.len(), 32 * D);

    let mut values = [0i32; N];

    for (value, &coeff) in values.iter_mut().zip(coeffs.iter()) {
        assert!(-a <= coeff);
        assert!(coeff <= b);
        *value = b - coeff;
    }

    bit_pack::<D>(&values, out);
}


/// FIPS 204 `SimpleBitUnpack(v, b)`.
///
/// Decodes 256 coefficients by reading `D = bitlen(b)` bits per coefficient.
///
/// The output coefficients are in `[0, 2^D - 1]`. They are not necessarily in
/// `[0, b]` if the input byte string is malformed and `b + 1` is not a power
/// of two.
///
/// # Panics
///
/// Panics if:
///
/// - `b <= 0`;
/// - `D != bitlen(b)`;
/// - `input.len() != 32 * D`.
#[must_use]
pub fn simple_bit_unpack_q8380417<const D: usize>(
    input: &[u8],
    b: i32,
) -> Poly<Q8380417> {
    assert!(b > 0);
    assert_eq!(D, bitlen_u32(b as u32));
    assert_eq!(input.len(), 32 * D);

    let mut coeffs = [0i32; N];

    bit_unpack::<D>(input, &mut coeffs);

    Poly::from_coeffs(coeffs)
}

/// FIPS 204 `BitUnpack(v, a, b)`.
///
/// Decodes 256 unsigned integers `y_i` using `D = bitlen(a + b)` bits each,
/// then maps them back to signed coefficients:
///
/// ```text
/// w_i = b - y_i
/// ```
///
/// The output coefficients are not necessarily in `[-a, b]` if the input byte
/// string is malformed.
///
/// # Panics
///
/// Panics if:
///
/// - `a < 0` or `b < 0`;
/// - `a + b <= 0`;
/// - `D != bitlen(a + b)`;
/// - `input.len() != 32 * D`.
#[must_use]
pub fn bit_unpack_q8380417<const D: usize>(
    input: &[u8],
    a: i32,
    b: i32,
) -> Poly<Q8380417> {
    assert!(a >= 0);
    assert!(b >= 0);
    assert!(a + b > 0);
    assert_eq!(D, bitlen_u32((a + b) as u32));
    assert_eq!(input.len(), 32 * D);

    let mut coeffs = [0i32; N];

    bit_unpack::<D>(input, &mut coeffs);

    for coeff in &mut coeffs {
        *coeff = b - *coeff;
    }

    Poly::from_coeffs(coeffs)
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_bit_pack_unpack_roundtrip_d10() {
        let mut coeffs = [0i32; N];

        for (i, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = (i as i32) % 1024;
        }

        let mut bytes = [0u8; 32 * 10];

        simple_bit_pack_q8380417::<10>(&coeffs, 1023, &mut bytes);

        let decoded = simple_bit_unpack_q8380417::<10>(&bytes, 1023);

        assert_eq!(decoded.coeffs(), &coeffs);
    }

    #[test]
    fn bit_pack_signed_unpack_roundtrip_small_range() {
        let mut coeffs = [0i32; N];

        for (i, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = match i % 5 {
                0 => -2,
                1 => -1,
                2 => 0,
                3 => 1,
                _ => 2,
            };
        }

        let mut bytes = [0u8; 32 * 3];

        bit_pack_signed_q8380417::<3>(&coeffs, 2, 2, &mut bytes);

        let decoded = bit_unpack_q8380417::<3>(&bytes, 2, 2);

        assert_eq!(decoded.coeffs(), &coeffs);
    }

    #[test]
    fn simple_bit_unpack_can_decode_outside_b_for_malformed_input() {
        // b = 13 has bitlen 4, so a 4-bit chunk can decode to 15.
        // This matches the FIPS warning that unpacking malformed byte strings
        // can produce coefficients outside the nominal range.
        let input = [0xffu8; 32 * 4];

        let decoded = simple_bit_unpack_q8380417::<4>(&input, 13);

        assert!(decoded.coeffs().iter().any(|&c| c > 13));
    }

    #[test]
    #[should_panic]
    fn simple_bit_pack_rejects_coefficient_above_b() {
        let mut coeffs = [0i32; N];
        coeffs[0] = 1024;

        let mut bytes = [0u8; 32 * 10];

        simple_bit_pack_q8380417::<10>(&coeffs, 1023, &mut bytes);
    }

    #[test]
    #[should_panic]
    fn bit_pack_signed_rejects_coefficient_below_minus_a() {
        let mut coeffs = [0i32; N];
        coeffs[0] = -3;

        let mut bytes = [0u8; 32 * 3];

        bit_pack_signed_q8380417::<3>(&coeffs, 2, 2, &mut bytes);
    }

    #[test]
    #[should_panic]
    fn bit_pack_signed_rejects_coefficient_above_b() {
        let mut coeffs = [0i32; N];
        coeffs[0] = 3;

        let mut bytes = [0u8; 32 * 3];

        bit_pack_signed_q8380417::<3>(&coeffs, 2, 2, &mut bytes);
    }
}