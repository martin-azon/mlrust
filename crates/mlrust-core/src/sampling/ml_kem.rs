//! ML-KEM sampling routines.
//!
//! This module implements the sampling primitives used by ML-KEM:
//!
//! - `SampleNTT`, used to sample public matrix entries from the public matrix
//!   seed `rho`;
//! - `SamplePolyCBD`, used to sample small secret/error polynomials from
//!   centered binomial distributions.
//!
//! The `SampleNTT` routine uses rejection sampling from SHAKE128 output. Its
//! loop count is variable, as in FIPS 203. This is acceptable because the
//! rejection pattern depends on public matrix-seed material, not on secret
//! coefficients.
//!
//! The `SamplePolyCBD` routine uses fixed-size input and fixed loop bounds.
//! It works directly with byte slices and bit extraction rather than allocating
//! an intermediate bit array.


use crate::encode::bits::get_bit;
use crate::params::{RingParams, N, Q3329};
use crate::poly::Poly;
use crate::symmetric::ml_kem::{xof_absorb, xof_squeeze};


/// Samples a public matrix entry in the NTT/Montgomery domain.
///
/// This implements the FIPS 203 `SampleNTT` procedure for the ML-KEM modulus
/// `q = 3329`.
///
/// The XOF input is:
///
/// ```text
/// rho || j || i
/// ```
///
/// where `rho` is the 32-byte public matrix seed and `i`, `j` are matrix
/// indices. The order `rho || j || i` is the order used by FIPS 203 for
/// matrix generation.
///
/// The rejection-sampling loop is intentionally unbounded. FIPS 203 recommends
/// avoiding artificial bounds for this loop where possible.
#[must_use]
pub fn sample_ntt(rho: &[u8; 32], i: u8, j: u8) -> Poly<Q3329> {
    let mut input = [0u8; 34];

    input[..32].copy_from_slice(rho);
    input[32] = j;
    input[33] = i;

    let mut reader = xof_absorb(&input);

    let mut coeffs = [0i32; N];
    let mut ctr = 0usize;

    // SHAKE128 has rate 168 bytes. FIPS SampleNTT consumes the XOF stream
    // in 3-byte chunks; we squeeze one rate block at a time and parse it
    // as consecutive 3-byte chunks.
    let mut buf = [0u8; 168];

    while ctr < N {
        xof_squeeze(&mut reader, &mut buf);

        let mut pos = 0usize;

        while pos + 3 <= buf.len() && ctr < N {
            let b0 = buf[pos] as u16;
            let b1 = buf[pos + 1] as u16;
            let b2 = buf[pos + 2] as u16;

            let d1 = b0 | ((b1 & 0x0f) << 8);
            let d2 = (b1 >> 4) | (b2 << 4);

            if d1 < Q3329::Q as u16 {
                coeffs[ctr] = Q3329::to_montgomery(d1 as i32);
                ctr += 1;
            }

            if d2 < Q3329::Q as u16 && ctr < N {
                coeffs[ctr] = Q3329::to_montgomery(d2 as i32);
                ctr += 1;
            }

            pos += 3;
        }
    }

    Poly::<Q3329>::from_coeffs(coeffs)
}


/// Samples a secret/error polynomial in the ordinary coefficient domain from a centered binomial distribution.
///
/// This implements the FIPS 203 `SamplePolyCBD_eta` procedure.
///
/// The input must have length:
///
/// ```text
/// 64 * ETA bytes
/// ```
///
/// Supported values are:
///
/// ```text
/// ETA = 2
/// ETA = 3
/// ```
///
/// The output coefficients are small signed representatives in the range:
///
/// ```text
/// [-ETA, ETA]
/// ```
///
/// They are intentionally not canonicalized modulo `q`. This is the natural
/// coefficient-domain representation for secret/error polynomials before later
/// arithmetic or NTT conversion.
#[must_use]
pub fn sample_poly_cbd<const ETA: usize>(input: &[u8]) -> Poly<Q3329> {
    assert!(ETA == 2 || ETA == 3);
    assert_eq!(input.len(), 64 * ETA);

    let mut coeffs = [0i32; N];

    for i in 0..N {
        let mut x = 0i32;
        let mut y = 0i32;

        for j in 0..ETA {
            x += get_bit(input, 2 * i * ETA + j) as i32;
            y += get_bit(input, 2 * i * ETA + ETA +  j) as i32;
        }

        coeffs[i] = x - y;
    }

    Poly::<Q3329>::from_coeffs(coeffs)
}



#[cfg(test)]
mod tests {
    use super::*;

    use crate::params::{N, Q3329, RingParams};
    use crate::symmetric::ml_kem::{xof_absorb, xof_squeeze};

    fn set_bit(input: &mut [u8], bit_index: usize) {
        input[bit_index / 8] |= 1u8 << (bit_index % 8);
    }

    fn reference_sample_ntt_three_byte_chunks(
        rho: &[u8; 32],
        i: u8,
        j: u8,
    ) -> Poly<Q3329> {
        let mut input = [0u8; 34];

        input[..32].copy_from_slice(rho);

        // FIPS 203 matrix generation uses rho || j || i.
        input[32] = j;
        input[33] = i;

        let mut reader = xof_absorb(&input);

        let mut coeffs = [0i32; N];
        let mut ctr = 0usize;

        while ctr < N {
            let mut buf = [0u8; 3];

            xof_squeeze(&mut reader, &mut buf);

            let b0 = buf[0] as u16;
            let b1 = buf[1] as u16;
            let b2 = buf[2] as u16;

            let d1 = b0 | ((b1 & 0x0f) << 8);
            let d2 = (b1 >> 4) | (b2 << 4);

            if d1 < Q3329::Q as u16 {
                coeffs[ctr] = Q3329::to_montgomery(d1 as i32);
                ctr += 1;
            }

            if ctr < N && d2 < Q3329::Q as u16 {
                coeffs[ctr] = Q3329::to_montgomery(d2 as i32);
                ctr += 1;
            }
        }

        Poly::<Q3329>::from_coeffs(coeffs)
    }

    #[test]
    fn sample_ntt_matches_reference_three_byte_chunks() {
        let mut rho = [0u8; 32];

        for (i, byte) in rho.iter_mut().enumerate() {
            *byte = (3 * i + 17) as u8;
        }

        let got = sample_ntt(&rho, 2, 5);
        let expected = reference_sample_ntt_three_byte_chunks(&rho, 2, 5);

        assert_eq!(got, expected);
    }

    #[test]
    fn sample_ntt_uses_fips_index_order_rho_j_i() {
        let mut rho = [0u8; 32];

        for (i, byte) in rho.iter_mut().enumerate() {
            *byte = (7 * i + 11) as u8;
        }

        let got = sample_ntt(&rho, 4, 9);

        let expected = reference_sample_ntt_three_byte_chunks(&rho, 4, 9);

        assert_eq!(got, expected);
    }

    #[test]
    fn sample_ntt_outputs_valid_montgomery_representatives() {
        let rho = [0x9bu8; 32];

        let p = sample_ntt(&rho, 0, 0);

        for (idx, &coeff_mont) in p.coeffs().iter().enumerate() {
            let coeff = Q3329::freeze(Q3329::from_montgomery(coeff_mont));

            assert!(
                0 <= coeff && coeff < Q3329::Q,
                "coefficient {idx} is out of range after Montgomery decoding: {coeff}"
            );
        }
    }

    #[test]
    fn sample_ntt_changes_with_indices() {
        let rho = [0x55u8; 32];

        let a = sample_ntt(&rho, 0, 1);
        let b = sample_ntt(&rho, 1, 0);

        assert_ne!(a, b);
    }

    #[test]
    fn sample_poly_cbd_eta2_zero_input_is_zero_poly() {
        let input = [0u8; 128];

        let p = sample_poly_cbd::<2>(&input);

        assert!(p.coeffs().iter().all(|&c| c == 0));
    }

    #[test]
    fn sample_poly_cbd_eta3_zero_input_is_zero_poly() {
        let input = [0u8; 192];

        let p = sample_poly_cbd::<3>(&input);

        assert!(p.coeffs().iter().all(|&c| c == 0));
    }

    #[test]
    fn sample_poly_cbd_eta2_all_ones_is_zero_poly() {
        let input = [0xffu8; 128];

        let p = sample_poly_cbd::<2>(&input);

        assert!(p.coeffs().iter().all(|&c| c == 0));
    }

    #[test]
    fn sample_poly_cbd_eta3_all_ones_is_zero_poly() {
        let input = [0xffu8; 192];

        let p = sample_poly_cbd::<3>(&input);

        assert!(p.coeffs().iter().all(|&c| c == 0));
    }

    #[test]
    fn sample_poly_cbd_eta2_selected_coefficients() {
        let mut input = [0u8; 128];

        // ETA = 2, so each coefficient consumes 4 bits:
        //
        // coeff_i = (bits[4i] + bits[4i+1])
        //         - (bits[4i+2] + bits[4i+3])

        // coeff 0: x = 2, y = 0 => 2
        set_bit(&mut input, 0);
        set_bit(&mut input, 1);

        // coeff 1: x = 0, y = 2 => -2
        set_bit(&mut input, 6);
        set_bit(&mut input, 7);

        // coeff 2: x = 1, y = 1 => 0
        set_bit(&mut input, 8);
        set_bit(&mut input, 10);

        // coeff 255: x = 1, y = 2 => -1
        let base = 4 * 255;
        set_bit(&mut input, base + 1);
        set_bit(&mut input, base + 2);
        set_bit(&mut input, base + 3);

        let p = sample_poly_cbd::<2>(&input);

        assert_eq!(p.coeffs()[0], 2);
        assert_eq!(p.coeffs()[1], -2);
        assert_eq!(p.coeffs()[2], 0);
        assert_eq!(p.coeffs()[255], -1);

        for i in 3..255 {
            assert_eq!(p.coeffs()[i], 0, "unexpected nonzero coefficient at {i}");
        }
    }

    #[test]
    fn sample_poly_cbd_eta3_selected_coefficients() {
        let mut input = [0u8; 192];

        // ETA = 3, so each coefficient consumes 6 bits:
        //
        // coeff_i = (bits[6i] + bits[6i+1] + bits[6i+2])
        //         - (bits[6i+3] + bits[6i+4] + bits[6i+5])

        // coeff 0: x = 3, y = 0 => 3
        set_bit(&mut input, 0);
        set_bit(&mut input, 1);
        set_bit(&mut input, 2);

        // coeff 1: x = 0, y = 3 => -3
        set_bit(&mut input, 9);
        set_bit(&mut input, 10);
        set_bit(&mut input, 11);

        // coeff 2: x = 2, y = 1 => 1
        let base = 6 * 2;
        set_bit(&mut input, base);
        set_bit(&mut input, base + 2);
        set_bit(&mut input, base + 4);

        // coeff 255: x = 1, y = 2 => -1
        let base = 6 * 255;
        set_bit(&mut input, base + 1);
        set_bit(&mut input, base + 3);
        set_bit(&mut input, base + 5);

        let p = sample_poly_cbd::<3>(&input);

        assert_eq!(p.coeffs()[0], 3);
        assert_eq!(p.coeffs()[1], -3);
        assert_eq!(p.coeffs()[2], 1);
        assert_eq!(p.coeffs()[255], -1);

        for i in 3..255 {
            assert_eq!(p.coeffs()[i], 0, "unexpected nonzero coefficient at {i}");
        }
    }

    #[test]
    fn sample_poly_cbd_eta2_coefficients_are_in_range() {
        let input = [0xa5u8; 128];

        let p = sample_poly_cbd::<2>(&input);

        for (idx, &coeff) in p.coeffs().iter().enumerate() {
            assert!(
                (-2..=2).contains(&coeff),
                "coefficient {idx} out of eta=2 range: {coeff}"
            );
        }
    }

    #[test]
    fn sample_poly_cbd_eta3_coefficients_are_in_range() {
        let input = [0x3cu8; 192];

        let p = sample_poly_cbd::<3>(&input);

        for (idx, &coeff) in p.coeffs().iter().enumerate() {
            assert!(
                (-3..=3).contains(&coeff),
                "coefficient {idx} out of eta=3 range: {coeff}"
            );
        }
    }

    #[test]
    #[should_panic]
    fn sample_poly_cbd_rejects_eta2_wrong_input_length() {
        let input = [0u8; 127];

        let _ = sample_poly_cbd::<2>(&input);
    }

    #[test]
    #[should_panic]
    fn sample_poly_cbd_rejects_eta3_wrong_input_length() {
        let input = [0u8; 191];

        let _ = sample_poly_cbd::<3>(&input);
    }

    #[test]
    #[should_panic]
    fn sample_poly_cbd_rejects_unsupported_eta() {
        let input = [0u8; 256];

        let _ = sample_poly_cbd::<4>(&input);
    }
}