//! ML-DSA sampling routines.
//!
//! This module implements the ML-DSA sampling helpers used during matrix
//! expansion, secret-vector expansion, mask expansion, and challenge
//! construction.
//!
//! The rejection samplers in this module are variable-time by construction:
//! they consume XOF output until enough coefficients have been accepted. This
//! matches the FIPS 204 sampling structure.




use mlrust_core::encode::bits::bytes_to_bits;
use mlrust_core::encode::ml_dsa::{coeff_from_half_byte, coeff_from_three_bytes};
use mlrust_core::params::{Q8380417, N};
use mlrust_core::poly::Poly;
use mlrust_core::symmetric::ml_dsa::{g_absorb, g_squeeze, h_absorb, h_squeeze};



/// FIPS 204 `SampleInBall`.
///
/// Constructs a sparse challenge polynomial with exactly `TAU` nonzero
/// coefficients. Each nonzero coefficient is either `+1` or `-1`.
///
/// The input is the challenge seed `c_tilde`.
///
/// # Panics
///
/// Panics if:
///
/// - `c_tilde.len() != LAMBDA_OVER_4`;
/// - `TAU > 64`;
/// - `TAU > N`.
pub(crate) fn sample_in_ball<
    const LAMBDA_OVER_4: usize,
    const TAU: usize,
>(c_tilde: &[u8]) -> Poly<Q8380417> {
    assert_eq!(c_tilde.len(), LAMBDA_OVER_4);

    let mut c_coeffs = [0i32; N];

    let mut s = [0u8; 8];
    let mut h_bits = [0u8; 64];
    let mut j_byte = [0u8; 1];

    let mut reader = h_absorb(c_tilde);
    h_squeeze(&mut reader, &mut s);
    bytes_to_bits(&s, &mut h_bits);

    for i in (N - TAU)..N {
        h_squeeze(&mut reader, &mut j_byte);

        while j_byte[0] as usize > i {
            h_squeeze(&mut reader, &mut j_byte);
        }

        let j = j_byte[0] as usize;
        let sign_bit_index = i + TAU - N;

        c_coeffs[i] = c_coeffs[j];
        c_coeffs[j] = 1 - 2 * ((h_bits[sign_bit_index] & 1) as i32);
    }

    Poly::<Q8380417>::from_coeffs(c_coeffs)
}


/// FIPS 204 `RejNTTPoly`.
///
/// Samples a polynomial over `q = 8380417` by repeatedly reading three-byte
/// candidates from ML-DSA `G`, accepting only candidates strictly smaller than
/// `q`.
///
/// The input is normally `rho || j || i` during matrix expansion, hence the
/// expected length of 34 bytes.
///
/// This sampler is variable-time. For the standard `ExpandA` use case, its
/// input is derived from the public matrix seed.
///
/// # Panics
///
/// Panics if `rho.len() != 34`.
pub(crate) fn rej_ntt_poly(rho: &[u8]) -> Poly<Q8380417> {
    assert_eq!(rho.len(), 34);

    let mut a_coeffs = [0i32; N];

    let mut j = 0usize;

    let mut reader = g_absorb(rho);

    let mut s = [0u8; 3];

    while j < N {
        g_squeeze(&mut reader, &mut s);

        let candidates= coeff_from_three_bytes(s[0], s[1], s[2]);

        if bool::from(candidates.is_some()) {
            a_coeffs[j] = candidates.unwrap();
            j += 1;
        }
    }

    Poly::<Q8380417>::from_coeffs(a_coeffs)
}



/// FIPS 204 `RejBoundedPoly`.
///
/// Samples a polynomial with coefficients in `[-ETA, ETA]` by repeatedly
/// reading bytes from ML-DSA `H`, splitting each byte into two half-byte
/// candidates, and accepting candidates allowed by `CoeffFromHalfByte`.
///
/// The input is normally a 64-byte seed followed by a two-byte nonce, hence the
/// expected length of 66 bytes.
///
/// This sampler is variable-time and is not a hardened fixed-work sampler.
///
/// # Panics
///
/// Panics if:
///
/// - `rho.len() != 66`;
/// - `ETA` is not supported by `coeff_from_half_byte`.
pub(crate) fn rej_bounded_poly<const ETA: usize>(rho: &[u8]) -> Poly<Q8380417> {
    assert_eq!(rho.len(), 66);

    let mut a_coeffs = [0i32; N];

    let mut reader = h_absorb(rho);

    let mut j = 0usize;

    let mut z = [0u8; 1];

    while j < N {
        h_squeeze(&mut reader, &mut z);

        let candidate_z0 = coeff_from_half_byte::<ETA>(z[0] & 0x0f);
        if bool::from(candidate_z0.is_some()) {
            a_coeffs[j] = candidate_z0.unwrap();
            j += 1;
        }

        if j < N {
            let candidate_z1 = coeff_from_half_byte::<ETA>(z[0] >> 4);
            if bool::from(candidate_z1.is_some()) {
                a_coeffs[j] = candidate_z1.unwrap();
                j += 1;
            }
        }
    }

    Poly::<Q8380417>::from_coeffs(a_coeffs)
}




#[cfg(test)]
mod tests {
    use super::*;
    use mlrust_core::params::RingParams;

    fn count_nonzero(coeffs: &[i32; N]) -> usize {
        coeffs.iter().filter(|&&c| c != 0).count()
    }

    #[test]
    fn sample_in_ball_has_tau_nonzero_coefficients() {
        const LAMBDA_OVER_4: usize = 32;
        const TAU: usize = 39;

        let c_tilde = [0x42u8; LAMBDA_OVER_4];

        let c = sample_in_ball::<LAMBDA_OVER_4, TAU>(&c_tilde);

        assert_eq!(count_nonzero(c.coeffs()), TAU);
    }

    #[test]
    fn sample_in_ball_nonzero_coefficients_are_plus_or_minus_one() {
        const LAMBDA_OVER_4: usize = 32;
        const TAU: usize = 49;

        let c_tilde = [0x13u8; LAMBDA_OVER_4];

        let c = sample_in_ball::<LAMBDA_OVER_4, TAU>(&c_tilde);

        for &coeff in c.coeffs() {
            assert!(coeff == -1 || coeff == 0 || coeff == 1);
        }
    }

    #[test]
    fn sample_in_ball_is_deterministic() {
        const LAMBDA_OVER_4: usize = 32;
        const TAU: usize = 60;

        let c_tilde = [0xa5u8; LAMBDA_OVER_4];

        let c0 = sample_in_ball::<LAMBDA_OVER_4, TAU>(&c_tilde);
        let c1 = sample_in_ball::<LAMBDA_OVER_4, TAU>(&c_tilde);

        assert_eq!(c0, c1);
    }

    #[test]
    fn sample_in_ball_different_inputs_change_output() {
        const LAMBDA_OVER_4: usize = 32;
        const TAU: usize = 39;

        let c0_seed = [0x00u8; LAMBDA_OVER_4];
        let c1_seed = [0x01u8; LAMBDA_OVER_4];

        let c0 = sample_in_ball::<LAMBDA_OVER_4, TAU>(&c0_seed);
        let c1 = sample_in_ball::<LAMBDA_OVER_4, TAU>(&c1_seed);

        assert_ne!(c0, c1);
    }

    #[test]
    #[should_panic]
    fn sample_in_ball_rejects_wrong_input_length() {
        const LAMBDA_OVER_4: usize = 32;
        const TAU: usize = 39;

        let c_tilde = [0u8; LAMBDA_OVER_4 - 1];

        let _ = sample_in_ball::<LAMBDA_OVER_4, TAU>(&c_tilde);
    }

    #[test]
    #[should_panic]
    fn sample_in_ball_rejects_tau_above_64() {
        const LAMBDA_OVER_4: usize = 32;
        const TAU: usize = 65;

        let c_tilde = [0u8; LAMBDA_OVER_4];

        let _ = sample_in_ball::<LAMBDA_OVER_4, TAU>(&c_tilde);
    }

    #[test]
    fn rej_ntt_poly_coefficients_are_less_than_q() {
        let mut seed = [0u8; 34];

        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let poly = rej_ntt_poly(&seed);

        for &coeff in poly.coeffs() {
            assert!(0 <= coeff);
            assert!(coeff < Q8380417::Q);
        }
    }

    #[test]
    fn rej_ntt_poly_is_deterministic() {
        let seed = [0x5au8; 34];

        let p0 = rej_ntt_poly(&seed);
        let p1 = rej_ntt_poly(&seed);

        assert_eq!(p0, p1);
    }

    #[test]
    fn rej_ntt_poly_different_inputs_change_output() {
        let seed0 = [0x00u8; 34];
        let seed1 = [0x01u8; 34];

        let p0 = rej_ntt_poly(&seed0);
        let p1 = rej_ntt_poly(&seed1);

        assert_ne!(p0, p1);
    }

    #[test]
    #[should_panic]
    fn rej_ntt_poly_rejects_wrong_input_length() {
        let seed = [0u8; 33];

        let _ = rej_ntt_poly(&seed);
    }

    #[test]
    fn rej_bounded_poly_eta2_coefficients_are_in_range() {
        let mut seed = [0u8; 66];

        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (3 * i) as u8;
        }

        let poly = rej_bounded_poly::<2>(&seed);

        for &coeff in poly.coeffs() {
            assert!((-2..=2).contains(&coeff));
        }
    }

    #[test]
    fn rej_bounded_poly_eta4_coefficients_are_in_range() {
        let mut seed = [0u8; 66];

        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (7 * i) as u8;
        }

        let poly = rej_bounded_poly::<4>(&seed);

        for &coeff in poly.coeffs() {
            assert!((-4..=4).contains(&coeff));
        }
    }

    #[test]
    fn rej_bounded_poly_is_deterministic() {
        let seed = [0xabu8; 66];

        let p0 = rej_bounded_poly::<2>(&seed);
        let p1 = rej_bounded_poly::<2>(&seed);

        assert_eq!(p0, p1);
    }

    #[test]
    fn rej_bounded_poly_different_inputs_change_output() {
        let seed0 = [0x00u8; 66];
        let seed1 = [0x01u8; 66];

        let p0 = rej_bounded_poly::<2>(&seed0);
        let p1 = rej_bounded_poly::<2>(&seed1);

        assert_ne!(p0, p1);
    }

    #[test]
    #[should_panic]
    fn rej_bounded_poly_rejects_wrong_input_length() {
        let seed = [0u8; 65];

        let _ = rej_bounded_poly::<2>(&seed);
    }
}