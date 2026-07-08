use mlrust_core::encode::bits::bytes_to_bits;
use mlrust_core::params::{N, Q8380417};
use mlrust_core::poly::Poly;
use mlrust_core::symmetric::ml_dsa::{h_absorb_once, h_squeeze};

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

    let mut reader = h_absorb_once(c_tilde);
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





#[cfg(test)]
mod tests {
    use super::*;

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
}