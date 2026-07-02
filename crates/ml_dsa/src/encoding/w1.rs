//! ML-DSA `w1` encoding for challenge hashing.


use mlrust_core::encode::ml_dsa::simple_bit_pack_q8380417;
use mlrust_core::params::{Q8380417, RingParams};
use mlrust_core::poly::PolyVec;



/// FIPS 204 `w1Encode`.
///
/// Encodes the high-order vector `w1` for challenge hashing.
///
/// # Panics
///
/// Panics if `out.len()` does not match the expected parameter-set length, or
/// if a coefficient of `w1` is outside the expected range.
pub(crate) fn w1_encode<
    const K: usize,
    const GAMMA2: usize,
    const BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize,
>(
    w1: &PolyVec<Q8380417, K>,
    out: &mut [u8]
) {
    assert_eq!(
        out.len(),
        32 * K * BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE
    );

    out.fill(0);

    let w1_polys = w1.polys();

    let bound = ((Q8380417::Q - 1) as u32) / ((2 * GAMMA2) as u32) - 1;
    let packed_len = 32 * BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE;

    let mut start = 0usize;



    for poly in w1_polys {
        simple_bit_pack_q8380417::<BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE>(
            poly.coeffs(),
            bound as i32,
            &mut out[start..start + packed_len],
        );

        start += packed_len;
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use mlrust_core::params::N;
    use mlrust_core::poly::Poly;

    fn poly_from_fn<F>(mut f: F) -> Poly<Q8380417>
    where
        F: FnMut(usize) -> i32,
    {
        let mut coeffs = [0i32; N];

        for (i, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = f(i);
        }

        Poly::from_coeffs(coeffs)
    }

    #[test]
    fn w1_encode_advances_output_offset() {
        const K: usize = 2;
        const GAMMA2: usize = 95_232;
        const BITS: usize = 6;

        let w1 = PolyVec::from_polys([
            poly_from_fn(|_| 0),
            poly_from_fn(|i| (i as i32) % 16),
        ]);

        let mut out = [0u8; 32 * K * BITS];

        w1_encode::<K, GAMMA2, BITS>(&w1, &mut out);

        let first = &out[0..32 * BITS];
        let second = &out[32 * BITS..2 * 32 * BITS];

        assert!(first.iter().all(|&b| b == 0));
        assert!(second.iter().any(|&b| b != 0));
    }
}