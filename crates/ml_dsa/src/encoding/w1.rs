//! ML-DSA `w1` encoding for challenge hashing.
//!
//! This module implements FIPS 204 `w1Encode`, which serializes the high-bit
//! vector `w1` before hashing:
//!
//! ```text
//! c_tilde = H(mu || w1Encode(w1), lambda / 4)
//! ```
//!
//! This encoding is not a public-key, secret-key, or signature encoding. It is
//! an internal deterministic representation used only for challenge generation
//! and verification.

use mlrust_core::encode::bits::bitlen_u32;
use mlrust_core::encode::ml_dsa::simple_bit_pack_q8380417;
use mlrust_core::params::{Q8380417, RingParams};
use mlrust_core::poly::PolyVec;

/// FIPS 204 `w1Encode`.
///
/// Encodes the high-order vector `w1` for challenge hashing.
///
/// Each coefficient of `w1` is expected to lie in:
///
/// ```text
/// 0 ..= (q - 1) / (2 * gamma2) - 1
/// ```
///
/// and is packed using:
///
/// ```text
/// bitlen((q - 1) / (2 * gamma2) - 1)
/// ```
///
/// bits per coefficient.
///
/// # Panics
///
/// Panics if:
///
/// - `GAMMA2 == 0`;
/// - `BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE` is inconsistent with
///   `GAMMA2`;
/// - `out.len()` does not match the parameter-set `w1` encoding length;
/// - a coefficient of `w1` is outside the expected packing range.
pub(crate) fn w1_encode<
    const K: usize,
    const GAMMA2: usize,
    const BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize,
>(
    w1: &PolyVec<Q8380417, K>,
    out: &mut [u8],
) {
    assert!(GAMMA2 > 0);
    assert_eq!(
        BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
        bitlen_u32(((Q8380417::Q - 1) / (2 * GAMMA2) as i32) as u32 - 1)
    );
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

        let w1 = PolyVec::from_polys([poly_from_fn(|_| 0), poly_from_fn(|i| (i as i32) % 16)]);

        let mut out = [0u8; 32 * K * BITS];

        w1_encode::<K, GAMMA2, BITS>(&w1, &mut out);

        let first = &out[0..32 * BITS];
        let second = &out[32 * BITS..2 * 32 * BITS];

        assert!(first.iter().all(|&b| b == 0));
        assert!(second.iter().any(|&b| b != 0));
    }
}
