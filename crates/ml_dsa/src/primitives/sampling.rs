//! ML-DSA sampling and expansion routines.
//!
//! This module implements the ML-DSA sampling helpers used during public matrix
//! expansion, secret-vector expansion, and mask expansion.
//!
//! The rejection samplers in this module are variable-time by construction:
//! they consume XOF output until enough coefficients have been accepted. This
//! matches the FIPS 204 sampling structure.
//!
//! These routines are internal ML-DSA primitives. They are not exposed as part
//! of the public crate API.


use mlrust_core::encode::bits::{int_to_bytes, bitlen_u32};
use mlrust_core::encode::ml_dsa::{bit_unpack_q8380417, coeff_from_half_byte, coeff_from_three_bytes};
use mlrust_core::params::{Q8380417, N};
use mlrust_core::poly::{Poly, PolyMat, PolyVec};
use mlrust_core::symmetric::ml_dsa::{g_absorb_once, g_squeeze, h, h_absorb_once, h_squeeze};




#[inline]
fn write_u8(x: usize, out: &mut [u8]) {
    assert_eq!(out.len(), 1);
    assert!(x <= u8::MAX as usize);

    int_to_bytes(x as u32, 1, out);
}

#[inline]
fn write_u16(x: usize, out: &mut [u8]) {
    assert_eq!(out.len(), 2);
    assert!(x <= u16::MAX as usize);

    int_to_bytes(x as u32, 2, out);
}


/// FIPS 204 `RejNTTPoly`.
///
/// Samples a polynomial over `q = 8380417` by repeatedly reading three-byte
/// candidates from ML-DSA `G`, accepting only candidates strictly smaller than
/// `q`.
///
/// The input is normally `seed || j || i` during matrix expansion, hence the
/// expected length of 34 bytes.
///
/// This sampler is variable-time. For the standard `ExpandA` use case, its
/// input is derived from the public matrix seed.
#[must_use]
pub(crate) fn rej_ntt_poly(seed: &[u8; 34]) -> Poly<Q8380417> {
    let mut a_coeffs = [0i32; N];

    let mut j = 0usize;

    let mut reader = g_absorb_once(seed);

    let mut s = [0u8; 3];

    while j < N {
        g_squeeze(&mut reader, &mut s);

        let candidates = coeff_from_three_bytes(s[0], s[1], s[2]);

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
/// - `ETA` is not supported by `coeff_from_half_byte`.
#[must_use]
pub(crate) fn rej_bounded_poly<const ETA: usize>(seed: &[u8; 66]) -> Poly<Q8380417> {
    let mut a_coeffs = [0i32; N];

    let mut reader = h_absorb_once(seed);

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



/// FIPS 204 `ExpandA`.
///
/// Expands the public matrix `A` from the 32-byte public matrix seed `rho`.
///
/// The returned matrix has `K` rows and `L` columns. Entry `(r, s)` is sampled
/// from:
///
/// ```text
/// RejNTTPoly(rho || IntegerToBytes(s, 1) || IntegerToBytes(r, 1))
/// ```
///
/// # Panics
///
/// Panics if:
///
/// - `K > 256` or `L > 256`.
#[must_use]
pub(crate) fn expand_a<const K: usize, const L: usize>(rho: &[u8; 32]) -> PolyMat<Q8380417, K, L> {
    assert!(K <= 256);
    assert!(L <= 256);

    let mut rows = [PolyVec::<Q8380417, L>::zero(); K];
    let mut seed = [0u8; 34];

    seed[0..32].copy_from_slice(rho);

    for r in 0..K {
        let mut row = [Poly::<Q8380417>::zero(); L];

        for s in 0..L {
            write_u8(s, &mut seed[32..33]);
            write_u8(r, &mut seed[33..34]);

            row[s] = rej_ntt_poly(&seed);
        }

        rows[r] = PolyVec::from_polys(row);
    }

    PolyMat::<Q8380417, K, L>::from_rows(rows)
}



/// FIPS 204 `ExpandS`.
///
/// Expands the secret vectors `s1` and `s2` from the 64-byte secret expansion
/// seed `rho_prime`.
///
/// The returned vectors have dimensions `L` and `K`, respectively. The
/// polynomial `s1[r]` is sampled with nonce `r`, and the polynomial `s2[r]` is
/// sampled with nonce `L + r`.
///
/// # Panics
///
/// Panics if:
///
/// - `L + K - 1` does not fit in two bytes;
/// - `ETA` is not supported by `coeff_from_half_byte`.
#[must_use]
pub(crate) fn expand_s<
    const K: usize,
    const L: usize,
    const ETA: usize
>(rho_prime: &[u8; 64]) -> (PolyVec<Q8380417, L>, PolyVec<Q8380417, K>) {
    if L + K > 0 {
        assert!(L + K - 1 <= u16::MAX as usize);
    }

    let mut polys_s1 = [Poly::<Q8380417>::zero(); L];
    let mut polys_s2 = [Poly::<Q8380417>::zero(); K];

    let mut seed = [0u8; 66];
    seed[0..64].copy_from_slice(rho_prime);

    for r in 0..L {
        write_u16(r, &mut seed[64..66]);
        polys_s1[r] = rej_bounded_poly::<ETA>(&seed);
    }

    for r in 0..K {
        write_u16(L + r, &mut seed[64..66]);
        polys_s2[r] = rej_bounded_poly::<ETA>(&seed);
    }

    (PolyVec::from_polys(polys_s1), PolyVec::from_polys(polys_s2))
}


/// FIPS 204 `ExpandMask`.
///
/// Expands the signing mask vector `y` from a 64-byte seed and a two-byte
/// nonce.
///
/// The polynomial `y[r]` is produced from:
///
/// ```text
/// H(rho_prime || IntegerToBytes(nonce + r, 2))
/// ```
///
/// and decoded with `BitUnpack(_, GAMMA1 - 1, GAMMA1)`.
///
/// # Panics
///
/// Panics if:
///
/// - `nonce + L - 1` does not fit in two bytes;
/// - `BITLEN_2GAMMA1_MINUS_ONE != bitlen(2 * GAMMA1 - 1)`;
/// - `BITLEN_2GAMMA1_MINUS_ONE_TIMES_32 != 32 * BITLEN_2GAMMA1_MINUS_ONE`.
#[must_use]
pub(crate) fn expand_mask<
    const L: usize,
    const GAMMA1: usize,
    const BITLEN_2GAMMA1_MINUS_ONE: usize,
    const BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize,
>(
    rho_prime: &[u8; 64],
    nonce: usize
) -> PolyVec<Q8380417, L>{
    assert!(GAMMA1 > 0);
    assert_eq!(
        BITLEN_2GAMMA1_MINUS_ONE,
        bitlen_u32((2 * GAMMA1 - 1) as u32),
    );
    assert_eq!(
        BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
        32 * BITLEN_2GAMMA1_MINUS_ONE,
    );

    if L > 0 {
        assert!(nonce + L - 1 <= u16::MAX as usize);
    }

    let mut y_polys = [Poly::<Q8380417>::zero(); L];

    let mut seed = [0u8; 66];
    seed[0..64].copy_from_slice(rho_prime);

    for r in 0..L {
        write_u16(nonce + r, &mut seed[64..66]);

        let mut bytes = [0u8; BITLEN_2GAMMA1_MINUS_ONE_TIMES_32];

        h(&seed, &mut bytes);

        y_polys[r] = bit_unpack_q8380417::<BITLEN_2GAMMA1_MINUS_ONE>(
            &bytes,
            (GAMMA1 - 1) as i32,
            GAMMA1 as i32
        );
    }

    PolyVec::from_polys(y_polys)
}


#[cfg(test)]
mod tests {
    use super::*;
    use mlrust_core::params::RingParams;

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
    fn expand_a_matches_rej_ntt_poly_for_each_entry() {
        const K: usize = 2;
        const L: usize = 3;

        let rho = [0x42u8; 32];

        let a = expand_a::<K, L>(&rho);

        for r in 0..K {
            for s in 0..L {
                let mut seed = [0u8; 34];
                seed[0..32].copy_from_slice(&rho);
                seed[32] = s as u8;
                seed[33] = r as u8;

                let expected = rej_ntt_poly(&seed);

                assert_eq!(a.rows()[r].polys()[s], expected);
            }
        }
    }

    #[test]
    fn expand_a_is_deterministic() {
        const K: usize = 2;
        const L: usize = 2;

        let rho = [0x11u8; 32];

        let a0 = expand_a::<K, L>(&rho);
        let a1 = expand_a::<K, L>(&rho);

        assert_eq!(a0, a1);
    }

    #[test]
    fn expand_a_different_seeds_change_output() {
        const K: usize = 2;
        const L: usize = 2;

        let rho0 = [0x00u8; 32];
        let rho1 = [0x01u8; 32];

        let a0 = expand_a::<K, L>(&rho0);
        let a1 = expand_a::<K, L>(&rho1);

        assert_ne!(a0, a1);
    }

    #[test]
    fn expand_s_matches_rej_bounded_poly_nonces() {
        const L: usize = 2;
        const K: usize = 2;
        const ETA: usize = 2;

        let rho_prime = [0x7bu8; 64];

        let (s1, s2) = expand_s::<L, K, ETA>(&rho_prime);

        for r in 0..L {
            let mut seed = [0u8; 66];
            seed[0..64].copy_from_slice(&rho_prime);
            int_to_bytes(r as u32, 2, &mut seed[64..66]);

            let expected = rej_bounded_poly::<ETA>(&seed);

            assert_eq!(s1.polys()[r], expected);
        }

        for r in 0..K {
            let mut seed = [0u8; 66];
            seed[0..64].copy_from_slice(&rho_prime);
            int_to_bytes((L + r) as u32, 2, &mut seed[64..66]);

            let expected = rej_bounded_poly::<ETA>(&seed);

            assert_eq!(s2.polys()[r], expected);
        }
    }

    #[test]
    fn expand_s_coefficients_are_in_eta_range() {
        const L: usize = 2;
        const K: usize = 3;
        const ETA: usize = 4;

        let rho_prime = [0x33u8; 64];

        let (s1, s2) = expand_s::<L, K, ETA>(&rho_prime);

        for poly in s1.polys() {
            for &coeff in poly.coeffs() {
                assert!((-4..=4).contains(&coeff));
            }
        }

        for poly in s2.polys() {
            for &coeff in poly.coeffs() {
                assert!((-4..=4).contains(&coeff));
            }
        }
    }

    #[test]
    fn expand_s_is_deterministic() {
        const L: usize = 2;
        const K: usize = 2;
        const ETA: usize = 2;

        let rho_prime = [0xaau8; 64];

        let out0 = expand_s::<L, K, ETA>(&rho_prime);
        let out1 = expand_s::<L, K, ETA>(&rho_prime);

        assert_eq!(out0, out1);
    }

    #[test]
    fn expand_mask_coefficients_are_in_expected_range() {
        const L: usize = 2;
        const GAMMA1: usize = 4;
        const BITS: usize = 3;
        const BYTES: usize = 32 * BITS;

        let rho_prime = [0x55u8; 64];

        let y = expand_mask::<L, GAMMA1, BITS, BYTES>(&rho_prime, 0);

        for poly in y.polys() {
            for &coeff in poly.coeffs() {
                assert!((-(GAMMA1 as i32 - 1)..=GAMMA1 as i32).contains(&coeff));
            }
        }
    }

    #[test]
    fn expand_mask_is_deterministic() {
        const L: usize = 2;
        const GAMMA1: usize = 4;
        const BITS: usize = 3;
        const BYTES: usize = 32 * BITS;

        let rho_prime = [0x44u8; 64];

        let y0 = expand_mask::<L, GAMMA1, BITS, BYTES>(&rho_prime, 0);
        let y1 = expand_mask::<L, GAMMA1, BITS, BYTES>(&rho_prime, 0);

        assert_eq!(y0, y1);
    }

    #[test]
    fn expand_mask_different_nonces_change_output() {
        const L: usize = 2;
        const GAMMA1: usize = 4;
        const BITS: usize = 3;
        const BYTES: usize = 32 * BITS;

        let rho_prime = [0x44u8; 64];

        let y0 = expand_mask::<L, GAMMA1, BITS, BYTES>(&rho_prime, 0);
        let y1 = expand_mask::<L, GAMMA1, BITS, BYTES>(&rho_prime, 1);

        assert_ne!(y0, y1);
    }

    #[test]
    fn expand_mask_matches_direct_bit_unpack_for_first_poly() {
        const L: usize = 2;
        const GAMMA1: usize = 4;
        const BITS: usize = 3;
        const BYTES: usize = 32 * BITS;

        let rho_prime = [0x99u8; 64];
        let nonce = 5usize;

        let y = expand_mask::<L, GAMMA1, BITS, BYTES>(&rho_prime, nonce);

        let mut seed = [0u8; 66];
        seed[0..64].copy_from_slice(&rho_prime);
        int_to_bytes(nonce as u32, 2, &mut seed[64..66]);

        let mut bytes = [0u8; BYTES];
        h(&seed, &mut bytes);

        let expected = bit_unpack_q8380417::<BITS>(
            &bytes,
            (GAMMA1 - 1) as i32,
            GAMMA1 as i32,
        );

        assert_eq!(y.polys()[0], expected);
    }

    #[test]
    fn expand_mask_matches_direct_bit_unpack_for_each_poly() {
        const L: usize = 3;
        const GAMMA1: usize = 4;
        const BITS: usize = 3;
        const BYTES: usize = 32 * BITS;

        let rho_prime = [0x99u8; 64];
        let nonce = 5usize;

        let y = expand_mask::<L, GAMMA1, BITS, BYTES>(&rho_prime, nonce);

        for r in 0..L {
            let mut seed = [0u8; 66];
            seed[0..64].copy_from_slice(&rho_prime);
            int_to_bytes((nonce + r) as u32, 2, &mut seed[64..66]);

            let mut bytes = [0u8; BYTES];
            h(&seed, &mut bytes);

            let expected = bit_unpack_q8380417::<BITS>(
                &bytes,
                (GAMMA1 - 1) as i32,
                GAMMA1 as i32,
            );

            assert_eq!(y.polys()[r], expected);
        }
    }

    #[test]
    #[should_panic]
    fn expand_mask_rejects_wrong_bitlen() {
        const L: usize = 2;
        const GAMMA1: usize = 4;
        const WRONG_BITS: usize = 4;
        const BYTES: usize = 32 * WRONG_BITS;

        let rho_prime = [0u8; 64];

        let _ = expand_mask::<L, GAMMA1, WRONG_BITS, BYTES>(&rho_prime, 0);
    }

    #[test]
    #[should_panic]
    fn expand_mask_rejects_wrong_output_block_size() {
        const L: usize = 2;
        const GAMMA1: usize = 4;
        const BITS: usize = 3;
        const WRONG_BYTES: usize = 32 * BITS + 1;

        let rho_prime = [0u8; 64];

        let _ = expand_mask::<L, GAMMA1, BITS, WRONG_BYTES>(&rho_prime, 0);
    }

    #[test]
    #[should_panic]
    fn expand_mask_rejects_nonce_overflow() {
        const L: usize = 2;
        const GAMMA1: usize = 4;
        const BITS: usize = 3;
        const BYTES: usize = 32 * BITS;

        let rho_prime = [0u8; 64];

        let _ = expand_mask::<L, GAMMA1, BITS, BYTES>(
            &rho_prime,
            u16::MAX as usize,
        );
    }
}