//! ML-DSA rounding, decomposition, and hint primitives.
//!
//! This module implements the FIPS 204 rounding primitives used during key
//! generation, signing, and verification.
//!
//! The data-dependent selections in this module are written with `subtle`.
//! Parameter checks are ordinary assertions because parameters are compile-time
//! public constants.

use subtle::{Choice, ConstantTimeGreater};

use mlrust_core::ct::i32::{ct_i32_eq, ct_i32_ge, ct_i32_gt, ct_i32_select};
use mlrust_core::encode::ml_dsa::hint::HintVec;
use mlrust_core::params::{N, Q8380417, RingParams};
use mlrust_core::poly::{Poly, PolyVec};

const Q: i32 = Q8380417::Q;

#[inline]
fn reduce_q_canonical(r: i32) -> i32 {
    Q8380417::freeze(r)
}

/// Centered reduction modulo `2^D`.
///
/// For `alpha = 2^D`, this returns the FIPS-style representative in:
///
/// ```text
/// [-2^(D-1) + 1, 2^(D-1)]
/// ```
#[inline]
pub(crate) fn mod_pm_power2<const D: usize>(r: i32) -> i32 {
    assert!(D > 0);
    assert!(D < 31);

    let alpha = 1i32 << D;
    let half = 1i32 << (D - 1);
    let mask = alpha - 1;

    let r0 = r & mask;
    let centered = r0 - alpha;

    let use_centered = (r0 as u32).ct_gt(&(half as u32));

    ct_i32_select(r0, centered, use_centered)
}

/// Returns the centered reduction modulo `q` of an integer.
#[inline]
pub(crate) fn mod_pm_q(r: i32) -> i32 {
    let r_plus = reduce_q_canonical(r);

    let centered = r_plus - Q;
    let use_centered = ct_i32_gt(r_plus, Q / 2);

    ct_i32_select(r_plus, centered, use_centered)
}

/// Returns the centered reduction modulo `q` of a polynomial.
#[inline]
pub(crate) fn mod_pm_q_poly(poly: Poly<Q8380417>) -> Poly<Q8380417> {
    let mut coeffs_res = [0i32; N];

    for i in 0..N {
        coeffs_res[i] = mod_pm_q(poly.coeffs()[i]);
    }

    Poly::from_coeffs(coeffs_res)
}

/// Returns the centered reduction modulo `q` of a polynomial vector.
#[inline]
pub(crate) fn mod_pm_q_polyvec<const K: usize>(vec: PolyVec<Q8380417, K>) -> PolyVec<Q8380417, K> {
    let mut polys_res = [Poly::zero(); K];

    for i in 0..K {
        polys_res[i] = mod_pm_q_poly(vec.polys()[i]);
    }

    PolyVec::from_polys(polys_res)
}

/// Centered reduction modulo `2 * GAMMA2`.
///
/// This computes `r_plus mod± (2 * GAMMA2)` using the FIPS 204 convention,
/// returning a representative in:
///
/// ```text
/// [-GAMMA2 + 1, GAMMA2]
/// ```
///
/// # Input invariant
///
/// `r_plus` must already be reduced modulo `q`, i.e.:
///
/// ```text
/// 0 <= r_plus < q
/// ```
///
/// This function is constant-time with respect to `r_plus`. Its loop count
/// depends only on the public compile-time parameter `GAMMA2`.
#[inline]
pub(crate) fn mod_pm_2gamma2_with_quotient<const GAMMA2: usize>(r_plus: i32) -> (i32, i32) {
    assert!(GAMMA2 > 0);

    let alpha = 2 * GAMMA2;
    assert_eq!((Q - 1) % alpha as i32, 0);

    debug_assert!(0 <= r_plus);
    debug_assert!(r_plus < Q);

    let m = ((Q - 1) / alpha as i32) as usize;
    let x = r_plus + GAMMA2 as i32 - 1;

    let mut k = 0i32;

    for i in 1..=m {
        let threshold = (i * alpha) as i32;
        k += ct_i32_ge(x, threshold).unwrap_u8() as i32;
    }

    let r0 = r_plus - k * alpha as i32;
    (k, r0)
}

/// FIPS 204 `Power2Round`.
///
/// Splits `r mod q` into `(r1, r0)` such that:
///
/// ```text
/// r mod q = r1 * 2^D + r0
/// ```
///
/// with `r0` centered modulo `2^D`.
#[inline]
pub(crate) fn power2round<const D: usize>(r: i32) -> (i32, i32) {
    assert!(D > 0);
    assert!(D < 31);

    let r_plus = reduce_q_canonical(r);
    let r0 = mod_pm_power2::<D>(r_plus);
    let r1 = (r_plus - r0) >> D;

    (r1, r0)
}

/// FIPS 204 `Decompose`.
#[inline]
pub(crate) fn decompose<const GAMMA2: usize>(r: i32) -> (i32, i32) {
    assert!(GAMMA2 > 0);
    assert_eq!((Q - 1) % (2 * GAMMA2) as i32, 0);

    let r_plus = reduce_q_canonical(r);

    let (r1_raw, r0_raw) = mod_pm_2gamma2_with_quotient::<GAMMA2>(r_plus);

    let special = ct_i32_eq(r_plus - r0_raw, Q - 1);
    let r0_special = r0_raw - 1;
    let r1_special = 0;

    let r1 = ct_i32_select(r1_raw, r1_special, special);
    let r0 = ct_i32_select(r0_raw, r0_special, special);

    (r1, r0)
}

/// FIPS 204 `HighBits`.
#[inline]
pub(crate) fn high_bits<const GAMMA2: usize>(r: i32) -> i32 {
    decompose::<GAMMA2>(r).0
}

/// FIPS 204 `LowBits`.
#[inline]
pub(crate) fn low_bits<const GAMMA2: usize>(r: i32) -> i32 {
    decompose::<GAMMA2>(r).1
}

/// FIPS 204 `MakeHint`.
///
/// Returns `Choice(1)` if adding `z` to `r` changes the high bits of `r`,
/// and `Choice(0)` otherwise.
#[inline]
pub(crate) fn make_hint<const GAMMA2: usize>(z: i32, r: i32) -> Choice {
    let h0 = high_bits::<GAMMA2>(r);
    let h1 = high_bits::<GAMMA2>(r + z);

    !ct_i32_eq(h0, h1)
}

/// FIPS 204 `UseHint`.
///
/// Applies a one-bit hint to recover the corrected high bits.
#[inline]
pub(crate) fn use_hint<const GAMMA2: usize>(hint: Choice, r: i32) -> i32 {
    assert!(GAMMA2 > 0);
    assert_eq!((Q - 1) % (2 * GAMMA2) as i32, 0);

    let m = (Q - 1) / (2 * GAMMA2) as i32;

    let (r1, r0) = decompose::<GAMMA2>(r);

    let r1_plus_raw = r1 + 1;
    let r1_minus_raw = r1 - 1;
    let r1_plus = ct_i32_select(r1_plus_raw, 0, ct_i32_eq(r1_plus_raw, m));
    let r1_minus = ct_i32_select(r1_minus_raw, m - 1, ct_i32_eq(r1, 0));

    let r0_positive = ct_i32_gt(r0, 0);
    let corrected = ct_i32_select(r1_minus, r1_plus, r0_positive);

    ct_i32_select(r1, corrected, hint)
}

/// Applies FIPS 204 `Power2Round` coefficientwise to a polynomial.
///
/// Returns `(r1, r0)`.
#[must_use]
pub(crate) fn power2round_poly<const D: usize>(
    r: &Poly<Q8380417>,
) -> (Poly<Q8380417>, Poly<Q8380417>) {
    let mut r1_coeffs = [0i32; N];
    let mut r0_coeffs = [0i32; N];

    for ((r1, r0), &coeff) in r1_coeffs
        .iter_mut()
        .zip(r0_coeffs.iter_mut())
        .zip(r.coeffs().iter())
    {
        let (hi, lo) = power2round::<D>(coeff);

        *r1 = hi;
        *r0 = lo;
    }

    (
        Poly::<Q8380417>::from_coeffs(r1_coeffs),
        Poly::<Q8380417>::from_coeffs(r0_coeffs),
    )
}

/// Applies FIPS 204 `HighBits` coefficientwise to a polynomial.
#[must_use]
pub(crate) fn high_bits_poly<const GAMMA2: usize>(r: &Poly<Q8380417>) -> Poly<Q8380417> {
    let mut coeffs = [0i32; N];

    for (out, &coeff) in coeffs.iter_mut().zip(r.coeffs().iter()) {
        *out = high_bits::<GAMMA2>(coeff);
    }

    Poly::<Q8380417>::from_coeffs(coeffs)
}

/// Applies FIPS 204 `LowBits` coefficientwise to a polynomial.
#[must_use]
pub(crate) fn low_bits_poly<const GAMMA2: usize>(r: &Poly<Q8380417>) -> Poly<Q8380417> {
    let mut coeffs = [0i32; N];

    for (out, &coeff) in coeffs.iter_mut().zip(r.coeffs().iter()) {
        *out = low_bits::<GAMMA2>(coeff);
    }

    Poly::<Q8380417>::from_coeffs(coeffs)
}

/// Applies FIPS 204 `MakeHint` coefficientwise to a polynomial.
///
/// Returns the hint bits and their Hamming weight.
#[must_use]
pub(crate) fn make_hint_poly<const GAMMA2: usize>(
    z: &Poly<Q8380417>,
    r: &Poly<Q8380417>,
) -> ([u8; N], usize) {
    let mut hint = [0u8; N];
    let mut weight = 0usize;

    for ((out, &z_coeff), &r_coeff) in hint
        .iter_mut()
        .zip(z.coeffs().iter())
        .zip(r.coeffs().iter())
    {
        let bit = make_hint::<GAMMA2>(z_coeff, r_coeff).unwrap_u8();

        *out = bit;
        weight += bit as usize;
    }

    (hint, weight)
}

/// Applies FIPS 204 `UseHint` coefficientwise to a polynomial.
#[must_use]
pub(crate) fn use_hint_poly<const GAMMA2: usize>(
    hint: &[u8; N],
    r: &Poly<Q8380417>,
) -> Poly<Q8380417> {
    let mut coeffs = [0i32; N];

    for ((out, &hint_bit), &r_coeff) in coeffs.iter_mut().zip(hint.iter()).zip(r.coeffs().iter()) {
        assert!(hint_bit <= 1);

        *out = use_hint::<GAMMA2>(Choice::from(hint_bit), r_coeff);
    }

    Poly::<Q8380417>::from_coeffs(coeffs)
}

/// Applies FIPS 204 `Power2Round` coefficientwise to a vector of polynomials.
///
/// Returns `(r1, r0)`.
#[must_use]
pub(crate) fn power2round_vec<const K: usize, const D: usize>(
    r: &PolyVec<Q8380417, K>,
) -> (PolyVec<Q8380417, K>, PolyVec<Q8380417, K>) {
    let mut r1_polys = [Poly::<Q8380417>::zero(); K];
    let mut r0_polys = [Poly::<Q8380417>::zero(); K];

    for ((r1, r0), poly) in r1_polys
        .iter_mut()
        .zip(r0_polys.iter_mut())
        .zip(r.polys().iter())
    {
        let (hi, lo) = power2round_poly::<D>(poly);

        *r1 = hi;
        *r0 = lo;
    }

    (
        PolyVec::<Q8380417, K>::from_polys(r1_polys),
        PolyVec::<Q8380417, K>::from_polys(r0_polys),
    )
}

/// Applies FIPS 204 `HighBits` coefficientwise to a vector of polynomials.
#[must_use]
pub(crate) fn high_bits_vec<const K: usize, const GAMMA2: usize>(
    r: &PolyVec<Q8380417, K>,
) -> PolyVec<Q8380417, K> {
    let mut polys = [Poly::<Q8380417>::zero(); K];

    for (out, poly) in polys.iter_mut().zip(r.polys().iter()) {
        *out = high_bits_poly::<GAMMA2>(poly);
    }

    PolyVec::<Q8380417, K>::from_polys(polys)
}

/// Applies FIPS 204 `LowBits` coefficientwise to a vector of polynomials.
#[must_use]
pub(crate) fn low_bits_vec<const K: usize, const GAMMA2: usize>(
    r: &PolyVec<Q8380417, K>,
) -> PolyVec<Q8380417, K> {
    let mut polys = [Poly::<Q8380417>::zero(); K];

    for (out, poly) in polys.iter_mut().zip(r.polys().iter()) {
        *out = low_bits_poly::<GAMMA2>(poly);
    }

    PolyVec::<Q8380417, K>::from_polys(polys)
}

/// Applies FIPS 204 `MakeHint` coefficientwise to a vector of polynomials.
///
/// Returns the hint vector and its Hamming weight.
#[must_use]
pub(crate) fn make_hint_vec<const K: usize, const GAMMA2: usize>(
    z: &PolyVec<Q8380417, K>,
    r: &PolyVec<Q8380417, K>,
) -> (HintVec<K>, usize) {
    let mut data = [[0u8; N]; K];
    let mut weight = 0usize;

    for ((hint_poly, z_poly), r_poly) in data.iter_mut().zip(z.polys().iter()).zip(r.polys().iter())
    {
        let (poly_hint, poly_weight) = make_hint_poly::<GAMMA2>(z_poly, r_poly);

        *hint_poly = poly_hint;
        weight += poly_weight;
    }

    (HintVec::from_data(data), weight)
}

/// Applies FIPS 204 `UseHint` coefficientwise to a vector of polynomials.
#[must_use]
pub(crate) fn use_hint_vec<const K: usize, const GAMMA2: usize>(
    hint: &HintVec<K>,
    r: &PolyVec<Q8380417, K>,
) -> PolyVec<Q8380417, K> {
    let mut polys = [Poly::<Q8380417>::zero(); K];

    for ((out, hint_poly), r_poly) in polys
        .iter_mut()
        .zip(hint.data().iter())
        .zip(r.polys().iter())
    {
        *out = use_hint_poly::<GAMMA2>(hint_poly, r_poly);
    }

    PolyVec::<Q8380417, K>::from_polys(polys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::Choice;

    const GAMMA2_32: usize = ((Q - 1) as usize) / 32;
    const GAMMA2_88: usize = ((Q - 1) as usize) / 88;
    const D: usize = 13;

    fn reduce_q_ref(r: i32) -> i32 {
        (r as i64).rem_euclid(Q as i64) as i32
    }

    fn mod_pm_q_ref(r: i32) -> i32 {
        let r_plus = reduce_q_ref(r);

        if r_plus > Q / 2 { r_plus - Q } else { r_plus }
    }

    fn mod_pm_power2_ref<const D: usize>(r: i32) -> i32 {
        let alpha = 1i32 << D;
        let half = 1i32 << (D - 1);

        let t = (r as i64).rem_euclid(alpha as i64) as i32;

        if t > half { t - alpha } else { t }
    }

    fn mod_pm_2gamma2<const GAMMA2: usize>(r_plus: i32) -> i32 {
        mod_pm_2gamma2_with_quotient::<GAMMA2>(r_plus).1
    }

    fn mod_pm_2gamma2_quotient_ref<const GAMMA2: usize>(r_plus: i32) -> (i32, i32) {
        let alpha = (2 * GAMMA2) as i32;
        let gamma2 = GAMMA2 as i32;

        let k = (r_plus + gamma2 - 1) / alpha;
        let r0 = r_plus - k * alpha;

        (k, r0)
    }

    fn power2round_ref<const D: usize>(r: i32) -> (i32, i32) {
        let r_plus = reduce_q_ref(r);
        let r0 = mod_pm_power2_ref::<D>(r_plus);
        let r1 = (r_plus - r0) >> D;

        (r1, r0)
    }

    fn decompose_ref<const GAMMA2: usize>(r: i32) -> (i32, i32) {
        let r_plus = reduce_q_ref(r);
        let (r1_raw, r0_raw) = mod_pm_2gamma2_quotient_ref::<GAMMA2>(r_plus);

        if r_plus - r0_raw == Q - 1 {
            (0, r0_raw - 1)
        } else {
            (r1_raw, r0_raw)
        }
    }

    fn make_hint_ref<const GAMMA2: usize>(z: i32, r: i32) -> u8 {
        let h0 = high_bits::<GAMMA2>(r);
        let h1 = high_bits::<GAMMA2>(r + z);

        (h0 != h1) as u8
    }

    fn use_hint_ref<const GAMMA2: usize>(hint: u8, r: i32) -> i32 {
        let m = (Q - 1) / (2 * GAMMA2) as i32;
        let (r1, r0) = decompose_ref::<GAMMA2>(r);

        if hint == 0 {
            r1
        } else if r0 > 0 {
            if r1 + 1 == m { 0 } else { r1 + 1 }
        } else if r1 == 0 {
            m - 1
        } else {
            r1 - 1
        }
    }

    #[test]
    fn reduce_q_canonical_returns_canonical_representative() {
        let inputs = [
            -2 * Q - 123,
            -2 * Q,
            -Q - 1,
            -Q,
            -Q + 1,
            -1,
            0,
            1,
            Q - 1,
            Q,
            Q + 1,
            2 * Q,
            2 * Q + 123,
        ];

        for &r in &inputs {
            let reduced = reduce_q_canonical(r);

            assert!(0 <= reduced, "r = {r}, reduced = {reduced}");
            assert!(reduced < Q, "r = {r}, reduced = {reduced}");
            assert_eq!(reduced, reduce_q_ref(r), "r = {r}");
        }
    }

    #[test]
    fn ct_i32_eq_matches_normal_equality() {
        let values = [i32::MIN, -Q - 1, -Q, -1, 0, 1, Q / 2, Q - 1, Q, i32::MAX];

        for &x in &values {
            for &y in &values {
                assert_eq!(ct_i32_eq(x, y).unwrap_u8(), (x == y) as u8);
            }
        }
    }

    #[test]
    fn ct_i32_gt_matches_normal_greater_than() {
        let values = [i32::MIN, -Q - 1, -Q, -1, 0, 1, Q / 2, Q - 1, Q, i32::MAX];

        for &x in &values {
            for &y in &values {
                assert_eq!(ct_i32_gt(x, y).unwrap_u8(), (x > y) as u8);
            }
        }
    }

    #[test]
    fn ct_i32_ge_matches_normal_greater_or_equal() {
        let values = [i32::MIN, -Q - 1, -Q, -1, 0, 1, Q / 2, Q - 1, Q, i32::MAX];

        for &x in &values {
            for &y in &values {
                assert_eq!(ct_i32_ge(x, y).unwrap_u8(), (x >= y) as u8);
            }
        }
    }

    #[test]
    fn mod_pm_power2_matches_reference_on_range() {
        let alpha = 1i32 << D;

        for r in -2 * alpha..=2 * alpha {
            assert_eq!(mod_pm_power2::<D>(r), mod_pm_power2_ref::<D>(r));
        }
    }

    #[test]
    fn mod_pm_power2_boundary_values() {
        let half = 1i32 << (D - 1);
        let alpha = 1i32 << D;

        assert_eq!(mod_pm_power2::<D>(0), 0);
        assert_eq!(mod_pm_power2::<D>(half - 1), half - 1);
        assert_eq!(mod_pm_power2::<D>(half), half);
        assert_eq!(mod_pm_power2::<D>(half + 1), -half + 1);
        assert_eq!(mod_pm_power2::<D>(alpha - 1), -1);
        assert_eq!(mod_pm_power2::<D>(alpha), 0);
    }

    #[test]
    fn mod_pm_q_matches_reference() {
        let inputs = [
            -2 * Q - 123,
            -2 * Q,
            -Q - 1,
            -Q,
            -Q + 1,
            -1,
            0,
            1,
            Q / 2,
            Q / 2 + 1,
            Q - 1,
            Q,
            Q + 1,
            2 * Q + 123,
        ];

        for &r in &inputs {
            assert_eq!(mod_pm_q(r), mod_pm_q_ref(r), "r = {r}");
        }
    }

    fn check_mod_pm_2gamma2_boundaries<const GAMMA2: usize>() {
        let gamma2 = GAMMA2 as i32;
        let alpha = 2 * gamma2;

        assert_eq!(mod_pm_2gamma2::<GAMMA2>(0), 0);
        assert_eq!(mod_pm_2gamma2::<GAMMA2>(gamma2 - 1), gamma2 - 1);
        assert_eq!(mod_pm_2gamma2::<GAMMA2>(gamma2), gamma2);
        assert_eq!(mod_pm_2gamma2::<GAMMA2>(gamma2 + 1), -gamma2 + 1);
        assert_eq!(mod_pm_2gamma2::<GAMMA2>(alpha - 1), -1);
        assert_eq!(mod_pm_2gamma2::<GAMMA2>(alpha), 0);
    }

    #[test]
    fn mod_pm_2gamma2_boundaries_gamma2_q_minus_one_over_32() {
        check_mod_pm_2gamma2_boundaries::<GAMMA2_32>();
    }

    #[test]
    fn mod_pm_2gamma2_boundaries_gamma2_q_minus_one_over_88() {
        check_mod_pm_2gamma2_boundaries::<GAMMA2_88>();
    }

    fn check_mod_pm_2gamma2_with_quotient_matches_reference<const GAMMA2: usize>() {
        let samples = [
            0,
            1,
            GAMMA2 as i32 - 1,
            GAMMA2 as i32,
            GAMMA2 as i32 + 1,
            2 * GAMMA2 as i32 - 1,
            2 * GAMMA2 as i32,
            2 * GAMMA2 as i32 + 1,
            Q / 2,
            Q - 2,
            Q - 1,
        ];

        for &r_plus in &samples {
            let expected = mod_pm_2gamma2_quotient_ref::<GAMMA2>(r_plus);
            let actual = mod_pm_2gamma2_with_quotient::<GAMMA2>(r_plus);

            assert_eq!(actual, expected, "r_plus = {r_plus}");
            assert_eq!(actual.1, mod_pm_2gamma2::<GAMMA2>(r_plus));
        }
    }

    #[test]
    fn mod_pm_2gamma2_with_quotient_matches_reference_gamma2_q_minus_one_over_32() {
        check_mod_pm_2gamma2_with_quotient_matches_reference::<GAMMA2_32>();
    }

    #[test]
    fn mod_pm_2gamma2_with_quotient_matches_reference_gamma2_q_minus_one_over_88() {
        check_mod_pm_2gamma2_with_quotient_matches_reference::<GAMMA2_88>();
    }

    fn check_mod_pm_2gamma2_with_quotient_full_canonical_range<const GAMMA2: usize>() {
        let step = (Q / 257).max(1);

        let mut r_plus = 0;
        while r_plus < Q {
            let expected = mod_pm_2gamma2_quotient_ref::<GAMMA2>(r_plus);
            let actual = mod_pm_2gamma2_with_quotient::<GAMMA2>(r_plus);

            assert_eq!(actual, expected, "r_plus = {r_plus}");

            let r0 = actual.1;
            assert!(
                (-(GAMMA2 as i32) + 1..=GAMMA2 as i32).contains(&r0),
                "r_plus = {r_plus}, r0 = {r0}",
            );

            r_plus += step;
        }

        let expected = mod_pm_2gamma2_quotient_ref::<GAMMA2>(Q - 1);
        let actual = mod_pm_2gamma2_with_quotient::<GAMMA2>(Q - 1);

        assert_eq!(actual, expected);
    }

    #[test]
    fn mod_pm_2gamma2_with_quotient_sampled_range_gamma2_q_minus_one_over_32() {
        check_mod_pm_2gamma2_with_quotient_full_canonical_range::<GAMMA2_32>();
    }

    #[test]
    fn mod_pm_2gamma2_with_quotient_sampled_range_gamma2_q_minus_one_over_88() {
        check_mod_pm_2gamma2_with_quotient_full_canonical_range::<GAMMA2_88>();
    }

    #[test]
    fn power2round_matches_reference() {
        let inputs = [
            -2 * Q - 123,
            -Q - 1,
            -Q,
            -1,
            0,
            1,
            (1 << (D - 1)) - 1,
            1 << (D - 1),
            (1 << (D - 1)) + 1,
            Q / 2,
            Q - 1,
            Q,
            Q + 1,
            2 * Q + 123,
        ];

        for &r in &inputs {
            assert_eq!(power2round::<D>(r), power2round_ref::<D>(r), "r = {r}");
        }
    }

    #[test]
    fn power2round_reconstructs_reduced_input() {
        let inputs = [
            -2 * Q - 123,
            -Q - 1,
            -Q,
            -1,
            0,
            1,
            Q / 2,
            Q - 1,
            Q,
            Q + 1,
            2 * Q + 123,
        ];

        for &r in &inputs {
            let r_plus = reduce_q_canonical(r);
            let (r1, r0) = power2round::<D>(r);

            assert_eq!(r1 * (1 << D) + r0, r_plus, "r = {r}");
            assert!(
                (-(1 << (D - 1)) + 1..=1 << (D - 1)).contains(&r0),
                "r = {r}, r0 = {r0}",
            );
        }
    }

    fn check_decompose_matches_reference<const GAMMA2: usize>() {
        let inputs = [
            -2 * Q - 123,
            -Q - 1,
            -Q,
            -1,
            0,
            1,
            GAMMA2 as i32 - 1,
            GAMMA2 as i32,
            GAMMA2 as i32 + 1,
            2 * GAMMA2 as i32 - 1,
            2 * GAMMA2 as i32,
            2 * GAMMA2 as i32 + 1,
            Q / 2,
            Q - 2,
            Q - 1,
            Q,
            Q + 1,
            2 * Q + 123,
        ];

        for &r in &inputs {
            assert_eq!(
                decompose::<GAMMA2>(r),
                decompose_ref::<GAMMA2>(r),
                "r = {r}"
            );
        }
    }

    #[test]
    fn decompose_matches_reference_gamma2_q_minus_one_over_32() {
        check_decompose_matches_reference::<GAMMA2_32>();
    }

    #[test]
    fn decompose_matches_reference_gamma2_q_minus_one_over_88() {
        check_decompose_matches_reference::<GAMMA2_88>();
    }

    #[test]
    fn decompose_special_case_q_minus_one_gamma2_q_minus_one_over_32() {
        assert_eq!(mod_pm_2gamma2_with_quotient::<GAMMA2_32>(Q - 1), (16, 0));
        assert_eq!(decompose::<GAMMA2_32>(Q - 1), (0, -1));
    }

    #[test]
    fn decompose_special_case_q_minus_one_gamma2_q_minus_one_over_88() {
        assert_eq!(mod_pm_2gamma2_with_quotient::<GAMMA2_88>(Q - 1), (44, 0));
        assert_eq!(decompose::<GAMMA2_88>(Q - 1), (0, -1));
    }

    fn check_decompose_reconstructs_reduced_input<const GAMMA2: usize>() {
        let inputs = [
            -Q - 1,
            -Q,
            -1,
            0,
            1,
            GAMMA2 as i32,
            GAMMA2 as i32 + 1,
            Q / 2,
            Q - 2,
            Q - 1,
            Q,
            Q + 1,
        ];

        let alpha = (2 * GAMMA2) as i32;

        for &r in &inputs {
            let r_plus = reduce_q_canonical(r);
            let (r1, r0) = decompose::<GAMMA2>(r);

            assert!(
                (-(GAMMA2 as i32)..=GAMMA2 as i32).contains(&r0),
                "r = {r}, r0 = {r0}",
            );

            let reconstructed = r1 * alpha + r0;

            assert_eq!(
                reduce_q_canonical(reconstructed),
                r_plus,
                "r = {r}, reconstructed = {reconstructed}, r_plus = {r_plus}",
            );
        }
    }

    #[test]
    fn decompose_reconstructs_reduced_input_gamma2_q_minus_one_over_32() {
        check_decompose_reconstructs_reduced_input::<GAMMA2_32>();
    }

    #[test]
    fn decompose_reconstructs_reduced_input_gamma2_q_minus_one_over_88() {
        check_decompose_reconstructs_reduced_input::<GAMMA2_88>();
    }

    fn check_high_bits_and_low_bits_match_decompose<const GAMMA2: usize>() {
        let inputs = [
            -Q - 1,
            -Q,
            -1,
            0,
            1,
            GAMMA2 as i32,
            GAMMA2 as i32 + 1,
            Q / 2,
            Q - 1,
            Q,
            Q + 1,
        ];

        for &r in &inputs {
            let (r1, r0) = decompose::<GAMMA2>(r);

            assert_eq!(high_bits::<GAMMA2>(r), r1);
            assert_eq!(low_bits::<GAMMA2>(r), r0);
        }
    }

    #[test]
    fn high_bits_and_low_bits_match_decompose_gamma2_q_minus_one_over_32() {
        check_high_bits_and_low_bits_match_decompose::<GAMMA2_32>();
    }

    #[test]
    fn high_bits_and_low_bits_match_decompose_gamma2_q_minus_one_over_88() {
        check_high_bits_and_low_bits_match_decompose::<GAMMA2_88>();
    }

    fn check_make_hint_matches_reference<const GAMMA2: usize>() {
        let pairs = [
            (0, 0),
            (1, 0),
            (-1, 0),
            (GAMMA2 as i32, 0),
            (GAMMA2 as i32 + 1, 0),
            (1, Q / 2),
            (-1, Q / 2),
            (12345, Q - 12345),
            (-12345, 12345),
        ];

        for &(z, r) in &pairs {
            let expected = make_hint_ref::<GAMMA2>(z, r);
            let actual = make_hint::<GAMMA2>(z, r).unwrap_u8();

            assert_eq!(actual, expected, "z = {z}, r = {r}");
        }
    }

    #[test]
    fn make_hint_matches_reference_gamma2_q_minus_one_over_32() {
        check_make_hint_matches_reference::<GAMMA2_32>();
    }

    #[test]
    fn make_hint_matches_reference_gamma2_q_minus_one_over_88() {
        check_make_hint_matches_reference::<GAMMA2_88>();
    }

    fn check_use_hint_matches_reference<const GAMMA2: usize>() {
        let inputs = [
            0,
            1,
            GAMMA2 as i32 - 1,
            GAMMA2 as i32,
            GAMMA2 as i32 + 1,
            2 * GAMMA2 as i32 - 1,
            Q / 2,
            Q - 2,
            Q - 1,
            Q,
            Q + 1,
            -1,
            -Q + 1,
        ];

        for &r in &inputs {
            for hint in [0u8, 1u8] {
                let expected = use_hint_ref::<GAMMA2>(hint, r);
                let actual = use_hint::<GAMMA2>(Choice::from(hint), r);

                assert_eq!(actual, expected, "hint = {hint}, r = {r}");
            }
        }
    }

    #[test]
    fn use_hint_matches_reference_gamma2_q_minus_one_over_32() {
        check_use_hint_matches_reference::<GAMMA2_32>();
    }

    #[test]
    fn use_hint_matches_reference_gamma2_q_minus_one_over_88() {
        check_use_hint_matches_reference::<GAMMA2_88>();
    }

    fn check_use_hint_zero_returns_high_bits<const GAMMA2: usize>() {
        let inputs = [
            -Q - 1,
            -Q,
            -1,
            0,
            1,
            GAMMA2 as i32,
            GAMMA2 as i32 + 1,
            Q / 2,
            Q - 1,
            Q,
            Q + 1,
        ];

        for &r in &inputs {
            assert_eq!(
                use_hint::<GAMMA2>(Choice::from(0u8), r),
                high_bits::<GAMMA2>(r),
                "r = {r}",
            );
        }
    }

    #[test]
    fn use_hint_zero_returns_high_bits_gamma2_q_minus_one_over_32() {
        check_use_hint_zero_returns_high_bits::<GAMMA2_32>();
    }

    #[test]
    fn use_hint_zero_returns_high_bits_gamma2_q_minus_one_over_88() {
        check_use_hint_zero_returns_high_bits::<GAMMA2_88>();
    }

    fn sample_poly() -> Poly<Q8380417> {
        let mut coeffs = [0i32; N];

        for (i, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = match i % 8 {
                0 => 0,
                1 => 1,
                2 => Q - 1,
                3 => Q - 2,
                4 => Q / 2,
                5 => GAMMA2_32 as i32,
                6 => -(GAMMA2_32 as i32),
                _ => i as i32 * 17 - 1234,
            };
        }

        Poly::<Q8380417>::from_coeffs(coeffs)
    }

    fn sample_poly_vec<const K: usize>() -> PolyVec<Q8380417, K> {
        let mut polys = [Poly::<Q8380417>::zero(); K];

        for (j, poly) in polys.iter_mut().enumerate() {
            let mut coeffs = [0i32; N];

            for (i, coeff) in coeffs.iter_mut().enumerate() {
                *coeff = match (i + j) % 8 {
                    0 => 0,
                    1 => 1,
                    2 => Q - 1,
                    3 => Q - 2,
                    4 => Q / 2,
                    5 => GAMMA2_32 as i32 + j as i32,
                    6 => -(GAMMA2_32 as i32) + j as i32,
                    _ => (i as i32 * 17) - (j as i32 * 31) - 1234,
                };
            }

            *poly = Poly::<Q8380417>::from_coeffs(coeffs);
        }

        PolyVec::<Q8380417, K>::from_polys(polys)
    }

    #[test]
    fn power2round_poly_matches_scalar() {
        let poly = sample_poly();

        let (r1, r0) = power2round_poly::<D>(&poly);

        for i in 0..N {
            let expected = power2round::<D>(poly.coeffs()[i]);

            assert_eq!(r1.coeffs()[i], expected.0, "i = {i}");
            assert_eq!(r0.coeffs()[i], expected.1, "i = {i}");
        }
    }

    #[test]
    fn high_bits_poly_matches_scalar() {
        let poly = sample_poly();

        let high = high_bits_poly::<GAMMA2_32>(&poly);

        for i in 0..N {
            assert_eq!(
                high.coeffs()[i],
                high_bits::<GAMMA2_32>(poly.coeffs()[i]),
                "i = {i}",
            );
        }
    }

    #[test]
    fn low_bits_poly_matches_scalar() {
        let poly = sample_poly();

        let low = low_bits_poly::<GAMMA2_32>(&poly);

        for i in 0..N {
            assert_eq!(
                low.coeffs()[i],
                low_bits::<GAMMA2_32>(poly.coeffs()[i]),
                "i = {i}",
            );
        }
    }

    #[test]
    fn make_hint_poly_matches_scalar_and_counts_weight() {
        let z = sample_poly();
        let r = sample_poly();

        let (hint, weight) = make_hint_poly::<GAMMA2_32>(&z, &r);

        let mut expected_weight = 0usize;

        for i in 0..N {
            let expected = make_hint::<GAMMA2_32>(z.coeffs()[i], r.coeffs()[i]).unwrap_u8();

            assert_eq!(hint[i], expected, "i = {i}");

            expected_weight += expected as usize;
        }

        assert_eq!(weight, expected_weight);
    }

    #[test]
    fn use_hint_poly_matches_scalar() {
        let r = sample_poly();

        let mut hint = [0u8; N];
        for (i, bit) in hint.iter_mut().enumerate() {
            *bit = (i & 1) as u8;
        }

        let out = use_hint_poly::<GAMMA2_32>(&hint, &r);

        for i in 0..N {
            let expected = use_hint::<GAMMA2_32>(Choice::from(hint[i]), r.coeffs()[i]);

            assert_eq!(out.coeffs()[i], expected, "i = {i}");
        }
    }

    #[test]
    fn power2round_vec_matches_poly_wrapper() {
        const K: usize = 3;

        let v = sample_poly_vec::<K>();

        let (v1, v0) = power2round_vec::<K, D>(&v);

        for j in 0..K {
            let expected = power2round_poly::<D>(&v.polys()[j]);

            assert_eq!(v1.polys()[j], expected.0, "j = {j}");
            assert_eq!(v0.polys()[j], expected.1, "j = {j}");
        }
    }

    #[test]
    fn high_bits_vec_matches_poly_wrapper() {
        const K: usize = 3;

        let v = sample_poly_vec::<K>();

        let high = high_bits_vec::<K, GAMMA2_32>(&v);

        for j in 0..K {
            assert_eq!(
                high.polys()[j],
                high_bits_poly::<GAMMA2_32>(&v.polys()[j]),
                "j = {j}",
            );
        }
    }

    #[test]
    fn low_bits_vec_matches_poly_wrapper() {
        const K: usize = 3;

        let v = sample_poly_vec::<K>();

        let low = low_bits_vec::<K, GAMMA2_32>(&v);

        for j in 0..K {
            assert_eq!(
                low.polys()[j],
                low_bits_poly::<GAMMA2_32>(&v.polys()[j]),
                "j = {j}",
            );
        }
    }

    #[test]
    fn make_hint_vec_matches_poly_wrapper_and_counts_weight() {
        const K: usize = 3;

        let z = sample_poly_vec::<K>();
        let r = sample_poly_vec::<K>();

        let (hint, weight) = make_hint_vec::<K, GAMMA2_32>(&z, &r);

        let mut expected_weight = 0usize;

        for j in 0..K {
            let (expected_hint, expected_poly_weight) =
                make_hint_poly::<GAMMA2_32>(&z.polys()[j], &r.polys()[j]);

            assert_eq!(&hint.data()[j], &expected_hint, "j = {j}");

            expected_weight += expected_poly_weight;
        }

        assert_eq!(weight, expected_weight);
    }

    #[test]
    fn use_hint_vec_matches_poly_wrapper() {
        const K: usize = 3;

        let r = sample_poly_vec::<K>();

        let mut data = [[0u8; N]; K];

        for j in 0..K {
            for i in 0..N {
                data[j][i] = ((i + j) & 1) as u8;
            }
        }

        let hint = HintVec::<K>::from_data(data);

        let out = use_hint_vec::<K, GAMMA2_32>(&hint, &r);

        for j in 0..K {
            let expected = use_hint_poly::<GAMMA2_32>(&data[j], &r.polys()[j]);

            assert_eq!(out.polys()[j], expected, "j = {j}");
        }
    }
}
