//! ML-DSA infinity-norm routines.
//!
//! This module implements the coefficient, polynomial, and polynomial-vector
//! infinity norms used by ML-DSA signing and verification.
//!
//! The relevant norm is computed over centered representatives modulo `q`.
//! For a coefficient `x`, this module computes:
//!
//! ```text
//! |x mod± q|
//! ```
//!
//! For a polynomial:
//!
//! ```text
//! ||w||∞ = max_i |w_i mod± q|
//! ```
//!
//! For a polynomial vector:
//!
//! ```text
//! ||v||∞ = max_j ||v_j||∞
//! ```

use crate::primitives::rounding::mod_pm_q;
use mlrust_core::params::Q8380417;
use mlrust_core::poly::{Poly, PolyVec};
use subtle::{ConditionallySelectable, ConstantTimeGreater};

/// Computes the absolute value of an `i32` as a `u32`, branchlessly.
///
/// This handles `i32::MIN` without overflow:
///
/// ```text
/// ct_i32_abs(i32::MIN) = 2^31
/// ```
#[inline]
fn ct_i32_abs(x: i32) -> u32 {
    let ux = x as u32;
    let mask = ux >> 31;
    let mask = 0u32.wrapping_sub(mask);

    (ux ^ mask).wrapping_sub(mask)
}

/// Returns `max(a, b)` branchlessly.
#[inline]
fn ct_u32_max(a: u32, b: u32) -> u32 {
    u32::conditional_select(&a, &b, b.ct_gt(&a))
}

/// Computes the centered coefficient norm over `Z_q`.
///
/// This returns:
///
/// ```text
/// |x mod± q|
/// ```
///
/// where `mod± q` is the centered representative modulo `q`.
#[must_use]
pub(crate) fn norm_zq(x: i32) -> u32 {
    let x_mod_pm_q = mod_pm_q(x);
    ct_i32_abs(x_mod_pm_q)
}

/// Computes the infinity norm of a polynomial vector over `Z_q`.
///
/// This returns:
///
/// ```text
/// max_j ||v_j||∞
/// ```
#[must_use]
pub(crate) fn norm_poly_zq(poly: Poly<Q8380417>) -> u32 {
    let mut max = 0u32;

    for coeff in poly.into_coeffs().iter() {
        let coeff_norm = norm_zq(*coeff);
        max = ct_u32_max(max, coeff_norm);
    }

    max
}

/// Computes the infinity norm of a polynomial vector over `Z_q`.
///
/// This returns:
///
/// ```text
/// max_j ||w_j||
/// ```
///
/// where each `w_j` is a polynomial over `Z_q`.
#[must_use]
pub(crate) fn norm_polyvec_zq<const K: usize>(vec: PolyVec<Q8380417, K>) -> u32 {
    let mut max = 0u32;

    for poly in vec.into_polys().iter() {
        let poly_norm = norm_poly_zq(*poly);
        max = ct_u32_max(max, poly_norm);
    }

    max
}

#[cfg(test)]
mod tests {
    use super::*;
    use mlrust_core::params::{N, RingParams};

    const Q: i32 = Q8380417::Q;

    fn reduce_q_ref(x: i32) -> i32 {
        (x as i64).rem_euclid(Q as i64) as i32
    }

    fn mod_pm_q_ref(x: i32) -> i32 {
        let x_plus = reduce_q_ref(x);

        if x_plus > Q / 2 { x_plus - Q } else { x_plus }
    }

    fn norm_zq_ref(x: i32) -> u32 {
        mod_pm_q_ref(x).unsigned_abs()
    }

    fn poly_from_coeffs(coeffs: &[(usize, i32)]) -> Poly<Q8380417> {
        let mut data = [0i32; N];

        for &(i, coeff) in coeffs {
            data[i] = coeff;
        }

        Poly::<Q8380417>::from_coeffs(data)
    }

    #[test]
    fn ct_i32_abs_matches_expected_values() {
        assert_eq!(ct_i32_abs(0), 0);
        assert_eq!(ct_i32_abs(1), 1);
        assert_eq!(ct_i32_abs(-1), 1);
        assert_eq!(ct_i32_abs(42), 42);
        assert_eq!(ct_i32_abs(-42), 42);
        assert_eq!(ct_i32_abs(i32::MAX), i32::MAX as u32);
        assert_eq!(ct_i32_abs(i32::MIN), 2_147_483_648u32);
    }

    #[test]
    fn ct_u32_max_matches_normal_max() {
        let values = [0u32, 1, 2, 17, 255, 256, 1024, u32::MAX / 2, u32::MAX];

        for &a in &values {
            for &b in &values {
                assert_eq!(ct_u32_max(a, b), a.max(b), "a = {a}, b = {b}");
            }
        }
    }

    #[test]
    fn norm_zq_matches_reference_on_representative_values() {
        let inputs = [
            -2 * Q - 123,
            -2 * Q,
            -Q - 1,
            -Q,
            -Q + 1,
            -1,
            0,
            1,
            Q / 2 - 1,
            Q / 2,
            Q / 2 + 1,
            Q - 2,
            Q - 1,
            Q,
            Q + 1,
            2 * Q + 123,
        ];

        for &x in &inputs {
            assert_eq!(norm_zq(x), norm_zq_ref(x), "x = {x}");
        }
    }

    #[test]
    fn norm_zq_handles_centered_boundaries() {
        assert_eq!(norm_zq(0), 0);
        assert_eq!(norm_zq(1), 1);
        assert_eq!(norm_zq(-1), 1);
        assert_eq!(norm_zq(Q - 1), 1);
        assert_eq!(norm_zq(Q + 1), 1);
        assert_eq!(norm_zq(Q / 2), (Q / 2) as u32);
        assert_eq!(norm_zq(Q / 2 + 1), (Q / 2) as u32);
    }

    #[test]
    fn norm_poly_zq_zero_poly_is_zero() {
        let poly = Poly::<Q8380417>::zero();

        assert_eq!(norm_poly_zq(poly), 0);
    }

    #[test]
    fn norm_poly_zq_returns_largest_coefficient_norm() {
        let poly = poly_from_coeffs(&[(0, 0), (1, 7), (2, -11), (3, Q - 23), (4, 1234), (5, -999)]);

        assert_eq!(norm_poly_zq(poly), 1234);
    }

    #[test]
    fn norm_poly_zq_handles_mod_q_boundary_coefficients() {
        let poly = poly_from_coeffs(&[(0, Q - 1), (1, Q - 2), (2, Q / 2), (3, Q / 2 + 1)]);

        assert_eq!(norm_poly_zq(poly), (Q / 2) as u32);
    }

    #[test]
    fn norm_poly_zq_matches_reference_for_sampled_coefficients() {
        let mut coeffs = [0i32; N];

        for (i, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = match i % 10 {
                0 => 0,
                1 => 1,
                2 => -1,
                3 => Q - 1,
                4 => Q / 2,
                5 => Q / 2 + 1,
                6 => Q + i as i32,
                7 => -Q - i as i32,
                8 => i as i32 * 17 - 2048,
                _ => 2048 - i as i32 * 19,
            };
        }

        let poly = Poly::<Q8380417>::from_coeffs(coeffs);

        let expected = coeffs.iter().map(|&x| norm_zq_ref(x)).max().unwrap();

        assert_eq!(norm_poly_zq(poly), expected);
    }

    #[test]
    fn norm_polyvec_zq_zero_vec_is_zero() {
        const K: usize = 3;

        let vec = PolyVec::<Q8380417, K>::zero();

        assert_eq!(norm_polyvec_zq(vec), 0);
    }

    #[test]
    fn norm_polyvec_zq_returns_largest_polynomial_norm() {
        const K: usize = 3;

        let p0 = poly_from_coeffs(&[(0, 7), (1, -11)]);
        let p1 = poly_from_coeffs(&[(0, 1234), (1, Q - 55)]);
        let p2 = poly_from_coeffs(&[(0, -999), (1, 42)]);

        let vec = PolyVec::<Q8380417, K>::from_polys([p0, p1, p2]);

        assert_eq!(norm_polyvec_zq(vec), 1234);
    }

    #[test]
    fn norm_polyvec_zq_matches_reference_for_sampled_coefficients() {
        const K: usize = 4;

        let mut polys = [Poly::<Q8380417>::zero(); K];
        let mut expected = 0u32;

        for (j, poly) in polys.iter_mut().enumerate() {
            let mut coeffs = [0i32; N];

            for (i, coeff) in coeffs.iter_mut().enumerate() {
                *coeff = match (i + j) % 10 {
                    0 => 0,
                    1 => 1,
                    2 => -1,
                    3 => Q - 1,
                    4 => Q / 2,
                    5 => Q / 2 + 1,
                    6 => Q + i as i32 + j as i32,
                    7 => -Q - i as i32 - j as i32,
                    8 => i as i32 * 17 - j as i32 * 31 - 2048,
                    _ => 2048 - i as i32 * 19 + j as i32 * 13,
                };

                expected = expected.max(norm_zq_ref(*coeff));
            }

            *poly = Poly::<Q8380417>::from_coeffs(coeffs);
        }

        let vec = PolyVec::<Q8380417, K>::from_polys(polys);

        assert_eq!(norm_polyvec_zq(vec), expected);
    }
}
