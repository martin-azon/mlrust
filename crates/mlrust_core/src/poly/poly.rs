//! Single-polynomial arithmetic.
//!
//! This module defines [`Poly`], the fixed-degree polynomial type used by the
//! shared lattice-arithmetic layer.
//!
//! A polynomial is represented as an array of `N = 256` signed coefficients.
//! The coefficient modulus is not stored at runtime; instead, it is determined
//! by the type parameter `P`, which implements [`crate::params::RingParams`].
//!
//! The type intentionally separates:
//!
//! - in-place operations such as [`Poly::add_assign`] and [`Poly::sub_assign`],
//!   which mutate an existing polynomial;
//! - non-mutating operations such as [`Poly::add`] and [`Poly::sub`], which
//!   return a new polynomial.
//!
//! This gives higher-level code both efficient mutation primitives and clearer
//! value-returning helpers.
//!
//! Coefficients are not guaranteed to be canonical after every operation.
//! Use [`Poly::freeze`] before serialization or tests that require values in
//! `[0, q)`.

use crate::params::{N, NttDomainMul, NttOps, RingParams};
use core::marker::PhantomData;

/// Polynomial over the ring `Z_q[x] / (x^N + 1)`.
///
/// The coefficient modulus `q` and reduction routines are provided by the
/// type parameter `P`.
///
/// In this crate, `N` is fixed to `256`, which is the polynomial degree used
/// by both ML-KEM and ML-DSA.
///
/// Coefficients are stored as signed `i32` values. They are not necessarily
/// canonical at all times; many arithmetic routines keep coefficients in a
/// reduced internal representation. Use [`Poly::freeze`] before serialization,
/// comparison against canonical encodings, or tests requiring coefficients in
/// `[0, q)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly<P: RingParams> {
    coeffs: [i32; N],
    _params: PhantomData<P>,
}

impl<P: RingParams> Poly<P> {
    /// Returns the zero polynomial.
    ///
    /// All coefficients are initialized to `0`.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            coeffs: [0i32; N],
            _params: PhantomData,
        }
    }

    /// Creates a polynomial from a fixed-size coefficient array.
    ///
    /// This function does not reduce or canonicalize the coefficients. The
    /// caller is responsible for ensuring that the input coefficients are in
    /// the expected range, or for calling [`Poly::reduce`] or [`Poly::freeze`]
    /// afterwards.
    #[must_use]
    pub const fn from_coeffs(coeffs: [i32; N]) -> Self {
        Self {
            coeffs,
            _params: PhantomData,
        }
    }

    /// Returns an immutable reference to the coefficient array.
    ///
    /// The returned coefficients may be in an internal reduced representation,
    /// not necessarily in canonical range `[0, q)`.
    #[must_use]
    pub fn coeffs(&self) -> &[i32; N] {
        &self.coeffs
    }

    /// Returns a mutable reference to the coefficient array.
    ///
    /// This is useful for sampling, decoding, and low-level arithmetic routines
    /// that need direct coefficient access.
    ///
    /// The caller must preserve any invariants required by later operations.
    #[must_use]
    pub fn coeffs_mut(&mut self) -> &mut [i32; N] {
        &mut self.coeffs
    }

    /// Consumes the polynomial and returns its coefficient array.
    ///
    /// This is useful for tests, encoding routines, or APIs that need ownership
    /// of the raw coefficients.
    #[must_use]
    pub fn into_coeffs(self) -> [i32; N] {
        self.coeffs
    }

    /// Reduces every coefficient using the parameter set's Barrett reduction.
    ///
    /// This usually returns coefficients to a small internal representative
    /// range modulo `q`, but it does not necessarily canonicalize them into
    /// `[0, q)`.
    ///
    /// Use [`Poly::freeze`] when canonical representatives are required.
    pub fn reduce(&mut self) {
        for c in &mut self.coeffs {
            *c = P::barrett_reduce(*c)
        }
    }

    /// Canonicalizes every coefficient into the range `[0, q)`.
    ///
    /// This should be used before serialization, byte encoding, or tests that
    /// compare against canonical modular representatives.
    pub fn freeze(&mut self) {
        for c in &mut self.coeffs {
            *c = P::freeze(*c)
        }
    }

    /// Adds another polynomial to this polynomial in place.
    ///
    /// Each coefficient is updated as:
    ///
    /// ```text
    /// self[i] = self[i] + rhs[i] mod q
    /// ```
    ///
    /// The result is reduced with Barrett reduction, but not necessarily
    /// canonicalized into `[0, q)`.
    pub fn add_assign(&mut self, rhs: &Self) {
        for (a, b) in self.coeffs.iter_mut().zip(rhs.coeffs.iter()) {
            *a = P::barrett_reduce(*a + *b)
        }
    }

    /// Subtracts another polynomial from this polynomial in place.
    ///
    /// Each coefficient is updated as:
    ///
    /// ```text
    /// self[i] = self[i] - rhs[i] mod q
    /// ```
    ///
    /// The result is reduced with Barrett reduction, but not necessarily
    /// canonicalized into `[0, q)`.
    pub fn sub_assign(&mut self, rhs: &Self) {
        for (a, b) in self.coeffs.iter_mut().zip(rhs.coeffs.iter()) {
            *a = P::barrett_reduce(*a - *b)
        }
    }

    /// Returns the coefficientwise sum of two polynomials.
    ///
    /// This does not modify either input polynomial.
    ///
    /// Internally, this copies `self`, applies [`Poly::add_assign`], and returns
    /// the result.
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        let mut out = *self;
        out.add_assign(rhs);
        out
    }

    /// Returns the coefficientwise difference of two polynomials.
    ///
    /// This does not modify either input polynomial.
    ///
    /// Internally, this copies `self`, applies [`Poly::sub_assign`], and returns
    /// the result.
    #[must_use]
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut out = *self;
        out.sub_assign(rhs);
        out
    }

    /// Returns the product of a polynomial by a constant.
    ///
    /// This does not modify the input polynomial.
    #[must_use]
    pub fn mul_by_constant(&self, cst: &i32) -> Self {
        let mut coeffs_output = [0i32; N];

        for i in 0..N {
            coeffs_output[i] = self.coeffs[i] * cst;
        }

        Poly::from_coeffs(coeffs_output)
    }

    /// Multiplies two polynomials using slow schoolbook negacyclic multiplication.
    ///
    /// This computes multiplication in:
    ///
    /// ```text
    /// Z_q[x] / (x^N + 1)
    /// ```
    ///
    /// Since `x^N = -1` in this quotient ring, terms of degree `N` or larger wrap
    /// around with a negative sign:
    ///
    /// ```text
    /// x^{N+k} = -x^k
    /// ```
    ///
    /// This function is primarily intended as a correctness reference for testing
    /// NTT-based multiplication. It is not intended for performance-critical code.
    pub fn schoolbook_mul_negacyclic(&self, other: &Self) -> Self {
        let mut acc = [0i64; N];

        for i in 0..N {
            for j in 0..N {
                let prod = (self.coeffs[i] as i64) * (other.coeffs[j] as i64);
                let degree = i + j;

                if degree < N {
                    acc[degree] += prod;
                } else {
                    acc[degree - N] -= prod;
                }
            }
        }

        let mut coeffs = [0i32; N];
        for i in 0..N {
            // We use rem_euclid instead of P::freeze because the current function is mostly for debug purposes.
            // When working with P::freeze, there might issues due to working internally with huge values.
            coeffs[i] = acc[i].rem_euclid(P::Q as i64) as i32;
        }

        Self::from_coeffs(coeffs)
    }
}

impl<P: NttOps> Poly<P> {
    /// Applies the forward NTT in place
    pub fn ntt(&mut self) {
        P::ntt_in_place(self.coeffs_mut());
    }

    /// Applies the inverse NTT in place
    pub fn inv_ntt(&mut self) {
        P::inv_ntt_in_place(self.coeffs_mut());
    }
}

impl<P: NttDomainMul> Poly<P> {
    /// Multiplies two NTT-domain polynomials and returns the product.
    #[must_use]
    pub fn mul_ntt(&self, rhs: &Self) -> Self {
        let mut prod = [0i32; N];
        P::mul_ntt(self.coeffs(), rhs.coeffs(), &mut prod);
        Poly::<P>::from_coeffs(prod)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{Q3329, Q8380417};

    fn reference_mod(a: i64, q: i32) -> i32 {
        a.rem_euclid(q as i64) as i32
    }

    fn sparse_poly<P: RingParams>(terms: &[(usize, i32)]) -> Poly<P> {
        let mut coeffs = [0i32; N];

        for &(i, c) in terms {
            coeffs[i] = c;
        }

        Poly::from_coeffs(coeffs)
    }

    fn assert_sparse_coeffs_mod_q<P: RingParams>(poly: &Poly<P>, expected_terms: &[(usize, i64)]) {
        let mut expected = [0i32; N];

        for &(i, c) in expected_terms {
            expected[i] = reference_mod(c, P::Q);
        }

        for i in 0..N {
            assert_eq!(
                P::freeze(poly.coeffs()[i]),
                expected[i],
                "coefficient mismatch at index {i}"
            );
        }
    }

    #[test]
    fn zero_has_all_zero_coefficients() {
        let p = Poly::<Q3329>::zero();

        assert!(p.coeffs().iter().all(|&c| c == 0));
    }

    #[test]
    fn from_coeffs_roundtrip() {
        let mut coeffs = [0i32; N];
        coeffs[0] = 1;
        coeffs[1] = -2;
        coeffs[255] = 42;

        let p = Poly::<Q3329>::from_coeffs(coeffs);

        assert_eq!(p.into_coeffs(), coeffs);
    }

    #[test]
    fn add_matches_reference_q3329() {
        let mut a_coeffs = [0i32; N];
        let mut b_coeffs = [0i32; N];

        for i in 0..N {
            a_coeffs[i] = i as i32 - 100;
            b_coeffs[i] = 2 * i as i32 - 300;
        }

        let a = Poly::<Q3329>::from_coeffs(a_coeffs);
        let b = Poly::<Q3329>::from_coeffs(b_coeffs);
        let c = a.add(&b);

        for i in 0..N {
            let expected = reference_mod((a_coeffs[i] + b_coeffs[i]) as i64, Q3329::Q);
            assert_eq!(Q3329::freeze(c.coeffs()[i]), expected, "i = {i}");
        }
    }

    #[test]
    fn sub_matches_reference_q3329() {
        let mut a_coeffs = [0i32; N];
        let mut b_coeffs = [0i32; N];

        for i in 0..N {
            a_coeffs[i] = (i as i32 % 37) - 18;
            b_coeffs[i] = (3 * i as i32 % 53) - 26;
        }

        let a = Poly::<Q3329>::from_coeffs(a_coeffs);
        let b = Poly::<Q3329>::from_coeffs(b_coeffs);
        let c = a.sub(&b);

        for i in 0..N {
            let expected = reference_mod((a_coeffs[i] - b_coeffs[i]) as i64, Q3329::Q);
            assert_eq!(Q3329::freeze(c.coeffs()[i]), expected, "i = {i}");
        }
    }

    #[test]
    fn negacyclic_mul_simple_wraparound_q3329() {
        let mut a_coeffs = [0i32; N];
        let mut b_coeffs = [0i32; N];

        // x^255 * x = x^256 = -1 mod (x^256 + 1)
        a_coeffs[255] = 1;
        b_coeffs[1] = 1;

        let a = Poly::<Q3329>::from_coeffs(a_coeffs);
        let b = Poly::<Q3329>::from_coeffs(b_coeffs);

        let c = a.schoolbook_mul_negacyclic(&b);
        assert_eq!(Q3329::freeze(c.coeffs()[0]), Q3329::Q - 1);

        for i in 1..N {
            assert_eq!(Q3329::freeze(c.coeffs()[i]), 0, "i = {i}");
        }
    }

    #[test]
    fn negacyclic_mul_simple_wraparound_q8380417() {
        let mut a_coeffs = [0i32; N];
        let mut b_coeffs = [0i32; N];

        a_coeffs[255] = 1;
        b_coeffs[1] = 1;

        let a = Poly::<Q8380417>::from_coeffs(a_coeffs);
        let b = Poly::<Q8380417>::from_coeffs(b_coeffs);

        let c = a.schoolbook_mul_negacyclic(&b);

        assert_eq!(Q8380417::freeze(c.coeffs()[0]), Q8380417::Q - 1);

        for i in 1..N {
            assert_eq!(Q8380417::freeze(c.coeffs()[i]), 0, "i = {i}");
        }
    }

    #[test]
    fn negacyclic_mul_sparse_wraparound_many_terms_q3329() {
        let a = sparse_poly::<Q3329>(&[(0, 12), (1, -7), (127, 5), (200, -9), (255, 4)]);

        let b = sparse_poly::<Q3329>(&[(0, -3), (2, 8), (56, -6), (128, 7), (255, -5)]);

        let c = a.schoolbook_mul_negacyclic(&b);

        assert_sparse_coeffs_mod_q::<Q3329>(
            &c,
            &[
                (0, -125),
                (1, -11),
                (2, 96),
                (3, -56),
                (55, 24),
                (56, -72),
                (57, 42),
                (72, 63),
                (126, 25),
                (127, -43),
                (128, 84),
                (129, -9),
                (183, -30),
                (199, -45),
                (200, 27),
                (202, -72),
                (254, 20),
                (255, -37),
            ],
        );
    }

    #[test]
    fn negacyclic_mul_collisions_and_cancellations_q3329() {
        let a = sparse_poly::<Q3329>(&[(10, 3), (50, -4), (240, 8), (255, -2)]);

        let b = sparse_poly::<Q3329>(&[(90, 5), (50, 6), (30, -7), (20, 11)]);

        let c = a.schoolbook_mul_negacyclic(&b);

        assert_sparse_coeffs_mod_q::<Q3329>(
            &c,
            &[
                (4, -88),
                (14, 56),
                (19, 22),
                (29, -14),
                (30, 33),
                (34, -48),
                (40, -21),
                (49, 12),
                (60, 18),
                (70, -44),
                (74, -40),
                (80, 28),
                (89, 10),
                (100, -9),
                (140, -20),
            ],
        );
    }

    #[test]
    fn negacyclic_mul_high_canonical_coefficients_q3329() {
        let q = Q3329::Q;

        let a = sparse_poly::<Q3329>(&[
            (0, q - 1), // -1 mod q
            (255, 2),
        ]);

        let b = sparse_poly::<Q3329>(&[
            (0, q - 2), // -2 mod q
            (1, 3),
        ]);

        let c = a.schoolbook_mul_negacyclic(&b);

        // (q-1 + 2x^255)(q-2 + 3x)
        //
        // Interpreting q-1 = -1 and q-2 = -2:
        //
        // constant term:
        //   (-1)(-2) + (2)(3)x^256
        //   = 2 - 6
        //   = -4
        //
        // x term:
        //   (-1)(3)
        //   = -3
        //
        // x^255 term:
        //   2(-2)
        //   = -4
        assert_sparse_coeffs_mod_q::<Q3329>(&c, &[(0, -4), (1, -3), (255, -4)]);
    }

    #[test]
    fn negacyclic_mul_sparse_wraparound_many_terms_q8380417() {
        let a = sparse_poly::<Q8380417>(&[(0, 12), (1, -7), (127, 5), (200, -9), (255, 4)]);

        let b = sparse_poly::<Q8380417>(&[(0, -3), (2, 8), (56, -6), (128, 7), (255, -5)]);

        let c = a.schoolbook_mul_negacyclic(&b);

        assert_sparse_coeffs_mod_q::<Q8380417>(
            &c,
            &[
                (0, -125),
                (1, -11),
                (2, 96),
                (3, -56),
                (55, 24),
                (56, -72),
                (57, 42),
                (72, 63),
                (126, 25),
                (127, -43),
                (128, 84),
                (129, -9),
                (183, -30),
                (199, -45),
                (200, 27),
                (202, -72),
                (254, 20),
                (255, -37),
            ],
        );
    }

    /*
    #[test]
    fn negacyclic_mul_high_canonical_coefficients_q8380417() {
        let q = Q8380417::Q;

        let a = sparse_poly::<Q8380417>(&[
            (0, q - 1), // -1 mod q
            (255, 2),
        ]);

        let b = sparse_poly::<Q8380417>(&[
            (0, q - 2), // -2 mod q
            (1, 3),
        ]);

        let c = a.schoolbook_mul_negacyclic(&b);

        assert_sparse_coeffs_mod_q::<Q8380417>(
            &c,
            &[
                (0, -4),
                (1, -3),
                (255, -4),
            ],
        );
    }
    */
}
