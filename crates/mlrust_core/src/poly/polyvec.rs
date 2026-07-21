//! Polynomial-vector arithmetic.
//!
//! This module defines [`PolyVec`], a fixed-size vector of polynomials.
//!
//! The length of the vector is encoded at the type level by the const generic
//! parameter `K`. The coefficient modulus and reduction routines are provided
//! by the type parameter `P`, which implements [`crate::params::RingParams`].
//!
//! For example:
//!
//! ```ignore
//! PolyVec<Q3329, 3>     // length-3 vector over q = 3329
//! PolyVec<Q8380417, 4>  // length-4 vector over q = 8380417
//! ```
//!
//! Like [`crate::poly::Poly`], coefficients are not necessarily canonical after
//! every operation. Use [`PolyVec::freeze`] when canonical representatives in
//! `[0, q)` are required.

use super::Poly;
use crate::params::{NttDomainMul, NttOps, RingParams};

/// Fixed-size vector of polynomials over a modulus specified by `P`.
///
/// The vector contains exactly `K` polynomials. The parameter type `P`
/// determines the coefficient modulus and reduction routines.
///
/// This type is intended for module-lattice operations in ML-KEM and ML-DSA.
/// It provides basic coefficientwise arithmetic, reduction, and accessors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyVec<P: RingParams, const K: usize> {
    polys: [Poly<P>; K],
}

impl<P: RingParams, const K: usize> PolyVec<P, K> {
    /// Returns the zero polynomial vector.
    ///
    /// Every polynomial in the vector is initialized to [`Poly::zero`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let v = PolyVec::<Q3329, 3>::zero();
    /// ```
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            polys: [Poly::<P>::zero(); K],
        }
    }

    /// Creates a polynomial vector from a fixed-size polynomial array.
    ///
    /// This function does not reduce or canonicalize the coefficients of the
    /// input polynomials. The caller is responsible for ensuring that the
    /// polynomials are in the expected representation, or for calling
    /// [`PolyVec::reduce`] or [`PolyVec::freeze`] afterwards.
    #[must_use]
    pub const fn from_polys(polys: [Poly<P>; K]) -> Self {
        Self { polys }
    }

    /// Returns an immutable reference to the polynomial array.
    ///
    /// The coefficients inside the returned polynomials may be in an internal
    /// reduced representation, not necessarily canonical representatives in
    /// `[0, q)`.
    #[must_use]
    pub fn polys(&self) -> &[Poly<P>; K] {
        &self.polys
    }

    /// Returns a mutable reference to the polynomial array.
    ///
    /// This is useful for low-level algorithms that need direct access to the
    /// individual polynomials, such as sampling, decoding, or matrix expansion.
    #[must_use]
    pub fn polys_mut(&mut self) -> &mut [Poly<P>; K] {
        &mut self.polys
    }

    /// Returns the underlying array of the polynomial vector.
    #[must_use]
    pub fn into_polys(self) -> [Poly<P>; K] {
        self.polys
    }

    /// Returns an immutable reference to the polynomial at index `index`.
    ///
    /// Returns `None` if `index >= K`.
    #[must_use]
    pub fn get(&self, row: usize) -> Option<&Poly<P>> {
        self.polys.get(row)
    }

    /// Returns a mutable reference to the polynomial at index `index`.
    ///
    /// Returns `None` if `index >= K`.
    #[must_use]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Poly<P>> {
        self.polys.get_mut(index)
    }

    /// Reduces every coefficient of every polynomial.
    ///
    /// Use [`PolyVec::freeze`] when canonical
    /// representatives are required.
    pub fn reduce(&mut self) {
        for pol in &mut self.polys {
            pol.reduce()
        }
    }

    /// Canonicalizes every coefficient of every polynomial into `[0, q)`.
    pub fn freeze(&mut self) {
        for pol in &mut self.polys {
            pol.freeze()
        }
    }

    /// Adds another polynomial vector to this vector in place.
    ///
    /// For each index `i`, this computes:
    ///
    /// ```text
    /// self[i] = self[i] + rhs[i] mod q
    /// ```
    pub fn add_assign(&mut self, rhs: &Self) {
        for (pol_a, pol_b) in self.polys.iter_mut().zip(rhs.polys.iter()) {
            pol_a.add_assign(pol_b);
        }
    }

    /// Subtracts another polynomial vector from this vector in place.
    ///
    /// For each index `i`, this computes:
    ///
    /// ```text
    /// self[i] = self[i] - rhs[i] mod q
    /// ```
    pub fn sub_assign(&mut self, rhs: &Self) {
        for (pol_a, pol_b) in self.polys.iter_mut().zip(rhs.polys.iter()) {
            pol_a.sub_assign(pol_b);
        }
    }

    /// Returns the coefficientwise addition of two polynomial vectors.
    ///
    /// This does not modify either input vector.
    ///
    /// Internally, this copies `self`, applies [`PolyVec::add_assign`], and
    /// returns the result.
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        let mut out = *self;
        out.add_assign(rhs);
        out
    }

    /// Returns the coefficientwise difference of two polynomial vectors.
    ///
    /// This does not modify either input vector.
    ///
    /// Internally, this copies `self`, applies [`PolyVec::sub_assign`], and
    /// returns the result.
    #[must_use]
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut out = *self;
        out.sub_assign(rhs);
        out
    }

    /// Multiplies every polynomial in the vector by the same integer constant.
    ///
    /// For each vector index `i`, this computes:
    ///
    /// ```text
    /// out[i] = self[i] * constant mod q
    /// ```
    ///
    /// The operation is applied coefficientwise inside each polynomial by
    /// [`Poly::mul_by_constant`]. This function does not modify `self`.
    ///
    /// Coefficients in the returned vector may be in the ring implementation's
    /// internal reduced representation, not necessarily canonical
    /// representatives in `[0, q)`. Call [`PolyVec::freeze`] if canonical
    /// coefficients are required.
    #[must_use]
    pub fn mul_by_constant(&self, constant: &i32) -> Self {
        let mut polys_output = [Poly::<P>::zero(); K];

        for i in 0..K {
            polys_output[i] = self.polys[i].mul_by_constant(constant);
        }

        PolyVec::from_polys(polys_output)
    }

    /// Converts an NTT-domain polynomial vector from Montgomery representation
    /// to ordinary coefficient representatives.
    ///
    /// This does not apply an inverse NTT. It only changes the Montgomery
    /// representation of each stored coefficient.
    #[must_use]
    pub fn coeffs_from_montgomery(&self) -> Self {
        let mut out = *self;

        for poly in out.polys_mut() {
            for coeff in poly.coeffs_mut() {
                *coeff = P::freeze(P::from_montgomery(*coeff));
            }
        }

        out
    }

    /// Converts ordinary coefficient representatives to Montgomery representation.
    ///
    /// This does not apply an NTT. It only changes the representation of each
    /// stored coefficient from `x` to `xR mod q`.
    #[must_use]
    pub fn coeffs_to_montgomery(&self) -> Self {
        let mut out = *self;

        for poly in out.polys_mut() {
            for coeff in poly.coeffs_mut() {
                *coeff = P::to_montgomery(P::freeze(*coeff));
            }
        }

        out
    }
}

impl<P: NttOps, const K: usize> PolyVec<P, K> {
    /// Computes the NTT transform of all entries of the considered vector.
    pub fn ntt(&mut self) {
        for poly in self.polys_mut() {
            poly.ntt();
        }
    }

    /// Computes the inverse NTT transform of all entries of the considered vector.
    pub fn inv_ntt(&mut self) {
        for poly in self.polys_mut() {
            poly.inv_ntt();
        }
    }
}

impl<P: NttDomainMul, const K: usize> PolyVec<P, K> {
    /// Computes the NTT-domain multiplication of a polynomial vector by another polynomial.
    ///
    /// This computes:
    ///
    /// ```text
    /// sum_i self[i] * other
    /// ```
    ///
    /// where each product is an NTT-domain polynomial product.
    ///
    /// # Representation
    ///
    /// Both the vector and the other polynomial must be in the NTT/Montgomery domain. The returned
    /// polynomial vector is also in the NTT/Montgomery domain.
    #[must_use]
    pub fn mul_by_poly_ntt(&self, other: &Poly<P>) -> PolyVec<P, K> {
        let mut res_coeffs = [Poly::<P>::zero(); K];

        for i in 0..K {
            res_coeffs[i] = self.polys[i].mul_ntt(&other);
        }

        PolyVec::from_polys(res_coeffs)
    }

    /// Computes the NTT-domain scalar product of two polynomial vectors.
    ///
    /// This computes:
    ///
    /// ```text
    /// sum_i self[i] * other[i]
    /// ```
    ///
    /// where each product is an NTT-domain polynomial product.
    ///
    /// # Representation
    ///
    /// Both vectors must already be in the NTT/Montgomery domain. The returned
    /// polynomial is also in the NTT/Montgomery domain.
    #[must_use]
    pub fn dot_ntt(&self, other: &PolyVec<P, K>) -> Poly<P> {
        let mut acc = Poly::<P>::zero();

        for i in 0..K {
            let prod = self.polys[i].mul_ntt(&other.polys[i]);
            acc.add_assign(&prod);
        }

        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{N, Q3329, Q8380417};

    fn make_poly_q3329(offset: i32, step: i32) -> Poly<Q3329> {
        let mut coeffs = [0i32; N];

        for (i, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = offset + step * (i as i32);
        }

        Poly::from_coeffs(coeffs)
    }

    fn make_poly_q8380417(offset: i32, step: i32) -> Poly<Q8380417> {
        let mut coeffs = [0i32; N];

        for (i, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = offset + step * (i as i32);
        }

        Poly::from_coeffs(coeffs)
    }

    #[test]
    fn zero_has_all_zero_polynomials_q3329() {
        let v = PolyVec::<Q3329, 3>::zero();

        for poly in v.polys() {
            for &coeff in poly.coeffs() {
                assert_eq!(coeff, 0);
            }
        }
    }

    #[test]
    fn from_polys_into_polys_roundtrip_q3329() {
        let polys = [
            make_poly_q3329(-10, 1),
            make_poly_q3329(20, -2),
            make_poly_q3329(3000, 3),
        ];

        let v = PolyVec::<Q3329, 3>::from_polys(polys);

        assert_eq!(v.into_polys(), polys);
    }

    #[test]
    fn add_matches_poly_add_componentwise_q3329() {
        let a_polys = [
            make_poly_q3329(-100, 1),
            make_poly_q3329(250, -3),
            make_poly_q3329(3000, 2),
        ];

        let b_polys = [
            make_poly_q3329(75, -2),
            make_poly_q3329(-400, 5),
            make_poly_q3329(111, -1),
        ];

        let a = PolyVec::<Q3329, 3>::from_polys(a_polys);
        let b = PolyVec::<Q3329, 3>::from_polys(b_polys);

        let c = a.add(&b);

        for i in 0..3 {
            assert_eq!(c.polys()[i], a_polys[i].add(&b_polys[i]));
        }
    }

    #[test]
    fn sub_matches_poly_sub_componentwise_q3329() {
        let a_polys = [
            make_poly_q3329(-100, 1),
            make_poly_q3329(250, -3),
            make_poly_q3329(3000, 2),
        ];

        let b_polys = [
            make_poly_q3329(75, -2),
            make_poly_q3329(-400, 5),
            make_poly_q3329(111, -1),
        ];

        let a = PolyVec::<Q3329, 3>::from_polys(a_polys);
        let b = PolyVec::<Q3329, 3>::from_polys(b_polys);

        let c = a.sub(&b);

        for i in 0..3 {
            assert_eq!(c.polys()[i], a_polys[i].sub(&b_polys[i]));
        }
    }

    #[test]
    fn add_assign_matches_add_q3329() {
        let a = PolyVec::<Q3329, 3>::from_polys([
            make_poly_q3329(-100, 1),
            make_poly_q3329(250, -3),
            make_poly_q3329(3000, 2),
        ]);

        let b = PolyVec::<Q3329, 3>::from_polys([
            make_poly_q3329(75, -2),
            make_poly_q3329(-400, 5),
            make_poly_q3329(111, -1),
        ]);

        let expected = a.add(&b);

        let mut actual = a;
        actual.add_assign(&b);

        assert_eq!(actual, expected);
    }

    #[test]
    fn sub_assign_matches_sub_q3329() {
        let a = PolyVec::<Q3329, 3>::from_polys([
            make_poly_q3329(-100, 1),
            make_poly_q3329(250, -3),
            make_poly_q3329(3000, 2),
        ]);

        let b = PolyVec::<Q3329, 3>::from_polys([
            make_poly_q3329(75, -2),
            make_poly_q3329(-400, 5),
            make_poly_q3329(111, -1),
        ]);

        let expected = a.sub(&b);

        let mut actual = a;
        actual.sub_assign(&b);

        assert_eq!(actual, expected);
    }

    #[test]
    fn freeze_canonicalizes_all_coefficients_q3329() {
        let mut v = PolyVec::<Q3329, 2>::from_polys([
            make_poly_q3329(-5000, 37),
            make_poly_q3329(8000, -29),
        ]);

        v.freeze();

        for poly in v.polys() {
            for &coeff in poly.coeffs() {
                assert!((0..Q3329::Q).contains(&coeff));
            }
        }
    }

    #[test]
    fn freeze_canonicalizes_all_coefficients_q8380417() {
        let mut v = PolyVec::<Q8380417, 4>::from_polys([
            make_poly_q8380417(-9_000_000, 12_345),
            make_poly_q8380417(10_000_000, -7_777),
            make_poly_q8380417(-123_456, 555),
            make_poly_q8380417(8_500_000, -333),
        ]);

        v.freeze();

        for poly in v.polys() {
            for &coeff in poly.coeffs() {
                assert!((0..Q8380417::Q).contains(&coeff));
            }
        }
    }
}
