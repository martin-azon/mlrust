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


use crate::params::RingParams;
use super::Poly;


/// Fixed-size vector of polynomials over a modulus specified by `P`.
///
/// The vector contains exactly `K` polynomials. The parameter type `P`
/// determines the coefficient modulus and reduction routines.
///
/// This type is intended for module-lattice operations in ML-KEM and ML-DSA.
/// It provides basic coefficientwise arithmetic, reduction, and accessors.
#[derive(Clone, Copy, Debug, PartialEq,Eq)]
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
        Self{ polys: [Poly::<P>::zero(); K] }
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
    pub fn polys(&self) -> &[Poly<P>; K] { &self.polys }


    /// Returns a mutable reference to the polynomial array.
    ///
    /// This is useful for low-level algorithms that need direct access to the
    /// individual polynomials, such as sampling, decoding, or matrix expansion.
    #[must_use]
    pub fn polys_mut(&mut self) -> &mut [Poly<P>; K] { &mut self.polys }


    /// Returns the underlying array of the polynomial vector.
    #[must_use]
    pub fn into_polys(self) -> [Poly<P>; K] { self.polys }


    /// Reduces every coefficient of every polynomial.
    ///
    /// Use [`PolyVec::freeze`] when canonical representatives are required.
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
        for (pol_a, pol_b) in self.polys.iter_mut().zip(rhs.polys.iter()){
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
        for (pol_a, pol_b) in self.polys.iter_mut().zip(rhs.polys.iter()){
            pol_a.sub_assign(pol_b);
        }
    }


    /// Returns the coefficientwise addition of two polynomial vectors.
    ///
    /// This does not modify either input vector.
    ///
    /// Internally, this copies `self`, applies [`PolyVec::sub_assign`], and
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

}