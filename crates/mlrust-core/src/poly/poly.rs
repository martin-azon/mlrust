//! Single-polynomial arithmetic.
//!
//! This module defines [`Poly`], the fixed-degree polynomial type used by the
//! shared lattice-arithmetic layer.
//!
//! A polynomial is represented as an array of `N = 256` signed coefficients.
//! The coefficient modulus is not stored at runtime; instead, it is determined
//! by the type parameter `P`, which implements [`crate::params::RingParams`].
//!
//! For example:
//!
//! ```ignore
//! Poly<Q3329>     // polynomial modulo 3329, used by ML-KEM
//! Poly<Q8380417>  // polynomial modulo 8380417, used by ML-DSA
//! ```
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


use core::marker::PhantomData;
use crate::params::{N, RingParams};


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
    ///
    /// # Example
    ///
    /// ```ignore
    /// let p = Poly::<Q3329>::zero();
    /// ```
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
    pub fn coeffs(&self) -> &[i32; N] {
        &self.coeffs
    }

    /// Returns a mutable reference to the coefficient array.
    ///
    /// This is useful for sampling, decoding, and low-level arithmetic routines
    /// that need direct coefficient access.
    ///
    /// The caller must preserve any invariants required by later operations.
    pub fn coeffs_mut(&mut self) -> &mut [i32; N] {
        &mut self.coeffs
    }

    /// Consumes the polynomial and returns its coefficient array.
    ///
    /// This is useful for tests, encoding routines, or APIs that need ownership
    /// of the raw coefficients.
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
    pub fn add(& self, rhs: &Self) -> Self {
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
    pub fn sub(& self, rhs: &Self) -> Self {
        let mut out = *self;
        out.sub_assign(rhs);
        out
    }
}