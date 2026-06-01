//! Polynomial and polynomial-vector types.
//!
//! This module contains the core algebraic data structures used by the
//! ML-KEM and ML-DSA implementations:
//!
//! - [`Poly`], a polynomial with `N = 256` signed coefficients;
//! - [`PolyVec`], a fixed-size vector of polynomials;
//! - [`Matrix`], a fixed-size matrix of polynomial vectors.
//!
//! The arithmetic is generic over [`crate::params::RingParams`], so the same
//! types can be used with different coefficient moduli, such as `q = 3329`
//! for ML-KEM and `q = 8380417` for ML-DSA.
//!
//! Coefficients are stored as `i32` values. They are not necessarily canonical
//! after every operation. Arithmetic routines may leave coefficients in an
//! internal reduced representation. Call [`Poly::freeze`] when canonical
//! representatives in `[0, q)` are required.

mod poly;
mod polyvec;
mod matrix;

pub use poly::Poly;