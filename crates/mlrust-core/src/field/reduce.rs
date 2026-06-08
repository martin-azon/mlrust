//! Generic modular-arithmetic helper functions.
//!
//! This module provides thin wrappers around the [`RingParams`] trait.
//! The actual modulus-specific arithmetic is implemented by concrete
//! parameter types such as `Q3329` and `Q8380417`.


use crate::params::RingParams;


/// Add modulo q, returning an internal reduced representative.
pub fn add_mod<P: RingParams>(a: i32, b: i32) -> i32 {
    P::barrett_reduce(a + b)
}


/// Subtract modulo q, returning an internal reduced representative.
pub fn sub_mod<P: RingParams>(a: i32, b: i32) -> i32 {
    P::barrett_reduce(a - b)
}


/// Multiplies two Montgomery-domain representatives.
///
/// If `a = xR mod q` and `b = yR mod q`, this returns `xyR mod q`.
///
/// This is not ordinary modular multiplication on ordinary representatives.
pub fn mul_montgomery<P: RingParams>(a: i32, b: i32) -> i32 {
    P::montgomery_reduce((a as i64) * (b as i64))
}


/// Canonicalize into [0, q).
pub fn freeze<P: RingParams>(a: i32) -> i32 {
    P::freeze(a)
}


/// Conditionally add q if the representative is negative.
pub fn caddq<P: RingParams>(a: i32) -> i32 {
    P::caddq(a)
}