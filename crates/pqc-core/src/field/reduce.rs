use crate::params::RingParams;

/// Add modulo q, returning an internal reduced representative.
pub fn add_mod<P: RingParams>(a: i32, b: i32) -> i32 {
    P::barrett_reduce(a + b)
}

/// Subtract modulo q, returning an internal reduced representative.
pub fn sub_mod<P: RingParams>(a: i32, b: i32) -> i32 {
    P::barrett_reduce(a - b)
}

/// Multiply using Montgomery reduction.
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