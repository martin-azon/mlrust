//! Shared parameter traits and marker types.

/// Number of coefficients in each polynomial.
///
/// ML-KEM and ML-DSA both operate over degree-255 polynomials, represented by
/// `N = 256` coefficients modulo `x^256 + 1`.
pub const N: usize = 256;

/// Parameters for coefficient arithmetic over Z_q.
pub trait RingParams: Copy + Clone + 'static {

    /// Modulus q.
    const Q: i32;

    /// Montgomery reduction constant.
    const Q_INV: i32;

    /// Canonicalize into [0, q), assuming `barrett_reduce`
    /// returns a representative close enough to the canonical range.
    /// This works well for our lattice-based crypto purposes, but
    /// it is not a general-purpose reduction for arbitrary huge i32 values.
    fn freeze(a: i32) -> i32 {
        let mut r = Self::barrett_reduce(a);
        r = Self::caddq(r);

        // Ensure r < q:
        // sign_of_r_minus_q extracts the sign bit as a full mask (see caddq below)
        let r_minus_q = r - Self::Q;
        let sign_of_r_minus_q = r_minus_q >> 31;
        r_minus_q + (sign_of_r_minus_q & Self::Q)
    }

    /// Conditionally add q if the representative is negative.
    fn caddq(a: i32) -> i32 {
        // For an i32, shifting right by 31 extracts the sign bit as a full mask:
        // if a >= 0 then sign_of_a = 00000...0,
        // if a < 0 then sign_of_a = 11111...1
        let sign_of_a = a >> 31;
        a + (sign_of_a & Self::Q)
    }

    /// Montgomery reduction.
    fn montgomery_reduce(a: i64) -> i32;

    /// Barrett reduction.
    fn barrett_reduce(a: i32) -> i32;
}


/// Parameters needed by the Number Theoretic Transform.
pub trait NttParams: RingParams {
    /// Forward NTT constants.
    const ZETAS: &'static [i32];

    /// Inverse NTT constants.
    const INV_ZETAS: &'static [i32];

    /// Final inverse-NTT scaling factor.
    const INV_NTT_SCALE: i32;
}

/// Ring marker for ML-KEM coefficient arithmetic: q = 3329.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Q3329 {}

/// Ring marker for ML-DSA coefficient arithmetic: q = 8380417.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Q8380417 {}