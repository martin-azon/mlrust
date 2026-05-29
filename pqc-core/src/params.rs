//! Shared parameter traits and marker types.
pub const N: usize = 256;

/// Parameters for coefficient arithmetic over Z_q.
pub trait RingParams: Copy + Clone + 'static {

    /// Modulus q.
    const Q: i32;

    /// Montgomery reduction constant.
    ///
    /// Convention-dependent: this must match the implementation in
    /// `field::reduce`.
    const Q_INV: i32;

    /// General reduction into the implementation's preferred internal range.
    fn reduce(x: i64) -> i32;

    /// Canonicalize into [0, q).
    fn freeze(x: i32) -> i32;

    /// Conditionally add q if the representative is negative.
    fn caddq(x: i32) -> i32;

    /// Montgomery reduction.
    fn montgomery_reduce(x: i64) -> i32;

    /// Barrett reduction.
    fn barrett_reduce(x: i64) -> i32;
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