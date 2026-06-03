//! Finite-field arithmetic for the ML-KEM modulus `q = 3329`.
//!
//! This module implements [`RingParams`] for [`Q3329`], the coefficient field
//! used by ML-KEM.
//!
//! The implementation provides:
//!
//! - Montgomery reduction with radix `R = 2^16`;
//! - Barrett reduction for bounded coefficient cleanup;
//! - Montgomery conversion through `R2 = R^2 mod q`;
//! - tests for canonicalization, conditional correction, Barrett reduction,
//!   and Montgomery reduction.
//!
//! Coefficients are represented as signed `i32` values. The arithmetic routines
//! are intended for the bounded ranges that occur in ML-KEM polynomial and NTT
//! operations, not as arbitrary-precision modular arithmetic.
//!
//! The Montgomery constant satisfies:
//!
//! ```text
//! Q_INV = -q^{-1} mod 2^16 = -3327
//! ```
//!
//! and the Montgomery conversion constant is:
//!
//! ```text
//! R2 = R^2 mod q = 1353
//! ```


use crate::params::{RingParams, Q3329};

/// Barrett reduction constant: V approximates 2**26 / 3329
const BARRETT_V: i32 = 20159;

impl RingParams for Q3329 {
    const Q: i32 = 3_329;

    const Q_INV: i32 = -3_327;

    const R2: i32 = 1353;

    fn montgomery_reduce(a: i64) -> i32 {
        debug_assert!(a >= i32::MIN as i64);
        debug_assert!(a <= i32::MAX as i64);
        let a = a as i32;

        let t = a.wrapping_mul(Self::Q_INV) as i16 as i32;
        (a - t * Self::Q) >> 16
    }

    fn barrett_reduce(a: i32) -> i32 {
        let t = (((BARRETT_V as i64) * (a as i64) + (1_i64 << 25)) >> 26) as i32;
        a - t * Self::Q
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_mod(a: i64, q: i32) -> i32 {
        a.rem_euclid(q as i64) as i32
    }

    #[test]
    fn freeze_is_canonical() {
        for a in -20_000..20_000 {
            let r = Q3329::freeze(a);

            assert!(0 <= r && r < Q3329::Q);
            assert_eq!(r, reference_mod(a as i64, Q3329::Q));
        }
    }

    #[test]
    fn caddq_adds_q_to_negative_values() {
        for a in -Q3329::Q + 1..Q3329::Q {
            let r = Q3329::caddq(a);

            if a < 0 {
                assert_eq!(r, a + Q3329::Q);
            } else {
                assert_eq!(r, a);
            }
        }
    }

    #[test]
    fn barrett_reduce_preserves_residue() {
        for a in -20_000..20_000 {
            let r = Q3329::barrett_reduce(a);

            assert_eq!(
                reference_mod((r - a) as i64, Q3329::Q),
                0
            );
        }
    }

    #[test]
    fn montgomery_reduce_matches_reference() {
        const R_INV: i64 = 169; // (2^16)^(-1) mod 3329

        for a in -2_000_000..2_000_000 {
            let got = Q3329::freeze(Q3329::montgomery_reduce(a));
            let expected = reference_mod(a * R_INV, Q3329::Q);

            assert_eq!(got, expected, "a = {a}");
        }
    }
}