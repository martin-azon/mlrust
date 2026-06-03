use crate::params::{RingParams, Q8380417};

impl RingParams for Q8380417 {
    const Q: i32 = 8_380_417;

    const Q_INV: i32 = 58_728_449;

    const R2: i32 = 1; // placeholder, TO BE MODIFIED!!!

    fn montgomery_reduce(a: i64) -> i32 {
        let t = (a as i32).wrapping_mul(Self::Q_INV);
        ((a - (t as i64) * (Self::Q as i64)) >> 32) as i32
    }

    fn barrett_reduce(a: i32) -> i32 {
        let t = (a + (1 << 22)) >> 23;
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
        for a in -20_000_000..20_000_000 {
            let r = Q8380417::freeze(a);

            assert!(0 <= r && r < Q8380417::Q);
            assert_eq!(r, reference_mod(a as i64, Q8380417::Q));
        }
    }

    #[test]
    fn caddq_adds_q_to_negative_values() {
        for a in -Q8380417::Q + 1..Q8380417::Q {
            let r = Q8380417::caddq(a);

            if a < 0 {
                assert_eq!(r, a + Q8380417::Q);
            } else {
                assert_eq!(r, a);
            }
        }
    }

    #[test]
    fn barrett_reduce_preserves_residue() {
        for a in -20_000_000..20_000_000 {
            let r = Q8380417::barrett_reduce(a);

            assert_eq!(
                reference_mod((r - a) as i64, Q8380417::Q),
                0
            );
        }
    }

    #[test]
    fn montgomery_reduce_matches_reference() {
        const R_INV: i64 = 8265825; // (2^32)^(-1) mod 8380417

        for a in -50_000_000i64..50_000_000i64 {
            let got = Q8380417::freeze(Q8380417::montgomery_reduce(a));
            let expected = reference_mod(a * R_INV, Q8380417::Q);

            assert_eq!(got, expected, "a = {a}");
        }
    }
}