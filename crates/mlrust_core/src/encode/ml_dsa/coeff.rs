//! ML-DSA coefficient manipulation.



use crate::params::{Q8380417, RingParams};
use subtle::{CtOption, ConstantTimeLess, ConstantTimeGreater, ConditionallySelectable};



/// FIPS 204 `CoeffFromThreeBytes`.
///
/// Interprets `b0`, `b1`, and the low seven bits of `b2` as a 23-bit
/// little-endian integer:
///
/// ```text
/// z = b0 + 256*b1 + 65536*(b2 mod 128)
/// ```
///
/// The returned [`CtOption`] is present only when the decoded integer is
/// strictly less than `q`.
///
/// This function computes the local validity predicate without a branch.
/// Callers used for rejection sampling will still usually branch on
/// `is_some()` to decide whether to accept the candidate.
#[must_use]
pub fn coeff_from_three_bytes(b0: u8, b1: u8, b2: u8) -> CtOption<i32> {
    let b2_low = (b2 & 0x7f) as u32;
    let z = b0 as u32 | ((b1 as u32) << 8) | (b2_low << 16);

    let valid = z.ct_lt(&(Q8380417::Q as u32));
    CtOption::new(z as i32, valid)
}


/// Computes `x mod 5` for `0 <= x <= 15` without `%` or branches.
///
/// # Panics
///
/// Panics if `x > 15`.
#[inline]
fn mod5_ct(mut x: u8) -> u8 {
    assert!(x <= 15);

    let ge_10 = x.ct_gt(&9u8);
    let x_minus_10 = x.wrapping_sub(10);
    x = u8::conditional_select(&x, &x_minus_10, ge_10);

    let ge_5 = x.ct_gt(&4u8);
    let x_minus_5 = x.wrapping_sub(5);
    x = u8::conditional_select(&x, &x_minus_5, ge_5);

    x
}

/// FIPS 204 `CoeffFromHalfByte`.
///
/// For `ETA = 2`, accepts half-bytes `0 <= b < 15` and returns:
///
/// ```text
/// 2 - (b mod 5)
/// ```
///
/// For `ETA = 4`, accepts half-bytes `0 <= b < 9` and returns:
///
/// ```text
/// 4 - b
/// ```
///
/// Invalid half-bytes are represented as `CtOption::None`.
///
/// # Panics
///
/// Panics if `ETA` is not `2` or `4`.
///
/// The returned [`CtOption`] is present only when the half-byte is accepted by
/// the FIPS 204 rejection rule for the selected `ETA`.
///
/// This function only makes the candidate-level validity predicate explicit;
/// rejection samplers that call it are still variable-time.
#[must_use]
pub fn coeff_from_half_byte<const ETA: usize>(b: u8) -> CtOption<i32> {
    let b = b & 0x0f;

    match ETA {
        2 => {
            let valid = b.ct_lt(& 15u8);
            let r = mod5_ct(b);
            let coeff = 2i32 - r as i32;
            CtOption::new(coeff, valid)
        }
        4 => {
            let valid = b.ct_lt(& 9u8);
            let coeff = 4i32 - (b as i32);
            CtOption::new(coeff, valid)
        }

        _ => panic!("Unsupported ML-DSA eta")
    }
}




#[cfg(test)]
mod tests {
    use super::*;

    fn coeff_from_z(z: u32) -> CtOption<i32> {
        coeff_from_three_bytes(
            (z & 0xff) as u8,
            ((z >> 8) & 0xff) as u8,
            ((z >> 16) & 0xff) as u8,
        )
    }

    #[test]
    fn coeff_from_three_bytes_ignores_high_bit_of_third_byte() {
        let a = coeff_from_three_bytes(0x34, 0x12, 0x00);
        let b = coeff_from_three_bytes(0x34, 0x12, 0x80);

        assert!(bool::from(a.is_some()));
        assert!(bool::from(b.is_some()));
        assert_eq!(a.unwrap(), 0x1234);
        assert_eq!(b.unwrap(), 0x1234);
    }

    #[test]
    fn coeff_from_three_bytes_accepts_q_minus_one() {
        let z = (Q8380417::Q - 1) as u32;
        let coeff = coeff_from_z(z);

        assert!(bool::from(coeff.is_some()));
        assert_eq!(coeff.unwrap(), Q8380417::Q - 1);
    }

    #[test]
    fn coeff_from_three_bytes_rejects_q() {
        let z = Q8380417::Q as u32;
        let coeff = coeff_from_z(z);

        assert!(!bool::from(coeff.is_some()));
    }

    #[test]
    fn coeff_from_three_bytes_rejects_max_23_bit_value() {
        let coeff = coeff_from_three_bytes(0xff, 0xff, 0x7f);

        assert!(!bool::from(coeff.is_some()));
    }

    #[test]
    fn mod5_ct_matches_mod_operator_on_nibbles() {
        for x in 0u8..=15 {
            assert_eq!(mod5_ct(x), x % 5);
        }
    }

    #[test]
    fn coeff_from_half_byte_eta2_valid_values() {
        let expected = [
            2, 1, 0, -1, -2,
            2, 1, 0, -1, -2,
            2, 1, 0, -1, -2,
        ];

        for b in 0u8..15 {
            let coeff = coeff_from_half_byte::<2>(b);

            assert_eq!(coeff.is_some().unwrap_u8(), 1);
            assert_eq!(coeff.unwrap(), expected[b as usize]);
        }
    }

    #[test]
    fn coeff_from_half_byte_eta2_rejects_15() {
        let coeff = coeff_from_half_byte::<2>(15);

        assert_eq!(coeff.is_some().unwrap_u8(), 0);
    }

    #[test]
    fn coeff_from_half_byte_eta4_valid_values() {
        for b in 0u8..9 {
            let coeff = coeff_from_half_byte::<4>(b);

            assert_eq!(coeff.is_some().unwrap_u8(), 1);
            assert_eq!(coeff.unwrap(), 4 - b as i32);
        }
    }

    #[test]
    fn coeff_from_half_byte_eta4_rejects_9_to_15() {
        for b in 9u8..16 {
            let coeff = coeff_from_half_byte::<4>(b);

            assert_eq!(coeff.is_some().unwrap_u8(), 0);
        }
    }
}