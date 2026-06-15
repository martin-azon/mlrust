//! Constant-time byte-slice operations.
//!
//! The functions in this module use the `subtle` crate to express
//! constant-time equality, selection, and assignment over byte slices.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Compares two byte slices in constant time.
///
/// Returns `Choice::from(1)` if `a` and `b` are equal, and
/// `Choice::from(0)` otherwise.
pub fn ct_eq(a: &[u8], b: &[u8]) -> Choice {
    a.ct_eq(b)
}

/// Checks whether all bytes in a slice are zero.
///
/// Returns `Choice::from(1)` if every byte in `a` is equal to zero, and
/// `Choice::from(0)` otherwise.
pub fn ct_is_zero(a: &[u8]) -> Choice {
    let mut acc = 0u8;

    for &byte in a {
        acc |= byte;
    }

    acc.ct_eq(&0u8)
}

/// Selects between two byte slices in constant time and writes the result into
/// `out`.
///
/// For each index `i`, this function writes:
///
/// ```text
/// out[i] = if choice == 0 { a[i] } else { b[i] }
/// ```
///
/// # Panics
///
/// Panics if `a`, `b`, and `out` do not all have the same length.
pub fn ct_select_bytes(out: &mut [u8], a: &[u8], b: &[u8], choice: Choice) {
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), out.len());

    for ((out_byte, a_byte), b_byte) in out.iter_mut().zip(a.iter()).zip(b.iter()) {
        *out_byte = u8::conditional_select(a_byte, b_byte, choice);
    }
}

/// Conditionally assigns `source` into `target` in constant time.
///
/// For each index `i`, this function performs:
///
/// ```text
/// if choice == 1 {
///     target[i] = source[i]
/// }
/// ```
///
/// If `choice` is `Choice::from(0)`, `target` is left unchanged. If `choice`
/// is `Choice::from(1)`, every byte of `source` is copied into `target`.
///
/// # Panics
///
/// Panics if `target` and `source` do not have the same length.
pub fn ct_conditional_assign_bytes(target: &mut [u8], source: &[u8], choice: Choice) {
    assert_eq!(target.len(), source.len());

    for (target_byte, source_byte) in target.iter_mut().zip(source.iter()) {
        target_byte.conditional_assign(source_byte, choice);
    }
}
