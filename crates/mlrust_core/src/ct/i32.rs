//! Constant-time helpers for signed 32-bit integers.
//!
//! This module provides small wrappers around the `subtle` crate for operations
//! that are used in secret-dependent checks.
//!
//! The `subtle` crate provides constant-time comparison traits for unsigned
//! integers. For signed `i32` ordering, this module maps values to their biased
//! unsigned representation by flipping the sign bit:
//!
//! ```text
//! x ↦ (x as u32) ^ 0x8000_0000
//! ```
//!
//! This preserves signed ordering while allowing the comparison to be performed
//! with `subtle`'s unsigned constant-time comparison primitives.
//!
//! # Side-channel note
//!
//! Functions in this module return [`Choice`] rather than `bool`. Callers should
//! keep computations in terms of [`Choice`] while processing secret-dependent
//! data and avoid branching on the result until a public error boundary or final
//! validation point.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

/// Checks whether two `i32` values are equal.
///
/// This compares the two's-complement bit patterns directly. For `i32`, that is
/// equivalent to signed integer equality.
///
/// Returns `Choice(1)` if `x == y`, and `Choice(0)` otherwise.
#[inline]
#[must_use]
pub fn ct_i32_eq(x: i32, y: i32) -> Choice {
    (x as u32).ct_eq(&(y as u32))
}

/// Checks whether `x > y` using signed `i32` ordering.
///
/// The comparison is performed by biasing both operands into an unsigned domain
/// that preserves signed order, then using `subtle`'s constant-time unsigned
/// greater-than comparison.
///
/// Returns `Choice(1)` if `x > y`, and `Choice(0)` otherwise.
#[inline]
#[must_use]
pub fn ct_i32_gt(x: i32, y: i32) -> Choice {
    let x = (x as u32) ^ 0x8000_0000;
    let y = (y as u32) ^ 0x8000_0000;

    x.ct_gt(&y)
}

/// Checks whether `x < y` using signed `i32` ordering.
///
/// This is implemented as `y > x` after applying the same signed-order-preserving
/// unsigned bias used by [`ct_i32_gt`].
///
/// Returns `Choice(1)` if `x < y`, and `Choice(0)` otherwise.
#[inline]
#[must_use]
fn ct_i32_lt(x: i32, y: i32) -> Choice {
    let x = (x as u32) ^ 0x8000_0000;
    let y = (y as u32) ^ 0x8000_0000;

    y.ct_gt(&x)
}

/// Checks whether `x >= y` using signed `i32` ordering.
///
/// Returns `Choice(1)` if `x >= y`, and `Choice(0)` otherwise.
#[inline]
#[must_use]
pub fn ct_i32_ge(x: i32, y: i32) -> Choice {
    ct_i32_gt(x, y) | ct_i32_eq(x, y)
}

/// Selects between two `i32` values in constant time.
///
/// Returns `a` when `choice == Choice(0)` and `b` when
/// `choice == Choice(1)`.
///
/// This is a local wrapper around [`ConditionallySelectable::conditional_select`]
/// for `i32`, so callers do not need to import the `subtle` trait directly.
#[inline]
#[must_use]
pub fn ct_i32_select(a: i32, b: i32, choice: Choice) -> i32 {
    i32::conditional_select(&a, &b, choice)
}

/// Conditionally assigns an `i32` value in constant time.
///
/// When `choice == Choice(1)`, `target` is set to `source`.
/// When `choice == Choice(0)`, `target` is left unchanged.
#[inline]
pub fn ct_i32_cond_assign(target: &mut i32, source: i32, choice: Choice) {
    *target = ct_i32_select(*target, source, choice);
}

/// Checks whether every coefficient lies in the inclusive range
/// `min <= coeff <= max`.
///
/// The function scans the full slice and accumulates the validity bit without
/// returning early on the first out-of-range coefficient. This is useful for
/// validating secret-derived coefficient arrays without making the amount of
/// work depend on the position of the first invalid value.
///
/// Returns `Choice(1)` if all coefficients are in range, and `Choice(0)`
/// otherwise.
#[inline]
#[must_use]
pub fn coeffs_in_range_ct(coeffs: &[i32], min: i32, max: i32) -> Choice {
    let mut ok = Choice::from(1);

    for &coeff in coeffs {
        ok &= !ct_i32_lt(coeff, min);
        ok &= !ct_i32_gt(coeff, max);
    }

    ok
}