//! Finite-field arithmetic for polynomial coefficients.
//!
//! This module exposes generic helpers for modular addition, subtraction,
//! Montgomery multiplication, canonicalization, and conditional correction.
//! Concrete modulus implementations are kept private.

mod reduce;
mod q3329;
mod q8380417;

pub use reduce::{
    add_mod,
    sub_mod,
    mul_montgomery,
    freeze,
    caddq
};