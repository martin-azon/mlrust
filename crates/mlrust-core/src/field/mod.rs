//! Finite-field arithmetic for polynomial coefficients.
//!
//! This module exposes generic helpers for modular addition, subtraction,
//! Montgomery multiplication, canonicalization, and conditional correction.
//! Concrete modulus implementations are kept private.

mod reduce;
pub mod q3329;
pub mod q8380417;

pub use reduce::{
    add_mod,
    caddq,
    freeze,
    mul_montgomery,
    sub_mod
};