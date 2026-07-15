//! ML-DSA primitive operations.
//!
//! This module groups the low-level ML-DSA primitives used by key generation,
//! signing, and verification.
//!
//! The primitives here are not public API. They operate on algebraic objects
//! such as polynomials, polynomial vectors, hints, and challenge seeds.
//!
//! Module overview:
//!
//! - [`sampling`]: rejection sampling and deterministic expansion routines;
//! - [`challenge`]: sparse challenge polynomial generation;
//! - [`rounding`]: `Power2Round`, `Decompose`, `HighBits`, `LowBits`,
//!   `MakeHint`, and `UseHint`;
//! - [`norm`]: infinity norms used by signing and verification rejection
//!   checks.

pub(crate) mod sampling;
pub(crate) mod challenge;
pub(crate) mod rounding;
pub(crate) mod norm;