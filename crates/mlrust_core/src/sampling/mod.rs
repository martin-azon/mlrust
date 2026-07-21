//! Sampling and random-byte support for lattice-based schemes.
//!
//! This module contains deterministic sampling primitives used to construct
//! polynomials and polynomial vectors from byte strings, seeds, and XOF output.
//! It also contains the byte-oriented random generator abstraction used by
//! protocol crates to obtain seeds and signing randomness.

pub mod ml_kem;
pub mod random;
