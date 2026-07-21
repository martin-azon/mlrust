//! Encoding, compression, and bit-packing routines.
//!
//! This module contains byte-level encoding helpers used by the ML-KEM and
//! ML-DSA implementations.
//!
//! Low-level routines in this module are allocation-free and use caller-provided
//! output buffers so they remain compatible with `no_std` builds.

pub mod bits;
pub mod ml_dsa;
pub mod ml_kem;
