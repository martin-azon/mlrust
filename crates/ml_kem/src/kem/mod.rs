//! ML-KEM key generation, encapsulation, and decapsulation.
//!
//! This module contains the ML-KEM key-encapsulation implementation.
//!
//! The implementation is split into:
//!
//! - [`internal`]: deterministic internal algorithms for key generation,
//!   encapsulation, and decapsulation;
//! - [`params`]: parameter-set marker types and dispatch through
//!   [`params::MlKemParams`];
//! - [`api`]: public API that obtains randomness, accepts caller-provided
//!   random byte generators, and calls the parameter-set dispatch layer.
//!
//! Key generation and encapsulation have randomized public forms. The public
//! API obtains the required random byte strings and passes them to the
//! deterministic parameter-set implementation.
//!
//! Decapsulation is deterministic and infallible at the public API level.
//! Invalid ciphertexts are handled by the ML-KEM implicit-rejection path rather
//! than by returning an error.
//!
//! Public callers should use [`api`] rather than calling [`internal`] directly.

pub(crate) mod api;
pub(crate) mod internal;
pub(crate) mod params;

#[cfg(test)]
mod tests;