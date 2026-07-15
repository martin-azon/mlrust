//! ML-DSA algorithms and parameter-set dispatch.
//!
//! This module contains the ML-DSA signing-system implementation.
//!
//! The implementation is split into:
//!
//! - [`internal`]: deterministic FIPS-style internal algorithms for key
//!   generation, signing, and verification;
//! - [`params`]: parameter-set marker types and dispatch through
//!   [`params::MlDsaParams`];
//! - [`api`]: public message-oriented API that formats messages, obtains
//!   randomness, and calls the parameter-set dispatch layer.
//!
//! The internal algorithms operate on already formatted messages `M'`. Public
//! callers should use [`api`] rather than calling [`internal`] directly.

pub(crate) mod internal;
pub(crate) mod params;

pub mod api;

#[cfg(test)]
mod tests;