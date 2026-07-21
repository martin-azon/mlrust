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
//! The internal signing and verification algorithms accept byte messages and
//! contexts. They stream the pure ML-DSA formatted message into the transcript
//! without allocating a separate formatted-message buffer.
//!
//! Public callers should use [`api`] rather than calling [`internal`] directly.

pub(crate) mod internal;
pub(crate) mod params;

pub(crate) mod api;

#[cfg(test)]
mod tests;


pub use params::MlDsaParams;

pub use api::{
    ml_dsa_keygen,
    ml_dsa_keygen_with_rbg,
    ml_dsa_sign,
    ml_dsa_sign_with_rbg,
    ml_dsa_verify,
    ml_dsa44_keygen,
    ml_dsa44_keygen_with_rbg,
    ml_dsa44_sign,
    ml_dsa44_sign_with_rbg,
    ml_dsa44_verify,
    ml_dsa65_keygen,
    ml_dsa65_keygen_with_rbg,
    ml_dsa65_sign,
    ml_dsa65_sign_with_rbg,
    ml_dsa65_verify,
    ml_dsa87_keygen,
    ml_dsa87_keygen_with_rbg,
    ml_dsa87_sign,
    ml_dsa87_sign_with_rbg,
    ml_dsa87_verify,
};