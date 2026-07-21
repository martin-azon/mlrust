//! ML-DSA algorithms and parameter-set dispatch.
//!
//! This module contains the ML-DSA signing-system implementation.
//!
//! The implementation is split into:
//!
//! - [`internal`]: deterministic internal algorithms for key generation,
//!   signing, and verification;
//! - [`params`]: parameter-set marker types and dispatch through
//!   [`params::MlDsaParams`];
//! - [`api`]: public message-oriented API that obtains randomness and calls
//!   the parameter-set dispatch layer.
//!
//! Signing has a randomized public form. The public API obtains the required
//! signing randomness, accepts caller-provided random byte generators, and
//! dispatches to the parameter-set implementation.
//!
//! Verification is deterministic and returns `Ok(false)` for a well-formed but
//! cryptographically invalid signature. Malformed encodings and invalid
//! contexts are reported as errors.
//!
//! The internal signing and verification algorithms accept byte messages and
//! contexts. They stream the pure ML-DSA formatted message into the transcript
//! without allocating a separate formatted-message buffer.
//!
//! Public callers should use [`api`] rather than calling [`internal`] directly.

pub(crate) mod api;
pub(crate) mod internal;
pub(crate) mod params;

#[cfg(test)]
mod tests;