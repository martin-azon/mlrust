//! ML-KEM K-PKE algorithms.
//!
//! This module implements the deterministic public-key encryption component
//! used internally by ML-KEM.

pub(crate) mod internal;
mod kpke;

#[cfg(test)]
mod tests;

pub(crate) use kpke::{kpke_decrypt, kpke_encrypt, kpke_keygen};
