//! ML-KEM K-PKE algorithms.
//!
//! This module implements the deterministic public-key encryption component
//! used internally by ML-KEM.

pub(crate) mod internal;

// The `kpke` submodule contains the core K-PKE algorithms. Keeping the file
// name `kpke.rs` mirrors the primitive name and is clearer than renaming it
// only to satisfy Clippy.
#[allow(clippy::module_inception)]
mod kpke;

#[cfg(test)]
mod tests;

pub(crate) use kpke::{kpke_decrypt, kpke_encrypt, kpke_keygen};
