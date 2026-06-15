//! High-level public API for the `mlrust` project.
//!
//! This crate re-exports the user-facing APIs from the implementation crates.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// ML-KEM key encapsulation mechanisms.
pub mod kem;
