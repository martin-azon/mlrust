//! Shared core arithmetic and utility layer for ML-KEM and ML-DSA.
//!
//! This crate contains reusable building blocks used by the higher-level
//! ML-KEM and ML-DSA crates:
//!
//! - finite-field coefficient arithmetic;
//! - polynomial and polynomial-vector types;
//! - Number Theoretic Transform support;
//! - byte encoding helpers;
//! - symmetric primitive wrappers;
//! - sampling helpers;
//! - constant-time byte utilities.
//!
//! The crate is generic over [`RingParams`] and [`NttParams`] so that the same
//! polynomial code can be used with the ML-KEM modulus `q = 3329` and the
//! ML-DSA modulus `q = 8380417`.
//!
//! This crate does not implement key generation, encapsulation, decapsulation,
//! signing, or verification. Those belong in the algorithm-specific crates.


#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod params;

pub mod field;
pub mod ntt;
pub mod poly;
pub mod encode;
//pub mod symmetric;
//pub mod sampling;
pub mod ct;

pub use error::PqcCoreError;
pub use params::{N, RingParams, NttParams};
