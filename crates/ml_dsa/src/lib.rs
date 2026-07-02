//! ML-DSA implementation.
//!
//! This crate implements the ML-DSA digital signature algorithm specified in
//! FIPS 204.
//!
//! The public API uses FIPS 204 terminology:
//!
//! - public keys;
//! - private keys;
//! - signatures.


#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]


mod constants;
mod dsa;
mod error;
mod keys;
mod primitives;
mod encoding;