//! ML-KEM implementation.
//!
//! This crate implements the ML-KEM key encapsulation mechanism specified in
//! FIPS 203.
//!
//! The public API uses FIPS 203 terminology:
//!
//! - encapsulation keys;
//! - decapsulation keys;
//! - ciphertexts;
//! - shared secrets.


#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]


mod error;
mod internal;
mod k_pke;
mod kem;
mod keys;
mod params;