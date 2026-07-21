//! ML-DSA implementation.
//!
//! This crate implements the ML-DSA digital signature algorithm specified in
//! FIPS 204.
//!
//! The public API uses FIPS 204 terminology:
//!
//! - secret keys;
//! - public keys;
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

pub use error::MlDsaError;

pub use constants::{MlDsa44, MlDsa65, MlDsa87};

pub use keys::{
    SecretKey,
    PublicKey,
    Signature,
    MlDsaKeypair,
    MlDsa44SecretKey, MlDsa44PublicKey, MlDsa44Signature, MlDsa44Keypair,
    MlDsa65SecretKey, MlDsa65PublicKey, MlDsa65Signature, MlDsa65Keypair,
    MlDsa87SecretKey, MlDsa87PublicKey, MlDsa87Signature, MlDsa87Keypair,
};

pub use dsa::api::{
    ml_dsa44_keygen_with_rbg,
    ml_dsa44_sign_with_rbg,
    ml_dsa44_verify,
    ml_dsa65_keygen_with_rbg,
    ml_dsa65_sign_with_rbg,
    ml_dsa65_verify,
    ml_dsa87_keygen_with_rbg,
    ml_dsa87_sign_with_rbg,
    ml_dsa87_verify,
};

#[cfg(feature = "getrandom")]
pub use dsa::api::{
    ml_dsa44_keygen,
    ml_dsa44_sign,
    ml_dsa65_keygen,
    ml_dsa65_sign,
    ml_dsa87_keygen,
    ml_dsa87_sign,
};

#[cfg(test)]
mod test_utils;
