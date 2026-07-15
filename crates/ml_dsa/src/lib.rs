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
    ml_dsa_keygen44_from_seed,
    ml_dsa_sign44_from_seed,
    ml_dsa_verify44,
    ml_dsa_keygen65_from_seed,
    ml_dsa_sign65_from_seed,
    ml_dsa_verify65,
    ml_dsa_keygen87_from_seed,
    ml_dsa_sign87_from_seed,
    ml_dsa_verify87,
};

#[cfg(test)]
mod test_utils;