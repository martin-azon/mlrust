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
mod encoding;
mod error;
mod keys;
mod primitives;

pub use error::MlDsaError;

pub use constants::{
    MlDsa44, MlDsa65, MlDsa87,
    ML_DSA_44_PUBLIC_KEY_BYTES,
    ML_DSA_44_SECRET_KEY_BYTES,
    ML_DSA_44_SIGNATURE_BYTES,
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SECRET_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
    ML_DSA_87_PUBLIC_KEY_BYTES,
    ML_DSA_87_SECRET_KEY_BYTES,
    ML_DSA_87_SIGNATURE_BYTES,
};

pub use keys::{
    MlDsaKeypair, PublicKey, SecretKey, Signature,
    MlDsa44Keypair, MlDsa44PublicKey, MlDsa44SecretKey, MlDsa44Signature,
    MlDsa65Keypair, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature,
    MlDsa87Keypair, MlDsa87PublicKey, MlDsa87SecretKey, MlDsa87Signature,
};

pub use dsa::api::{
    ml_dsa44_keygen_with_rbg, ml_dsa44_sign_with_rbg, ml_dsa44_verify, ml_dsa65_keygen_with_rbg,
    ml_dsa65_sign_with_rbg, ml_dsa65_verify, ml_dsa87_keygen_with_rbg, ml_dsa87_sign_with_rbg,
    ml_dsa87_verify,
};

#[cfg(feature = "getrandom")]
pub use dsa::api::{
    ml_dsa44_keygen, ml_dsa44_sign, ml_dsa65_keygen, ml_dsa65_sign, ml_dsa87_keygen, ml_dsa87_sign,
};

#[cfg(test)]
mod test_utils;
