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

mod constants;
mod error;
pub mod kem;
mod keys;
mod kpke;

#[cfg(test)]
mod test_utils;

pub use error::MlKemError;

pub use constants::{MlKem512, MlKem768, MlKem1024};

pub use keys::{
    Ciphertext, DecapsulationKey, EncapsulationKey, MlKem512Ciphertext, MlKem512DecapsulationKey,
    MlKem512EncapsulationKey, MlKem512Keypair, MlKem768Ciphertext, MlKem768DecapsulationKey,
    MlKem768EncapsulationKey, MlKem768Keypair, MlKem1024Ciphertext, MlKem1024DecapsulationKey,
    MlKem1024EncapsulationKey, MlKem1024Keypair, MlKemKeypair, SharedSecret,
};

pub use kem::{
    MlKemParams, ml_kem_decaps, ml_kem_decaps512, ml_kem_decaps768, ml_kem_decaps1024,
    ml_kem_encaps, ml_kem_encaps512, ml_kem_encaps768, ml_kem_encaps1024, ml_kem_keygen,
    ml_kem_keygen512, ml_kem_keygen768, ml_kem_keygen1024,
};
