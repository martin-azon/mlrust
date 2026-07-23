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
mod kem;
mod keys;
mod kpke;

pub use error::MlKemError;

pub use constants::{
    ML_KEM_512_CIPHERTEXT_BYTES, ML_KEM_512_DECAPS_KEY_BYTES, ML_KEM_512_ENCAPS_KEY_BYTES,
    ML_KEM_768_CIPHERTEXT_BYTES, ML_KEM_768_DECAPS_KEY_BYTES, ML_KEM_768_ENCAPS_KEY_BYTES,
    ML_KEM_1024_CIPHERTEXT_BYTES, ML_KEM_1024_DECAPS_KEY_BYTES, ML_KEM_1024_ENCAPS_KEY_BYTES,
    ML_KEM_SHARED_SECRET_BYTES, MlKem512, MlKem768, MlKem1024,
};

pub use keys::{
    Ciphertext, DecapsulationKey, EncapsulationKey, MlKem512Ciphertext, MlKem512DecapsulationKey,
    MlKem512EncapsulationKey, MlKem512Keypair, MlKem768Ciphertext, MlKem768DecapsulationKey,
    MlKem768EncapsulationKey, MlKem768Keypair, MlKem1024Ciphertext, MlKem1024DecapsulationKey,
    MlKem1024EncapsulationKey, MlKem1024Keypair, SharedSecret,
};

pub use crate::kem::api::{
    ml_kem_decaps, ml_kem_encaps_with_rbg, ml_kem_keygen_with_rbg, ml_kem512_decaps,
    ml_kem512_encaps_with_rbg, ml_kem512_keygen_with_rbg, ml_kem768_decaps,
    ml_kem768_encaps_with_rbg, ml_kem768_keygen_with_rbg, ml_kem1024_decaps,
    ml_kem1024_encaps_with_rbg, ml_kem1024_keygen_with_rbg,
};

#[cfg(feature = "getrandom")]
pub use crate::kem::api::{
    ml_kem_encaps, ml_kem_keygen, ml_kem512_encaps, ml_kem512_keygen, ml_kem768_encaps,
    ml_kem768_keygen, ml_kem1024_encaps, ml_kem1024_keygen,
};

#[cfg(test)]
mod test_utils;
