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
//!
//! The crate exposes two randomness entry points:
//!
//! - `*_with_rbg` functions accept a caller-provided random byte generator and
//!   are available without the `getrandom` feature;
//! - OS-random convenience functions are available when the `getrandom` feature
//!   is enabled.
//!
//! Decapsulation is deterministic and infallible at the public API level.
//! Invalid ciphertexts are handled internally by the ML-KEM implicit-rejection
//! path and still produce a shared secret.
//!
//! Secret-bearing types such as decapsulation keys and shared secrets zeroize
//! their contents on drop. Public values such as encapsulation keys and
//! ciphertexts are ordinary serialized byte wrappers.
//!
//!
//! # Example
//!
//! ML-KEM-512 with OS randomness, this example requires the default `getrandom` feature.
//!
//! ```
//! use ml_kem::{
//!     ml_kem512_decaps,
//!     ml_kem512_encaps,
//!     ml_kem512_keygen,
//! };
//!
//! let keypair = ml_kem512_keygen().expect("key generation succeeds");
//!
//! let (ss_sender, ciphertext) =
//!     ml_kem512_encaps(keypair.encapsulation_key())
//!         .expect("encapsulation succeeds");
//!
//! let ss_receiver =
//!     ml_kem512_decaps(keypair.decapsulation_key(), &ciphertext);
//!
//! assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
//! ```
//!
//!
//! # Example
//!
//! ML-KEM-512 with caller-provided randomness.
//! 
//! ```
//! use ml_kem::{
//!     ml_kem512_decaps,
//!     ml_kem512_encaps_with_rbg,
//!     ml_kem512_keygen_with_rbg,
//! };
//! use mlrust_core::sampling::random::{
//!     RandomByteGenerator,
//!     RandomError,
//! };
//!
//! struct ExampleRbg {
//!     byte: u8,
//! }
//!
//! impl RandomByteGenerator for ExampleRbg {
//!     fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), RandomError> {
//!         output.fill(self.byte);
//!         self.byte = self.byte.wrapping_add(1);
//!         Ok(())
//!     }
//! }
//!
//! let mut rbg = ExampleRbg { byte: 1 };
//!
//! let keypair =
//!     ml_kem512_keygen_with_rbg(&mut rbg)
//!         .expect("key generation succeeds");
//!
//! let (ss_sender, ciphertext) =
//!     ml_kem512_encaps_with_rbg(
//!         keypair.encapsulation_key(),
//!         &mut rbg,
//!     )
//!     .expect("encapsulation succeeds");
//!
//! let ss_receiver =
//!     ml_kem512_decaps(keypair.decapsulation_key(), &ciphertext);
//!
//! assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
//! ```
//!
//! The `ExampleRbg` above is only for API illustration. Real deployments must use a cryptographically secure random byte generator.

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
