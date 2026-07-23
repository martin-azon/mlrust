//! ML-DSA implementation.
//!
//! This crate implements the pure ML-DSA digital signature algorithm specified
//! in FIPS 204.
//!
//! The public API uses FIPS 204 terminology:
//!
//! - secret keys;
//! - public keys;
//! - signatures.
//!
//! The crate exposes two randomness entry points:
//!
//! - `*_with_rbg` functions accept a caller-provided random byte generator and
//!   are available without the `getrandom` feature;
//! - OS-random convenience functions are available when the `getrandom` feature
//!   is enabled.
//!
//! Signing and verification accept an application message and context. The
//! implementation formats them internally as pure ML-DSA; HashML-DSA is not
//! implemented by this crate.
//!
//! Secret-bearing types such as secret keys zeroize their contents on drop.
//! Public values such as public keys and signatures are ordinary serialized byte
//! wrappers.
//!
//!
//!
//! # Examples
//!
//! ## OS randomness
//!
//! This example runs when the `getrandom` feature is enabled.
//!
//! ```
//! #[cfg(feature = "getrandom")]
//! {
//!     use ml_dsa::{
//!         ml_dsa44_keygen,
//!         ml_dsa44_sign,
//!         ml_dsa44_verify,
//!     };
//!
//!     let message = b"example message";
//!     let context = b"example context";
//!
//!     let keypair = ml_dsa44_keygen().expect("key generation succeeds");
//!
//!     let signature = ml_dsa44_sign(
//!         keypair.secret_key(),
//!         message,
//!         context,
//!     )
//!     .expect("signing succeeds");
//!
//!     let valid = ml_dsa44_verify(
//!         keypair.public_key(),
//!         message,
//!         context,
//!         &signature,
//!     )
//!     .expect("verification should not fail on well-formed inputs");
//!
//!     assert!(valid);
//! }
//! ```
//!
//! ## Caller-provided randomness
//!
//! This example compiles without the default `getrandom` feature.
//!
//! ```
//! use ml_dsa::{
//!     ml_dsa44_keygen_with_rbg,
//!     ml_dsa44_sign_with_rbg,
//!     ml_dsa44_verify,
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
//! let message = b"example message";
//! let context = b"example context";
//! let mut rbg = ExampleRbg { byte: 1 };
//!
//! let keypair =
//!     ml_dsa44_keygen_with_rbg(&mut rbg)
//!         .expect("key generation succeeds");
//!
//! let signature =
//!     ml_dsa44_sign_with_rbg(
//!         keypair.secret_key(),
//!         message,
//!         context,
//!         &mut rbg,
//!     )
//!     .expect("signing succeeds");
//!
//! let valid = ml_dsa44_verify(
//!     keypair.public_key(),
//!     message,
//!     context,
//!     &signature,
//! )
//! .expect("verification should not fail on well-formed inputs");
//!
//! assert!(valid);
//! ```
//!
//! The `ExampleRbg` above is only for API illustration. Real deployments must
//! use a cryptographically secure random byte generator.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Many arithmetic, encoding, and NTT routines intentionally use explicit
// index-based loops because they mirror FIPS pseudocode and fixed-size array
// layouts. In this codebase, those loops are often clearer than iterator
// rewrites.
#![allow(clippy::needless_range_loop)]

// `Zeroizing<[u8; 32]>` is explicitly dereferenced in a few API wrappers to
// preserve fixed-array reference types such as `&[u8; 32]`.
#![allow(clippy::explicit_auto_deref)]

mod constants;
mod dsa;
mod encoding;
mod error;
mod keys;
mod primitives;

pub use error::MlDsaError;

pub use constants::{
    ML_DSA_44_PUBLIC_KEY_BYTES, ML_DSA_44_SECRET_KEY_BYTES, ML_DSA_44_SIGNATURE_BYTES,
    ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SECRET_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES, MlDsa44,
    MlDsa65, MlDsa87,
};

pub use keys::{
    MlDsa44Keypair, MlDsa44PublicKey, MlDsa44SecretKey, MlDsa44Signature, MlDsa65Keypair,
    MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, MlDsa87Keypair, MlDsa87PublicKey,
    MlDsa87SecretKey, MlDsa87Signature, MlDsaKeypair, PublicKey, SecretKey, Signature,
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
