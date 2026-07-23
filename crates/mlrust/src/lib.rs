//! High-level public API for the `mlrust` project.
//!
//! This crate re-exports the user-facing APIs from the implementation crates.
//!
//! - [`kem`] exposes ML-KEM key encapsulation mechanisms.
//! - [`dsa`] exposes ML-DSA digital signature algorithms.
//!
//! # Examples
//!
//! ## ML-KEM with OS randomness
//!
//! This example runs when the `getrandom` feature is enabled.
//!
//! ```
//! #[cfg(feature = "getrandom")]
//! {
//!     use mlrust::kem::{
//!         ml_kem512_decaps,
//!         ml_kem512_encaps,
//!         ml_kem512_keygen,
//!     };
//!
//!     let keypair = ml_kem512_keygen().expect("key generation succeeds");
//!
//!     let (ss_sender, ciphertext) =
//!         ml_kem512_encaps(keypair.encapsulation_key())
//!             .expect("encapsulation succeeds");
//!
//!     let ss_receiver =
//!         ml_kem512_decaps(keypair.decapsulation_key(), &ciphertext);
//!
//!     assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
//! }
//! ```
//!
//! ## ML-DSA with OS randomness
//!
//! This example runs when the `getrandom` feature is enabled.
//!
//! ```
//! #[cfg(feature = "getrandom")]
//! {
//!     use mlrust::dsa::{
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
//! use mlrust::dsa::{
//!     ml_dsa44_keygen_with_rbg,
//!     ml_dsa44_sign_with_rbg,
//!     ml_dsa44_verify,
//! };
//! use mlrust::kem::{
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
//!
//!  // --- ML-KEM example ---
//!
//! let kem_keypair =
//!     ml_kem512_keygen_with_rbg(&mut rbg)
//!         .expect("ML-KEM key generation succeeds");
//!
//! let (ss_sender, ciphertext) =
//!     ml_kem512_encaps_with_rbg(
//!         kem_keypair.encapsulation_key(),
//!         &mut rbg,
//!     )
//!     .expect("ML-KEM encapsulation succeeds");
//!
//! let ss_receiver =
//!     ml_kem512_decaps(kem_keypair.decapsulation_key(), &ciphertext);
//!
//! assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
//!
//!
//!  // --- ML-DSA example ---
//!
//! let message = b"example message";
//! let context = b"example context";
//!
//! let dsa_keypair =
//!     ml_dsa44_keygen_with_rbg(&mut rbg)
//!         .expect("ML-DSA key generation succeeds");
//!
//! let signature =
//!     ml_dsa44_sign_with_rbg(
//!         dsa_keypair.secret_key(),
//!         message,
//!         context,
//!         &mut rbg,
//!     )
//!     .expect("ML-DSA signing succeeds");
//!
//! let valid = ml_dsa44_verify(
//!     dsa_keypair.public_key(),
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

/// ML-KEM key encapsulation mechanisms.
pub mod kem;

/// ML-DSA digital signature algorithms.
pub mod dsa;
