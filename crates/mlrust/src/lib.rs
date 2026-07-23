//! High-level public API for the `mlrust` project.
//!
//! This crate re-exports the user-facing APIs from the implementation crates.
//!
//!
//! # ML-KEM example
//!
//! This example uses OS-randomness and requires the default `getrandom` feature.
//!
//! ```
//! use mlrust::kem::{
//!     ml_kem512_decaps,
//!     ml_kem512_encaps,
//!     ml_kem512_keygen,
//! };
//!
//! let keypair = ml_kem512_keygen().expect("key generation succeeds");
//! let (ss_sender, ciphertext) =
//!     ml_kem512_encaps(keypair.encapsulation_key())
//!         .expect("encapsulation succeeds");
//! let ss_receiver =
//!     ml_kem512_decaps(keypair.decapsulation_key(), &ciphertext);
//!
//! assert_eq!(ss_sender.as_bytes(), ss_receiver.as_bytes());
//! ```
//!
//! # ML-DSA example
//!
//! This example uses OS-randomness and requires the default `getrandom` feature.
//!
//! ```
//! use mlrust::dsa::{
//!     ml_dsa44_keygen,
//!     ml_dsa44_sign,
//!     ml_dsa44_verify,
//! };
//!
//! let keypair = ml_dsa44_keygen().expect("key generation succeeds");
//! let message = b"example message";
//! let context = b"example context";
//!
//! let signature =
//!     ml_dsa44_sign(keypair.secret_key(), message, context)
//!         .expect("signing succeeds");
//!
//! let valid =
//!     ml_dsa44_verify(keypair.public_key(), message, context, &signature)
//!         .expect("verification should not fail on well-formed inputs");
//!
//! assert!(valid);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// ML-KEM key encapsulation mechanisms.
pub mod kem;

/// ML-DSA digital signature algorithms.
pub mod dsa;
