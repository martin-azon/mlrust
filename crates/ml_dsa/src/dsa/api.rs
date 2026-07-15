//! Public ML-DSA API.
//!
//! This module exposes message-oriented pure ML-DSA functions.
//!
//! Public functions accept an application message, a context string, and
//! explicit signing randomness for deterministic signing. The lower-level
//! implementation formats the message as pure ML-DSA:
//!
//! ```text
//! M' = IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx || message
//! ```
//!
//! and streams that representation into the SHAKE256 transcript without
//! allocating a separate formatted-message buffer.
//!
//! This module implements pure ML-DSA, not HashML-DSA.



use crate::constants::{MlDsa44, MlDsa65, MlDsa87};
use crate::dsa::params::MlDsaParams;
use crate::error::MlDsaError;
use crate::keys::{
    MlDsa44Keypair,
    MlDsa44PublicKey,
    MlDsa44SecretKey,
    MlDsa44Signature,
    MlDsa65Keypair,
    MlDsa65PublicKey,
    MlDsa65SecretKey,
    MlDsa65Signature,
    MlDsa87Keypair,
    MlDsa87PublicKey,
    MlDsa87SecretKey,
    MlDsa87Signature,
};





/// Deterministically generates an ML-DSA keypair from a 32-byte seed.
#[must_use]
pub(crate) fn keygen_from_seed<P: MlDsaParams>(xi: &[u8; 32]) -> P::KeyPair {
    P::keygen_from_seed(xi)
}


/// Deterministically signs a message with context using
/// explicit 32-byte signing randomness.
pub(crate) fn sign_from_seed<P: MlDsaParams>(
    sk: &P::SecretKey,
    message: &[u8],
    context: &[u8],
    randomness: &[u8; 32],
) -> Result<P::Signature, MlDsaError> {
    P::sign_from_seed(sk, message, context, randomness)
}

/// Verifies a signature against a message with context.
pub(crate) fn verify<P: MlDsaParams>(
    pk: &P::PublicKey,
    message: &[u8],
    context: &[u8],
    signature: &P::Signature,
) -> Result<bool, MlDsaError> {
    P::verify(pk, message, context, signature)
}





/// Deterministically generates an ML-DSA-44 keypair from a 32-byte seed.
#[must_use]
pub fn ml_dsa_keygen44_from_seed(xi: &[u8; 32]) -> MlDsa44Keypair {
    keygen_from_seed::<MlDsa44>(xi)
}

/// Deterministically signs a message with ML-DSA-44 using explicit signing
/// randomness.
///
/// The `context` length must be at most 255 bytes.
///
/// # Errors
///
/// Returns:
///
/// - [`MlDsaError::InvalidLength`] if `context.len() > 255`;
/// - [`MlDsaError::InvalidSecretKey`] if `sk` cannot be decoded for ML-DSA-44;
/// - [`MlDsaError::Core`] if the internal signing loop exhausts the supported
///   nonce space.
pub fn ml_dsa_sign44_from_seed(
    sk: &MlDsa44SecretKey,
    message: &[u8],
    context: &[u8],
    randomness: &[u8; 32],
) -> Result<MlDsa44Signature, MlDsaError> {
    sign_from_seed::<MlDsa44>(sk, message, context, randomness)
}

/// Verifies an ML-DSA-44 signature against a message and context.
///
/// # Errors
///
/// Returns:
///
/// - [`MlDsaError::InvalidLength`] if `context.len() > 255`;
/// - [`MlDsaError::InvalidPublicKey`] if `pk` cannot be decoded for ML-DSA-44;
/// - [`MlDsaError::InvalidSignature`] if `signature` is malformed.
pub fn ml_dsa_verify44(
    pk: &MlDsa44PublicKey,
    message: &[u8],
    context: &[u8],
    signature: &MlDsa44Signature,
) -> Result<bool, MlDsaError> {
    verify::<MlDsa44>(pk, message, context, signature)
}





/// Deterministically generates an ML-DSA-65 keypair from a 32-byte seed.
#[must_use]
pub fn ml_dsa_keygen65_from_seed(xi: &[u8; 32]) -> MlDsa65Keypair {
    keygen_from_seed::<MlDsa65>(xi)
}

/// Deterministically signs a message with ML-DSA-65 using explicit signing
/// randomness.
///
/// The `context` length must be at most 255 bytes.
///
/// # Errors
///
/// Returns:
///
/// - [`MlDsaError::InvalidLength`] if `context.len() > 255`;
/// - [`MlDsaError::InvalidSecretKey`] if `sk` cannot be decoded for ML-DSA-65;
/// - [`MlDsaError::Core`] if the internal signing loop exhausts the supported
///   nonce space.
pub fn ml_dsa_sign65_from_seed(
    sk: &MlDsa65SecretKey,
    message: &[u8],
    context: &[u8],
    randomness: &[u8; 32],
) -> Result<MlDsa65Signature, MlDsaError> {
    sign_from_seed::<MlDsa65>(sk, message, context, randomness)
}

/// Verifies an ML-DSA-65 signature against a message and context.
///
/// # Errors
///
/// Returns:
///
/// - [`MlDsaError::InvalidLength`] if `context.len() > 255`;
/// - [`MlDsaError::InvalidPublicKey`] if `pk` cannot be decoded for ML-DSA-65;
/// - [`MlDsaError::InvalidSignature`] if `signature` is malformed.
pub fn ml_dsa_verify65(
    pk: &MlDsa65PublicKey,
    message: &[u8],
    context: &[u8],
    signature: &MlDsa65Signature,
) -> Result<bool, MlDsaError> {
    verify::<MlDsa65>(pk, message, context, signature)
}




/// Deterministically generates an ML-DSA-87 keypair from a 32-byte seed.
#[must_use]
pub fn ml_dsa_keygen87_from_seed(xi: &[u8; 32]) -> MlDsa87Keypair {
    keygen_from_seed::<MlDsa87>(xi)
}

/// Deterministically signs a message with ML-DSA-87 using explicit signing
/// randomness.
///
/// The `context` length must be at most 255 bytes.
///
/// # Errors
///
/// Returns:
///
/// - [`MlDsaError::InvalidLength`] if `context.len() > 255`;
/// - [`MlDsaError::InvalidSecretKey`] if `sk` cannot be decoded for ML-DSA-87;
/// - [`MlDsaError::Core`] if the internal signing loop exhausts the supported
///   nonce space.
pub fn ml_dsa_sign87_from_seed(
    sk: &MlDsa87SecretKey,
    message: &[u8],
    context: &[u8],
    randomness: &[u8; 32],
) -> Result<MlDsa87Signature, MlDsaError> {
    sign_from_seed::<MlDsa87>(sk, message, context, randomness)
}

/// Verifies an ML-DSA-87 signature against a message and context.
///
/// # Errors
///
/// Returns:
///
/// - [`MlDsaError::InvalidLength`] if `context.len() > 255`;
/// - [`MlDsaError::InvalidPublicKey`] if `pk` cannot be decoded for ML-DSA-87;
/// - [`MlDsaError::InvalidSignature`] if `signature` is malformed.
pub fn ml_dsa_verify87(
    pk: &MlDsa87PublicKey,
    message: &[u8],
    context: &[u8],
    signature: &MlDsa87Signature,
) -> Result<bool, MlDsaError> {
    verify::<MlDsa87>(pk, message, context, signature)
}