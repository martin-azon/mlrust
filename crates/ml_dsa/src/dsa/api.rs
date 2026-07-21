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


#[cfg(feature = "getrandom")]
use mlrust_core::sampling::random::{random_array, os_random_array, RandomByteGenerator};

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


/// Generates an ML-DSA keypair using operating-system randomness.
///
/// This is the randomized public form of ML-DSA key generation. It samples
/// the 32-byte seed required by the deterministic internal key-generation
/// routine and returns the corresponding keypair.
///
/// # Errors
///
/// Returns [`MlDsaError::RandomnessFailure`] if operating-system randomness
/// generation fails.
#[cfg(feature = "getrandom")]
pub fn ml_dsa_keygen<P: MlDsaParams>() -> Result<P::KeyPair, MlDsaError> {
    let xi = os_random_array::<32>()?;

    Ok(P::keygen_from_seed(&xi))
}


/// Generates an ML-DSA keypair using a caller-provided random byte generator.
///
/// The generator is used to produce the 32-byte seed required
/// by deterministic ML-DSA key generation.
///
/// # Errors
///
/// Returns [`MlDsaError::RandomnessFailure`] if `rbg` fails.
pub fn ml_dsa_keygen_with_rbg<P: MlDsaParams, R: RandomByteGenerator + ?Sized>(
    rbg: &mut R
) -> Result<P::KeyPair, MlDsaError> {
    let xi = random_array::<32, _>(rbg)?;

    Ok(P::keygen_from_seed(&xi))
}


/// Signs a message with ML-DSA using operating-system randomness.
///
/// This is the randomized public form of ML-DSA signing. It samples the
/// 32-byte signing randomness internally, and returns a signature.
///
/// # Errors
///
/// Returns an error if randomness generation fails, the context is too long, or
/// the secret key is malformed.
#[cfg(feature = "getrandom")]
pub fn ml_dsa_sign<P: MlDsaParams>(
    sk: &P::SecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<P::Signature, MlDsaError> {
    let randomness = os_random_array::<32>()?;

    P::sign_from_seed(sk, message, context, &randomness)
}


/// Signs a message with ML-DSA using a caller-provided random byte generator.
///
/// The generator is used to produce the 32-byte signing randomness seed.
///
/// # Errors
///
/// Returns an error if `rbg` fails, the context is too long, or the secret key
/// is malformed.
pub fn ml_dsa_sign_with_rbg<P: MlDsaParams, R: RandomByteGenerator + ?Sized>(
    sk: &P::SecretKey,
    message: &[u8],
    context: &[u8],
    rbg: &mut R
) -> Result<P::Signature, MlDsaError> {
    let randomness = random_array::<32, _>(rbg)?;

    P::sign_from_seed(sk, message, context, &randomness)
}


/// Verifies a signature against a message with context.
pub fn ml_dsa_verify<P: MlDsaParams>(
    pk: &P::PublicKey,
    message: &[u8],
    context: &[u8],
    signature: &P::Signature,
) -> Result<bool, MlDsaError> {
    P::verify(pk, message, context, signature)
}



/// Generates an ML-DSA-44 keypair using operating-system randomness.
///
/// # Errors
///
/// Returns [`MlDsaError::RandomnessFailure`] if operating-system randomness
/// generation fails.
 #[cfg(feature = "getrandom")]
pub fn ml_dsa44_keygen() -> Result<MlDsa44Keypair, MlDsaError> {
    ml_dsa_keygen::<MlDsa44>()
}


/// Generates an ML-DSA-44 keypair using a caller-provided random byte generator.
///
/// # Errors
///
/// Returns [`MlDsaError::RandomnessFailure`] if `rbg` fails.
pub fn ml_dsa44_keygen_with_rbg<R: RandomByteGenerator + ?Sized>(
    rbg: &mut R
) -> Result<MlDsa44Keypair, MlDsaError> {
    ml_dsa_keygen_with_rbg::<MlDsa44, R>(rbg)
}


/// Signs a message with ML-DSA-44 using operating-system randomness.
///
/// # Errors
///
/// Returns an error if randomness generation fails, the context is too long, or
/// the secret key is malformed.
 #[cfg(feature = "getrandom")]
pub fn ml_dsa44_sign(
    sk: &MlDsa44SecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<MlDsa44Signature, MlDsaError> {
    ml_dsa_sign::<MlDsa44>(sk, message, context)
}


/// Signs a message with ML-DSA-44 using a caller-provided random byte generator.
///
/// # Errors
///
/// Returns an error if `rbg` fails, the context is too long, or the secret key
/// is malformed.
pub fn ml_dsa44_sign_with_rbg<R: RandomByteGenerator + ?Sized>(
    sk: &MlDsa44SecretKey,
    message: &[u8],
    context: &[u8],
    rbg: &mut R
) -> Result<MlDsa44Signature, MlDsaError> {
    ml_dsa_sign_with_rbg::<MlDsa44, R>(sk, message, context, rbg)
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
pub fn ml_dsa44_verify(
    pk: &MlDsa44PublicKey,
    message: &[u8],
    context: &[u8],
    signature: &MlDsa44Signature,
) -> Result<bool, MlDsaError> {
    ml_dsa_verify::<MlDsa44>(pk, message, context, signature)
}


/// Generates an ML-DSA-65 keypair using operating-system randomness.
///
/// # Errors
///
/// Returns [`MlDsaError::RandomnessFailure`] if operating-system randomness
/// generation fails.
 #[cfg(feature = "getrandom")]
pub fn ml_dsa65_keygen() -> Result<MlDsa65Keypair, MlDsaError> {
    ml_dsa_keygen::<MlDsa65>()
}


/// Generates an ML-DSA-65 keypair using a caller-provided random byte generator.
///
/// # Errors
///
/// Returns [`MlDsaError::RandomnessFailure`] if `rbg` fails.
pub fn ml_dsa65_keygen_with_rbg<R: RandomByteGenerator + ?Sized>(
    rbg: &mut R
) -> Result<MlDsa65Keypair, MlDsaError> {
    ml_dsa_keygen_with_rbg::<MlDsa65, R>(rbg)
}


/// Signs a message with ML-DSA-65 using operating-system randomness.
///
/// # Errors
///
/// Returns an error if randomness generation fails, the context is too long, or
/// the secret key is malformed.
 #[cfg(feature = "getrandom")]
pub fn ml_dsa65_sign(
    sk: &MlDsa65SecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<MlDsa65Signature, MlDsaError> {
    ml_dsa_sign::<MlDsa65>(sk, message, context)
}


/// Signs a message with ML-DSA-65 using a caller-provided random byte generator.
///
/// # Errors
///
/// Returns an error if `rbg` fails, the context is too long, or the secret key
/// is malformed.
pub fn ml_dsa65_sign_with_rbg<R: RandomByteGenerator + ?Sized>(
    sk: &MlDsa65SecretKey,
    message: &[u8],
    context: &[u8],
    rbg: &mut R
) -> Result<MlDsa65Signature, MlDsaError> {
    ml_dsa_sign_with_rbg::<MlDsa65, R>(sk, message, context, rbg)
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
pub fn ml_dsa65_verify(
    pk: &MlDsa65PublicKey,
    message: &[u8],
    context: &[u8],
    signature: &MlDsa65Signature,
) -> Result<bool, MlDsaError> {
    ml_dsa_verify::<MlDsa65>(pk, message, context, signature)
}


/// Generates an ML-DSA-87 keypair using operating-system randomness.
///
/// # Errors
///
/// Returns [`MlDsaError::RandomnessFailure`] if operating-system randomness
/// generation fails.
 #[cfg(feature = "getrandom")]
pub fn ml_dsa87_keygen() -> Result<MlDsa87Keypair, MlDsaError> {
    ml_dsa_keygen::<MlDsa87>()
}


/// Generates an ML-DSA-87 keypair using a caller-provided random byte generator.
///
/// # Errors
///
/// Returns [`MlDsaError::RandomnessFailure`] if `rbg` fails.
pub fn ml_dsa87_keygen_with_rbg<R: RandomByteGenerator + ?Sized>(
    rbg: &mut R
) -> Result<MlDsa87Keypair, MlDsaError> {
    ml_dsa_keygen_with_rbg::<MlDsa87, R>(rbg)
}


/// Signs a message with ML-DSA-87 using operating-system randomness.
///
/// # Errors
///
/// Returns an error if randomness generation fails, the context is too long, or
/// the secret key is malformed.
 #[cfg(feature = "getrandom")]
pub fn ml_dsa87_sign(
    sk: &MlDsa87SecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<MlDsa87Signature, MlDsaError> {
    ml_dsa_sign::<MlDsa87>(sk, message, context)
}


/// Signs a message with ML-DSA-87 using a caller-provided random byte generator.
///
/// # Errors
///
/// Returns an error if `rbg` fails, the context is too long, or the secret key
/// is malformed.
pub fn ml_dsa87_sign_with_rbg<R: RandomByteGenerator + ?Sized>(
    sk: &MlDsa87SecretKey,
    message: &[u8],
    context: &[u8],
    rbg: &mut R
) -> Result<MlDsa87Signature, MlDsaError> {
    ml_dsa_sign_with_rbg::<MlDsa87, R>(sk, message, context, rbg)
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
pub fn ml_dsa87_verify(
    pk: &MlDsa87PublicKey,
    message: &[u8],
    context: &[u8],
    signature: &MlDsa87Signature,
) -> Result<bool, MlDsaError> {
    ml_dsa_verify::<MlDsa87>(pk, message, context, signature)
}