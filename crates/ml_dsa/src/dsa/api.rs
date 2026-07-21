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


#[must_use]
pub fn ml_dsa_keygen<P: MlDsaParams>() -> Result<P::KeyPair, MlDsaError> {
    let xi = os_random_array()?;

    P::keygen_from_seed(&xi)
}


pub fn ml_dsa_keygen_with_rbg<P: MlDsaParams, R: RandomByteGenerator + ?Sized>(
    rbg: &mut R
) -> Result<P::KeyPair, MlDsaError> {
    let xi = random_array::<32, _>(rbg)?;

    P::keygen_from_seed(&xi)
}


pub fn ml_dsa_sign<P: MlDsaParams>(
    sk: &P::SecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<P::Signature, MlDsaError> {
    let randomness = os_random_array()?;

    P::sign_from_seed(sk, message, context, &randomness)
}


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



#[must_use]
pub fn ml_dsa44_keygen() -> Result<MlDsa44Keypair, MlDsaError> {
    ml_dsa_keygen::<MlDsa44>()
}


#[must_use]
pub fn ml_dsa44_keygen_with_rbg<R: RandomByteGenerator + ?Sized>(
    rbg: &mut R
) -> Result<MlDsa44Keypair, MlDsaError> {
    ml_dsa_keygen_with_rbg::<MlDsa44, R>(rbg)
}


#[must_use]
pub fn ml_dsa44_sign(
    sk: &MlDsa44SecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<MlDsa44Signature, MlDsaError> {
    ml_dsa_sign::<MlDsa44>(sk, message, context)
}


#[must_use]
pub fn ml_dsa44_sign_with_rbg<R: RandomByteGenerator + ?Sized>(
    rbg: &mut R
) -> Result<MlDsa44Keypair, MlDsaError> {
    ml_dsa_keygen_with_rbg::<MlDsa44, R>(rbg)
}


#[must_use]
pub fn ml_dsa44_verify(
    pk: &MlDsa44PublicKey,
    message: &[u8],
    context: &[u8],
    signature: &MlDsa44Signature,
) -> Result<bool, MlDsaError> {
    ml_dsa_verify::<MlDsa44>(pk, message, context, signature)
}


#[must_use]
pub fn ml_dsa65_keygen() -> Result<MlDsa65Keypair, MlDsaError> {
    ml_dsa_keygen::<MlDsa65>()
}


#[must_use]
pub fn ml_dsa65_keygen_with_rbg<R: RandomByteGenerator + ?Sized>(
    rbg: &mut R
) -> Result<MlDsa65Keypair, MlDsaError> {
    ml_dsa_keygen_with_rbg::<MlDsa65, R>(rbg)
}


#[must_use]
pub fn ml_dsa65_sign(
    sk: &MlDsa65SecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<MlDsa65Signature, MlDsaError> {
    ml_dsa_sign::<MlDsa65>(sk, message, context)
}


#[must_use]
pub fn ml_dsa65_sign_with_rbg<R: RandomByteGenerator + ?Sized>(
    rbg: &mut R
) -> Result<MlDsa65Keypair, MlDsaError> {
    ml_dsa_keygen_with_rbg::<MlDsa65, R>(rbg)
}


#[must_use]
pub fn ml_dsa65_verify(
    pk: &MlDsa65PublicKey,
    message: &[u8],
    context: &[u8],
    signature: &MlDsa65Signature,
) -> Result<bool, MlDsaError> {
    ml_dsa_verify::<MlDsa65>(pk, message, context, signature)
}


#[must_use]
pub fn ml_dsa87_keygen() -> Result<MlDsa87Keypair, MlDsaError> {
    ml_dsa_keygen::<MlDsa87>()
}


#[must_use]
pub fn ml_dsa87_keygen_with_rbg<R: RandomByteGenerator + ?Sized>(
    rbg: &mut R
) -> Result<MlDsa87Keypair, MlDsaError> {
    ml_dsa_keygen_with_rbg::<MlDsa87, R>(rbg)
}


#[must_use]
pub fn ml_dsa87_sign(
    sk: &MlDsa87SecretKey,
    message: &[u8],
    context: &[u8],
) -> Result<MlDsa87Signature, MlDsaError> {
    ml_dsa_sign::<MlDsa87>(sk, message, context)
}


#[must_use]
pub fn ml_dsa87_sign_with_rbg<R: RandomByteGenerator + ?Sized>(
    rbg: &mut R
) -> Result<MlDsa87Keypair, MlDsaError> {
    ml_dsa_keygen_with_rbg::<MlDsa87, R>(rbg)
}


#[must_use]
pub fn ml_dsa87_verify(
    pk: &MlDsa87PublicKey,
    message: &[u8],
    context: &[u8],
    signature: &MlDsa87Signature,
) -> Result<bool, MlDsaError> {
    ml_dsa_verify::<MlDsa87>(pk, message, context, signature)
}