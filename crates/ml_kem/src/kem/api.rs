//! Public ML-KEM API.
//!
//! This module exposes randomized ML-KEM key generation and encapsulation,
//! together with deterministic decapsulation. The generic functions are
//! parameterized by an [`MlKemParams`] marker type, and the concrete wrappers
//! expose the three standardized ML-KEM parameter sets.

use mlrust_core::sampling::random::{RandomByteGenerator, random_array};

#[cfg(feature = "getrandom")]
use mlrust_core::sampling::random::os_random_array;

use super::params::MlKemParams;
use crate::constants::{MlKem512, MlKem768, MlKem1024};
use crate::error::MlKemError;
use crate::keys::{
    MlKem512Ciphertext, MlKem512DecapsulationKey, MlKem512EncapsulationKey, MlKem512Keypair,
    MlKem768Ciphertext, MlKem768DecapsulationKey, MlKem768EncapsulationKey, MlKem768Keypair,
    MlKem1024Ciphertext, MlKem1024DecapsulationKey, MlKem1024EncapsulationKey, MlKem1024Keypair,
    SharedSecret,
};

/// Generates an ML-KEM keypair for parameter set `P`.
///
/// This is the randomized public form of ML-KEM key generation. It samples
/// the two 32-byte seeds required by the deterministic internal key-generation
/// routine and returns the corresponding keypair.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if operating-system randomness
/// generation fails.
#[cfg(feature = "getrandom")]
pub fn ml_kem_keygen<P: MlKemParams>() -> Result<P::Keypair, MlKemError> {
    let d = os_random_array::<32>()?;
    let z = os_random_array::<32>()?;

    Ok(P::keygen_from_seed(&d, &z))
}

/// Generates an ML-KEM keypair using a caller-provided random byte generator.
///
/// The generator is used to produce the two 32-byte seeds required by
/// deterministic ML-KEM key generation.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if `rbg` fails.
pub fn ml_kem_keygen_with_rbg<P: MlKemParams, R: RandomByteGenerator + ?Sized>(
    rbg: &mut R,
) -> Result<P::Keypair, MlKemError> {
    let d = random_array::<32, _>(rbg)?;
    let z = random_array::<32, _>(rbg)?;

    Ok(P::keygen_from_seed(&d, &z))
}

/// Encapsulates a shared secret to an ML-KEM encapsulation key.
///
/// This is the randomized public form of ML-KEM encapsulation. It samples the
/// 32-byte encapsulation randomness internally, derives a shared secret, and
/// returns the shared secret together with the ciphertext.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if operating-system randomness
/// generation fails.
#[cfg(feature = "getrandom")]
pub fn ml_kem_encaps<P: MlKemParams>(
    ek: &P::EncapsulationKey,
) -> Result<(SharedSecret, P::Ciphertext), MlKemError> {
    let m = os_random_array::<32>()?;

    Ok(P::encaps_from_seed(ek, &m))
}

/// Encapsulates using a caller-provided random byte generator.
///
/// The generator is used to produce the 32-byte encapsulation seed.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if `rbg` fails.
pub fn ml_kem_encaps_with_rbg<P: MlKemParams, R: RandomByteGenerator + ?Sized>(
    ek: &P::EncapsulationKey,
    rbg: &mut R,
) -> Result<(SharedSecret, P::Ciphertext), MlKemError> {
    let m = random_array::<32, _>(rbg)?;

    Ok(P::encaps_from_seed(ek, &m))
}

/// Decapsulates an ML-KEM ciphertext.
///
/// This function is infallible at the API level. Invalid ciphertexts are
/// handled internally by the ML-KEM re-encryption check and fallback shared
/// secret derivation.
#[must_use]
pub fn ml_kem_decaps<P: MlKemParams>(
    dk: &P::DecapsulationKey,
    ciphertext: &P::Ciphertext,
) -> SharedSecret {
    P::decaps(dk, ciphertext)
}

/// Generates an ML-KEM-512 keypair.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if randomness generation
/// fails.
#[cfg(feature = "getrandom")]
pub fn ml_kem512_keygen() -> Result<MlKem512Keypair, MlKemError> {
    ml_kem_keygen::<MlKem512>()
}

/// Generates an ML-KEM-512 keypair using a caller-provided random byte generator.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if `rbg` fails.
pub fn ml_kem512_keygen_with_rbg<R: RandomByteGenerator + ?Sized>(
    rbg: &mut R,
) -> Result<MlKem512Keypair, MlKemError> {
    ml_kem_keygen_with_rbg::<MlKem512, R>(rbg)
}

/// Encapsulates a shared secret to an ML-KEM-512 encapsulation key.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if randomness generation
/// fails.
#[cfg(feature = "getrandom")]
pub fn ml_kem512_encaps(
    ek: &MlKem512EncapsulationKey,
) -> Result<(SharedSecret, MlKem512Ciphertext), MlKemError> {
    ml_kem_encaps::<MlKem512>(ek)
}

/// Encapsulates to an ML-KEM-512 encapsulation key using a caller-provided RBG.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if `rbg` fails.
pub fn ml_kem512_encaps_with_rbg<R: RandomByteGenerator + ?Sized>(
    ek: &MlKem512EncapsulationKey,
    rbg: &mut R,
) -> Result<(SharedSecret, MlKem512Ciphertext), MlKemError> {
    ml_kem_encaps_with_rbg::<MlKem512, R>(ek, rbg)
}

/// Decapsulates an ML-KEM-512 ciphertext.
#[must_use]
pub fn ml_kem512_decaps(
    dk: &MlKem512DecapsulationKey,
    ciphertext: &MlKem512Ciphertext,
) -> SharedSecret {
    ml_kem_decaps::<MlKem512>(dk, ciphertext)
}

/// Generates an ML-KEM-768 keypair.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if randomness generation
/// fails.
#[cfg(feature = "getrandom")]
pub fn ml_kem768_keygen() -> Result<MlKem768Keypair, MlKemError> {
    ml_kem_keygen::<MlKem768>()
}

/// Generates an ML-KEM-768 keypair using a caller-provided random byte generator.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if `rbg` fails.
pub fn ml_kem768_keygen_with_rbg<R: RandomByteGenerator + ?Sized>(
    rbg: &mut R,
) -> Result<MlKem768Keypair, MlKemError> {
    ml_kem_keygen_with_rbg::<MlKem768, R>(rbg)
}

/// Encapsulates a shared secret to an ML-KEM-768 encapsulation key.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if randomness generation
/// fails.
#[cfg(feature = "getrandom")]
pub fn ml_kem768_encaps(
    ek: &MlKem768EncapsulationKey,
) -> Result<(SharedSecret, MlKem768Ciphertext), MlKemError> {
    ml_kem_encaps::<MlKem768>(ek)
}

/// Encapsulates to an ML-KEM-768 encapsulation key using a caller-provided RBG.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if `rbg` fails.
pub fn ml_kem768_encaps_with_rbg<R: RandomByteGenerator + ?Sized>(
    ek: &MlKem768EncapsulationKey,
    rbg: &mut R,
) -> Result<(SharedSecret, MlKem768Ciphertext), MlKemError> {
    ml_kem_encaps_with_rbg::<MlKem768, R>(ek, rbg)
}

/// Decapsulates an ML-KEM-768 ciphertext.
#[must_use]
pub fn ml_kem768_decaps(
    dk: &MlKem768DecapsulationKey,
    ciphertext: &MlKem768Ciphertext,
) -> SharedSecret {
    ml_kem_decaps::<MlKem768>(dk, ciphertext)
}

/// Generates an ML-KEM-1024 keypair.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if randomness generation
/// fails.
#[cfg(feature = "getrandom")]
pub fn ml_kem1024_keygen() -> Result<MlKem1024Keypair, MlKemError> {
    ml_kem_keygen::<MlKem1024>()
}

/// Generates an ML-KEM-1024 keypair using a caller-provided random byte generator.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if `rbg` fails.
pub fn ml_kem1024_keygen_with_rbg<R: RandomByteGenerator + ?Sized>(
    rbg: &mut R,
) -> Result<MlKem1024Keypair, MlKemError> {
    ml_kem_keygen_with_rbg::<MlKem1024, R>(rbg)
}

/// Encapsulates a shared secret to an ML-KEM-1024 encapsulation key.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if randomness generation
/// fails.
#[cfg(feature = "getrandom")]
pub fn ml_kem1024_encaps(
    ek: &MlKem1024EncapsulationKey,
) -> Result<(SharedSecret, MlKem1024Ciphertext), MlKemError> {
    ml_kem_encaps::<MlKem1024>(ek)
}

/// Encapsulates to an ML-KEM-1024 encapsulation key using a caller-provided RBG.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessFailure`] if `rbg` fails.
pub fn ml_kem1024_encaps_with_rbg<R: RandomByteGenerator + ?Sized>(
    ek: &MlKem1024EncapsulationKey,
    rbg: &mut R,
) -> Result<(SharedSecret, MlKem1024Ciphertext), MlKemError> {
    ml_kem_encaps_with_rbg::<MlKem1024, R>(ek, rbg)
}

/// Decapsulates an ML-KEM-1024 ciphertext.
#[must_use]
pub fn ml_kem1024_decaps(
    dk: &MlKem1024DecapsulationKey,
    ciphertext: &MlKem1024Ciphertext,
) -> SharedSecret {
    ml_kem_decaps::<MlKem1024>(dk, ciphertext)
}
