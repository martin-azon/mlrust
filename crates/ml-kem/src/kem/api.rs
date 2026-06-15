//! Public ML-KEM API.
//!
//! This module exposes randomized ML-KEM key generation and encapsulation,
//! together with deterministic decapsulation. The generic functions are
//! parameterized by an [`MlKemParams`] marker type, and the concrete wrappers
//! expose the three standardized ML-KEM parameter sets.


use crate::error::MlKemError;
use crate::keys::{
    MlKem512Ciphertext,
    MlKem512DecapsulationKey,
    MlKem512EncapsulationKey,
    MlKem512Keypair,
    MlKem768Ciphertext,
    MlKem768DecapsulationKey,
    MlKem768EncapsulationKey,
    MlKem768Keypair,
    MlKem1024Ciphertext,
    MlKem1024DecapsulationKey,
    MlKem1024EncapsulationKey,
    MlKem1024Keypair,
    SharedSecret,
};

use crate::constants::{
    MlKem512,
    MlKem768,
    MlKem1024,
};

use super::params::MlKemParams;



/// Fills `bytes` with randomness from the operating system.
fn fill_random(bytes: &mut [u8]) -> Result<(), MlKemError> {
    getrandom::fill(bytes)
        .map_err(|_| MlKemError::RandomnessGenerationFailed)
}


/// Samples a uniformly random 32-byte string.
fn random_32() -> Result<[u8; 32], MlKemError> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes)?;
    Ok(bytes)
}


/// Generates an ML-KEM keypair for parameter set `P`.
///
/// This is the randomized public form of ML-KEM key generation. It samples
/// the two 32-byte seeds required by the deterministic internal key-generation
/// routine and returns the corresponding keypair.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessGenerationFailed`] if randomness generation
/// fails.
pub fn ml_kem_keygen<P: MlKemParams>() -> Result<P::Keypair, MlKemError> {
    let d = random_32()?;
    let z = random_32()?;

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
/// Returns [`MlKemError::RandomnessGenerationFailed`] if randomness generation
/// fails.
pub fn ml_kem_encaps<P: MlKemParams>(
    ek: &P::EncapsulationKey,
) -> Result<(SharedSecret, P::Ciphertext), MlKemError> {
    let m = random_32()?;

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
/// Returns [`MlKemError::RandomnessGenerationFailed`] if randomness generation
/// fails.
pub fn ml_kem_keygen512() -> Result<MlKem512Keypair, MlKemError> {
    ml_kem_keygen::<MlKem512>()
}


/// Encapsulates a shared secret to an ML-KEM-512 encapsulation key.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessGenerationFailed`] if randomness generation
/// fails.
pub fn ml_kem_encaps512(
    ek: &MlKem512EncapsulationKey,
) -> Result<(SharedSecret, MlKem512Ciphertext), MlKemError> {
    ml_kem_encaps::<MlKem512>(ek)
}


/// Decapsulates an ML-KEM-512 ciphertext.
#[must_use]
pub fn ml_kem_decaps512(
    dk: &MlKem512DecapsulationKey,
    ciphertext: &MlKem512Ciphertext,
) -> SharedSecret {
    ml_kem_decaps::<MlKem512>(dk, ciphertext)
}


/// Generates an ML-KEM-768 keypair.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessGenerationFailed`] if randomness generation
/// fails.
pub fn ml_kem_keygen768() -> Result<MlKem768Keypair, MlKemError> {
    ml_kem_keygen::<MlKem768>()
}


/// Encapsulates a shared secret to an ML-KEM-768 encapsulation key.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessGenerationFailed`] if randomness generation
/// fails.
pub fn ml_kem_encaps768(
    ek: &MlKem768EncapsulationKey,
) -> Result<(SharedSecret, MlKem768Ciphertext), MlKemError> {
    ml_kem_encaps::<MlKem768>(ek)
}


/// Decapsulates an ML-KEM-512 ciphertext.
#[must_use]
pub fn ml_kem_decaps768(
    dk: &MlKem768DecapsulationKey,
    ciphertext: &MlKem768Ciphertext,
) -> SharedSecret {
    ml_kem_decaps::<MlKem768>(dk, ciphertext)
}


/// Generates an ML-KEM-1024 keypair.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessGenerationFailed`] if randomness generation
/// fails.
pub fn ml_kem_keygen1024() -> Result<MlKem1024Keypair, MlKemError> {
    ml_kem_keygen::<MlKem1024>()
}


/// Encapsulates a shared secret to an ML-KEM-1024 encapsulation key.
///
/// # Errors
///
/// Returns [`MlKemError::RandomnessGenerationFailed`] if randomness generation
/// fails.
pub fn ml_kem_encaps1024(
    ek: &MlKem1024EncapsulationKey,
) -> Result<(SharedSecret, MlKem1024Ciphertext), MlKemError> {
    ml_kem_encaps::<MlKem1024>(ek)
}


/// Decapsulates an ML-KEM-512 ciphertext.
#[must_use]
pub fn ml_kem_decaps1024(
    dk: &MlKem1024DecapsulationKey,
    ciphertext: &MlKem1024Ciphertext,
) -> SharedSecret {
    ml_kem_decaps::<MlKem1024>(dk, ciphertext)
}
