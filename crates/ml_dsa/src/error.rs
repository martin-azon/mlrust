//! Error types for the ML-DSA crate.

use core::fmt;
use mlrust_core::error::PqcCoreError;


/// Errors returned by the ML-DSA public API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsaError {
    /// The operating system or platform randomness source failed.
    RandomnessFailure,

    /// A provided byte string had an invalid length.
    InvalidLength,

    /// The encoded public key was malformed or non-canonical.
    InvalidPublicKey,

    /// The encoded secret key was malformed or non-canonical.
    InvalidSecretKey,

    /// The encoded signature was malformed or non-canonical.
    InvalidSignature,

    /// The signature was well-formed but did not verify.
    VerificationFailed,

    /// A lower-level reusable core primitive failed.
    Core(PqcCoreError),
}


impl fmt::Display for MlDsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlDsaError::RandomnessFailure => {
                f.write_str("randomness generation failed")
            }
            MlDsaError::InvalidLength => {
                f.write_str("invalid ML-DSA input length")
            }
            MlDsaError::InvalidPublicKey => {
                f.write_str("invalid ML-DSA public key")
            }
            MlDsaError::InvalidSecretKey => {
                f.write_str("invalid ML-DSA secret key")
            }
            MlDsaError::InvalidSignature => {
                f.write_str("invalid ML-DSA signature")
            }
            MlDsaError::VerificationFailed => {
                f.write_str("ML-DSA signature verification failed")
            }
            Self::Core(err) => write!(f, "ML-DSA core error: {err}")
        }
    }
}


#[cfg(feature = "std")]
impl std::error::Error for MlDsaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(err) => Some(err),
            _ => None,
        }
    }
}