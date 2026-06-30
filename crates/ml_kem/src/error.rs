//! Error types for the ML-KEM crate.

use core::fmt;
use mlrust_core::error::PqcCoreError;


/// Errors returned by the public ML-KEM API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKemError {
    /// The operating system or platform randomness source failed.
    RandomnessFailure,

    /// A provided byte slice had an invalid length.
    InvalidLength,

    /// A lower-level ML-Rust core primitive failed.
    Core(PqcCoreError),
}

impl From<PqcCoreError> for MlKemError {
    fn from(err: PqcCoreError) -> Self {
        match err {
            PqcCoreError::InvalidLength => MlKemError::InvalidLength,
            other => MlKemError::Core(other),
        }
    }
}

/// Errors displayed by the ML-KEM public API.
impl fmt::Display for MlKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlKemError::RandomnessFailure => {
                f.write_str("randomness generation failed")
            }
            MlKemError::InvalidLength => {
                f.write_str("invalid ML-KEM input length")
            }
            Self::Core(err) => write!(f, "ML-KEM core error: {err}")
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MlKemError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Core(err) => Some(err),
            _ => None,
        }
    }
}
