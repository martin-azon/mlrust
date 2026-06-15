//! Error types for the ML-KEM crate.

use core::fmt;

/// Errors returned by the public ML-KEM API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKemError {
    /// The operating system or configured random source failed.
    RandomnessGenerationFailed,

    /// A byte slice had the wrong length for the requested ML-KEM object.
    InvalidLength {
        /// Expected size of the byte slice.
        expected: usize,
        /// Actual size of the byte slice.
        actual: usize,
    },
}

impl fmt::Display for MlKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlKemError::RandomnessGenerationFailed => {
                write!(f, "randomness generation failed")
            }
            MlKemError::InvalidLength { expected, actual } => {
                write!(f, "invalid byte length: expected {expected}, got {actual}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MlKemError {}
