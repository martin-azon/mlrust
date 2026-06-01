//! Error type for reusable `mlrust-core` operations.
//!
//! The errors in this module describe failures in low-level shared utilities,
//! such as malformed encodings, invalid buffer lengths, or bounded rejection
//! sampling failures. Algorithm-specific errors should be defined in the
//! ML-KEM and ML-DSA crates.


use core::fmt;

/// Error type for low-level reusable `mlrust-core` operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcCoreError {
    /// An input slice or byte string has an invalid length.
    InvalidLength,
    /// A caller-provided output buffer is too small.
    BufferTooSmall,
    /// A byte sequence does not match the expected encoding format.
    InvalidEncoding,
    /// A byte sequence decodes to a value outside the required canonical range.
    NonCanonicalEncoding,
    /// Rejection sampling failed to produce enough output within a bounded loop.
    RejectionSamplingFailed,
}

impl fmt::Display for PqcCoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidLength => f.write_str("invalid input length"),
            Self::BufferTooSmall => f.write_str("output buffer too small"),
            Self::InvalidEncoding => f.write_str("invalid encoding"),
            Self::NonCanonicalEncoding => f.write_str("non-canonical encoding"),
            Self::RejectionSamplingFailed => f.write_str("rejection sampling failed"),
        }
    }
}


#[cfg(feature = "std")]
impl std::error::Error for PqcCoreError {}