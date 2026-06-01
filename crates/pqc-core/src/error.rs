use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcCoreError {
    InvalidLength,
    BufferTooSmall,
    InvalidEncoding,
    NonCanonicalEncoding,
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