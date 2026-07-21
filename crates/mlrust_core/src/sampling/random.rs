//! Random byte generation abstraction.
//!
//! This module defines a small trait for filling byte buffers with random
//! bytes. Protocol crates map the generic [`RandomError`] into their own error
//! types.
//!
//! The abstraction is intentionally byte-oriented. ML-KEM and ML-DSA use random
//! byte strings as seeds or signing randomness, and then derive structured
//! objects from those bytes using their protocol-specific algorithms.

/// Error returned by a random byte generator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomError {
    /// The random byte generator failed to fill the requested buffer.
    GeneratorFailure,
}

/// Trait for user-provided random byte generators.
///
/// Implementations must fill the entire `output` buffer with random bytes or
/// return an error. Partial success must not be reported as `Ok(())`.
pub trait RandomByteGenerator {
    /// Fills `output` with random bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RandomError::GeneratorFailure`] if the generator cannot produce
    /// the requested bytes.
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), RandomError>;
}

/// Fills and returns a fixed-size random byte array.
///
/// # Errors
///
/// Returns [`RandomError::GeneratorFailure`] if `rng` fails to fill the output
/// buffer.
pub fn random_array<const N: usize, R: RandomByteGenerator + ?Sized>(
    rng: &mut R,
) -> Result<[u8; N], RandomError> {
    let mut output = [0u8; N];

    rng.fill_bytes(&mut output[..])?;
    Ok(output)
}

/// Operating-system random byte generator.
///
/// This is a convenience backend using the `getrandom` crate. Protocol crates
/// also expose APIs accepting a caller-provided [`RandomByteGenerator`] so users
/// can supply their own RBG.
#[cfg(feature = "getrandom")]
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandom;

#[cfg(feature = "getrandom")]
impl RandomByteGenerator for OsRandom {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), RandomError> {
        getrandom::fill(output).map_err(|_| RandomError::GeneratorFailure)
    }
}

/// Fills and returns a fixed-size random byte array using [`OsRandom`].
///
/// # Errors
///
/// Returns [`RandomError::GeneratorFailure`] if the operating-system RNG fails.
#[cfg(feature = "getrandom")]
pub fn os_random_array<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut rng = OsRandom;

    random_array::<N, _>(&mut rng)
}
