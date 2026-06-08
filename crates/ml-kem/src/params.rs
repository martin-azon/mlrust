//! ML-KEM parameter sets.
//!
//! This module defines the public parameter sets standardized for ML-KEM:
//!
//! - [`MlKem512`];
//! - [`MlKem768`];
//! - [`MlKem1024`].
//!
//! Each parameter set is represented by a zero-sized marker type implementing
//! [`MlKemParams`]. The associated constants describe the module rank, noise
//! parameters, compression widths, and serialized object sizes for that
//! parameter set.
//!



// --------------------------------------------------------------------
// Defining the trait MlKemParams
// --------------------------------------------------------------------


/// Parameters for an ML-KEM instantiation.
///
/// This trait collects the constants that distinguish ML-KEM-512,
/// ML-KEM-768, and ML-KEM-1024.
///
/// The parameter `K` is the module rank. The noise parameters `ETA1` and
/// `ETA2` determine the centered binomial distributions used for secret and
/// error sampling. The compression widths `DU` and `DV` determine the number
/// of bits used when compressing the two ciphertext components.
///
/// The byte-size constants describe the serialized sizes of the public
/// encapsulation key, secret decapsulation key, ciphertext, and shared secret.
pub trait MlKemParams {

    /// Module rank.
    const K: usize;
    /// Noise parameter for secret-vector sampling.
    const ETA1: usize;
    /// Noise parameter for encryption error sampling.
    const ETA2: usize;
    /// Compression width for the first ciphertext component.
    const DU: usize;
    /// Compression width for the second ciphertext component.
    const DV: usize;

    const ENCAPS_KEY_BYTES: usize;
    const DECAPS_KEY_BYTES: usize;
    const CIPHERTEXT_BYTES: usize;
    const SHARED_SECRET_BYTES: usize = ML_KEM_SHARED_SECRET_BYTES;

}



// --------------------------------------------------------------------
// Fixing the numerical values of the parameters for each instantiation
// --------------------------------------------------------------------

/// Length in bytes of an ML-KEM-512 encapsulation key.
pub const ML_KEM_512_ENCAPS_KEY_BYTES: usize = 800;
/// Length in bytes of an ML-KEM-512 decapsulation key.
pub const ML_KEM_512_DECAPS_KEY_BYTES: usize = 1632;
/// Length in bytes of an ML-KEM-512 ciphertext.
pub const ML_KEM_512_CIPHERTEXT_BYTES: usize = 768;



/// Length in bytes of an ML-KEM-768 encapsulation key.
pub const ML_KEM_768_ENCAPS_KEY_BYTES: usize = 1184;
/// Length in bytes of an ML-KEM-768 decapsulation key.
pub const ML_KEM_768_DECAPS_KEY_BYTES: usize = 2400;
/// Length in bytes of an ML-KEM-768 ciphertext.
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;



/// Length in bytes of an ML-KEM-1024 encapsulation key.
pub const ML_KEM_1024_ENCAPS_KEY_BYTES: usize = 1568;
/// Length in bytes of an ML-KEM-1024 decapsulation key.
pub const ML_KEM_1024_DECAPS_KEY_BYTES: usize = 3168;
/// Length in bytes of an ML-KEM-1024 ciphertext.
pub const ML_KEM_1024_CIPHERTEXT_BYTES: usize = 1568;



/// Length in bytes of an ML-KEM shared secret.
pub const ML_KEM_SHARED_SECRET_BYTES: usize = 32;



// --------------------------------------------------------------------
// Defining enums and setting the parameters for each instantiation
// --------------------------------------------------------------------

/// Marker type for the ML-KEM-512 parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKem512 {}

/// Marker type for the ML-KEM-768 parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKem768 {}

/// Marker type for the ML-KEM-1024 parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKem1024 {}


impl MlKemParams for MlKem512 {
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;

    const ENCAPS_KEY_BYTES: usize = ML_KEM_512_ENCAPS_KEY_BYTES;
    const DECAPS_KEY_BYTES: usize = ML_KEM_512_DECAPS_KEY_BYTES;
    const CIPHERTEXT_BYTES: usize = ML_KEM_512_CIPHERTEXT_BYTES;
}


impl MlKemParams for MlKem768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;

    const ENCAPS_KEY_BYTES: usize = ML_KEM_768_ENCAPS_KEY_BYTES;
    const DECAPS_KEY_BYTES: usize = ML_KEM_768_DECAPS_KEY_BYTES;
    const CIPHERTEXT_BYTES: usize = ML_KEM_768_CIPHERTEXT_BYTES;
}


impl MlKemParams for MlKem1024 {
    const K: usize = 4;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;

    const ENCAPS_KEY_BYTES: usize = ML_KEM_1024_ENCAPS_KEY_BYTES;
    const DECAPS_KEY_BYTES: usize = ML_KEM_1024_DECAPS_KEY_BYTES;
    const CIPHERTEXT_BYTES: usize = ML_KEM_1024_CIPHERTEXT_BYTES;
}

