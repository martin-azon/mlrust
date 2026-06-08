//! ML-KEM serialized object types.
//!
//! This module defines fixed-size wrappers for ML-KEM encapsulation keys,
//! decapsulation keys, ciphertexts, and shared secrets.

use crate::params::{
    ML_KEM_512_CIPHERTEXT_BYTES,
    ML_KEM_512_DECAPS_KEY_BYTES,
    ML_KEM_512_ENCAPS_KEY_BYTES,
    ML_KEM_768_CIPHERTEXT_BYTES,
    ML_KEM_768_DECAPS_KEY_BYTES,
    ML_KEM_768_ENCAPS_KEY_BYTES,
    ML_KEM_1024_CIPHERTEXT_BYTES,
    ML_KEM_1024_DECAPS_KEY_BYTES,
    ML_KEM_1024_ENCAPS_KEY_BYTES,
    ML_KEM_SHARED_SECRET_BYTES,
};



// --------------------------------------------------------------------
// Defining generic structs for each of the keys
// --------------------------------------------------------------------

/// Fixed-size ML-KEM encapsulation key.
#[derive(Clone, PartialEq, Eq)]
pub struct EncapsulationKey<const N: usize> {
    bytes: [u8; N],
}


/// Fixed-size ML-KEM decapsulation key.
#[derive(Clone, PartialEq, Eq)]
pub struct DecapsulationKey<const N: usize> {
    bytes: [u8; N],
}


/// Fixed-size ML-KEM ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext<const N: usize> {
    bytes: [u8; N],
}


/// ML-KEM shared secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SharedSecret {
    bytes: [u8; ML_KEM_SHARED_SECRET_BYTES],
}



// --------------------------------------------------------------------
// Defining key types for each of the instantiations of ML-KEM
// --------------------------------------------------------------------

/// ML-KEM-512 encapsulation key.
pub type MlKem512EncapsulationKey =
    EncapsulationKey<ML_KEM_512_ENCAPS_KEY_BYTES>;

/// ML-KEM-512 decapsulation key.
pub type MlKem512DecapsulationKey =
    DecapsulationKey<ML_KEM_512_DECAPS_KEY_BYTES>;

/// ML-KEM-512 ciphertext.
pub type MlKem512Ciphertext =
    Ciphertext<ML_KEM_512_CIPHERTEXT_BYTES>;

/// ML-KEM-768 encapsulation key.
pub type MlKem768EncapsulationKey =
    EncapsulationKey<ML_KEM_768_ENCAPS_KEY_BYTES>;

/// ML-KEM-768 decapsulation key.
pub type MlKem768DecapsulationKey =
    DecapsulationKey<ML_KEM_768_DECAPS_KEY_BYTES>;

/// ML-KEM-768 ciphertext.
pub type MlKem768Ciphertext =
    Ciphertext<ML_KEM_768_CIPHERTEXT_BYTES>;

/// ML-KEM-1024 encapsulation key.
pub type MlKem1024EncapsulationKey =
    EncapsulationKey<ML_KEM_1024_ENCAPS_KEY_BYTES>;

/// ML-KEM-1024 decapsulation key.
pub type MlKem1024DecapsulationKey =
    DecapsulationKey<ML_KEM_1024_DECAPS_KEY_BYTES>;

/// ML-KEM-1024 ciphertext.
pub type MlKem1024Ciphertext =
    Ciphertext<ML_KEM_1024_CIPHERTEXT_BYTES>;



// --------------------------------------------------------------------
// Generic traits for each of the keys
// --------------------------------------------------------------------

impl<const N: usize> EncapsulationKey<N> {
    /// Creates an encapsulation key from its serialized bytes
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Returns the serialized encapsulation key
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consumes the key and returns the serialized bytes
    #[must_use]
    pub const fn into_bytes(self) -> [u8; N] {
        self.bytes
    }
}



impl<const N: usize> DecapsulationKey<N> {
    /// Creates a decapsulation key from its serialized bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Returns the serialized decapsulation key.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consumes the key and returns the serialized bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; N] {
        self.bytes
    }
}

impl<const N: usize> Ciphertext<N> {
    /// Creates a ciphertext from its serialized bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Returns the serialized ciphertext.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consumes the ciphertext and returns the serialized bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; N] {
        self.bytes
    }
}

impl SharedSecret {
    /// Creates a shared secret from its bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ML_KEM_SHARED_SECRET_BYTES]) -> Self {
        Self { bytes }
    }

    /// Returns the shared secret bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ML_KEM_SHARED_SECRET_BYTES] {
        &self.bytes
    }

    /// Consumes the shared secret and returns the bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; ML_KEM_SHARED_SECRET_BYTES] {
        self.bytes
    }
}