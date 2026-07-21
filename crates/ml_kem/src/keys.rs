//! ML-KEM serialized object types.
//!
//! This module defines fixed-size wrappers for ML-KEM encapsulation keys,
//! decapsulation keys, ciphertexts, and shared secrets.
//!
//! The generic wrappers enforce byte lengths at the type level. The public
//! aliases correspond to the final ML-KEM object sizes. The same wrappers may
//! also be reused internally for K-PKE objects, whose decapsulation-key lengths
//! are smaller than final ML-KEM decapsulation-key lengths.

use crate::MlKemError;
use crate::constants::{
    ML_KEM_512_CIPHERTEXT_BYTES, ML_KEM_512_DECAPS_KEY_BYTES, ML_KEM_512_ENCAPS_KEY_BYTES,
    ML_KEM_768_CIPHERTEXT_BYTES, ML_KEM_768_DECAPS_KEY_BYTES, ML_KEM_768_ENCAPS_KEY_BYTES,
    ML_KEM_1024_CIPHERTEXT_BYTES, ML_KEM_1024_DECAPS_KEY_BYTES, ML_KEM_1024_ENCAPS_KEY_BYTES,
    ML_KEM_SHARED_SECRET_BYTES,
};
use mlrust_core::params::Q3329;
use mlrust_core::poly::PolyVec;

// --------------------------------------------------------------------
// Defining generic structs for each of the keys
// --------------------------------------------------------------------

/// Fixed-size serialized K-PKE encryption key.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KpkeEncryptionKey<const N: usize> {
    bytes: [u8; N],
}

/// Fixed-size serialized K-PKE decryption key.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KpkeDecryptionKey<const N: usize> {
    bytes: [u8; N],
}

/// Internal algebraic K-PKE keypair before serialization.
///
/// This type is useful for testing and for separating the algebraic key
/// generation logic from FIPS byte encoding.
///
/// # Representation
///
/// Both `s_hat` and `t_hat` are in the NTT/Montgomery domain.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KpkeInternalKeypair<const K: usize> {
    pub(crate) rho: [u8; 32],
    pub(crate) s_hat: PolyVec<Q3329, K>,
    pub(crate) t_hat: PolyVec<Q3329, K>,
}

/// Serialized K-PKE keypair. This is not the final ML-KEM keypair.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KpkeKeypair<const EK_PKE_BYTES: usize, const DK_PKE_BYTES: usize> {
    pub(crate) ek_pke: KpkeEncryptionKey<EK_PKE_BYTES>,
    pub(crate) dk_pke: KpkeDecryptionKey<DK_PKE_BYTES>,
}

/// Fixed-size serialized ML-KEM encapsulation key.
#[derive(Clone, PartialEq, Eq)]
pub struct EncapsulationKey<const N: usize> {
    bytes: [u8; N],
}

/// Fixed-size serialized ML-KEM decapsulation key.
#[derive(Clone, PartialEq, Eq)]
pub struct DecapsulationKey<const N: usize> {
    bytes: [u8; N],
}

/// ML-KEM Keypair.
#[derive(Clone, PartialEq, Eq)]
pub struct MlKemKeypair<const EK_BYTES: usize, const DK_BYTES: usize> {
    ek: EncapsulationKey<EK_BYTES>,
    dk: DecapsulationKey<DK_BYTES>,
}

/// Fixed-size KPKE / ML-KEM ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext<const N: usize> {
    bytes: [u8; N],
}

/// ML-KEM shared secret.
#[derive(Clone, PartialEq, Eq)]
pub struct SharedSecret {
    bytes: [u8; ML_KEM_SHARED_SECRET_BYTES],
}

impl<const EK_BYTES: usize, const DK_BYTES: usize> MlKemKeypair<EK_BYTES, DK_BYTES> {
    /// Returns the encapsulation key.
    #[must_use]
    pub const fn encapsulation_key(&self) -> &EncapsulationKey<EK_BYTES> {
        &self.ek
    }

    /// Returns the decapsulation key.
    #[must_use]
    pub const fn decapsulation_key(&self) -> &DecapsulationKey<DK_BYTES> {
        &self.dk
    }

    /// Splits the keypair into its encapsulation and decapsulation keys.
    #[must_use]
    pub const fn into_parts(self) -> (EncapsulationKey<EK_BYTES>, DecapsulationKey<DK_BYTES>) {
        (self.ek, self.dk)
    }

    /// Constructs a keypair from an encapsulation key and a decapsulation key.
    pub(crate) const fn from_parts(
        ek: EncapsulationKey<EK_BYTES>,
        dk: DecapsulationKey<DK_BYTES>,
    ) -> Self {
        Self { ek, dk }
    }
}

// --------------------------------------------------------------------
// Defining key types for each of the instantiations of ML-KEM
// --------------------------------------------------------------------

/// ML-KEM-512 encapsulation key.
pub type MlKem512EncapsulationKey = EncapsulationKey<ML_KEM_512_ENCAPS_KEY_BYTES>;

/// ML-KEM-512 decapsulation key.
pub type MlKem512DecapsulationKey = DecapsulationKey<ML_KEM_512_DECAPS_KEY_BYTES>;

/// ML-KEM-512 keypair.
pub type MlKem512Keypair = MlKemKeypair<ML_KEM_512_ENCAPS_KEY_BYTES, ML_KEM_512_DECAPS_KEY_BYTES>;

/// ML-KEM-512 ciphertext.
pub type MlKem512Ciphertext = Ciphertext<ML_KEM_512_CIPHERTEXT_BYTES>;

/// ML-KEM-768 encapsulation key.
pub type MlKem768EncapsulationKey = EncapsulationKey<ML_KEM_768_ENCAPS_KEY_BYTES>;

/// ML-KEM-768 decapsulation key.
pub type MlKem768DecapsulationKey = DecapsulationKey<ML_KEM_768_DECAPS_KEY_BYTES>;

/// ML-KEM-768 keypair.
pub type MlKem768Keypair = MlKemKeypair<ML_KEM_768_ENCAPS_KEY_BYTES, ML_KEM_768_DECAPS_KEY_BYTES>;

/// ML-KEM-768 ciphertext.
pub type MlKem768Ciphertext = Ciphertext<ML_KEM_768_CIPHERTEXT_BYTES>;

/// ML-KEM-1024 encapsulation key.
pub type MlKem1024EncapsulationKey = EncapsulationKey<ML_KEM_1024_ENCAPS_KEY_BYTES>;

/// ML-KEM-1024 decapsulation key.
pub type MlKem1024DecapsulationKey = DecapsulationKey<ML_KEM_1024_DECAPS_KEY_BYTES>;

/// ML-KEM-1024 keypair.
pub type MlKem1024Keypair =
    MlKemKeypair<ML_KEM_1024_ENCAPS_KEY_BYTES, ML_KEM_1024_DECAPS_KEY_BYTES>;

/// ML-KEM-1024 ciphertext.
pub type MlKem1024Ciphertext = Ciphertext<ML_KEM_1024_CIPHERTEXT_BYTES>;

// --------------------------------------------------------------------
// Generic traits for each of the keys
// --------------------------------------------------------------------

impl<const N: usize> KpkeEncryptionKey<N> {
    /// Creates an encryption key from its serialized bytes
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Returns the serialized encryption key
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /*
    /// Consumes the key and returns the serialized bytes
    #[must_use]
    pub(crate) const fn into_bytes(self) -> [u8; N] {
        self.bytes
    }
    */
}

impl<const N: usize> KpkeDecryptionKey<N> {
    /// Creates an decryption key from its serialized bytes
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Returns the serialized decryption key
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

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

    /// Constructs an ML-KEM encapsulation key from a byte slice.
    ///
    /// This is the checked slice-based counterpart to [`Self::from_bytes`].
    /// It checks only that `bytes.len() == N`; it does not perform semantic
    /// validation of the encoded K-PKE public key material.
    ///
    /// # Errors
    ///
    /// Returns [`MlKemError::InvalidLength`] if `bytes.len() != N`.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, MlKemError> {
        if bytes.len() != N {
            return Err(MlKemError::InvalidLength);
        }

        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(Self::from_bytes(out))
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

    /// Constructs an ML-KEM decapsulation key from a byte slice.
    ///
    /// This is the checked slice-based counterpart to [`Self::from_bytes`].
    /// It checks only that `bytes.len() == N`; it does not perform semantic
    /// validation of the encoded K-PKE public key material.
    ///
    /// # Errors
    ///
    /// Returns [`MlKemError::InvalidLength`] if `bytes.len() != N`.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, MlKemError> {
        if bytes.len() != N {
            return Err(MlKemError::InvalidLength);
        }

        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(Self::from_bytes(out))
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

    /// Constructs an ML-KEM ciphertext from a byte slice.
    ///
    /// This checks only the serialized length. ML-KEM decapsulation handles
    /// invalid ciphertext contents through implicit rejection rather than by
    /// returning a decoding error.
    ///
    /// # Errors
    ///
    /// Returns [`MlKemError::InvalidLength`] if `bytes.len() != N`.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, MlKemError> {
        if bytes.len() != N {
            return Err(MlKemError::InvalidLength);
        }

        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(Self::from_bytes(out))
    }
}

impl SharedSecret {
    /// Creates a shared secret from its bytes.
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; ML_KEM_SHARED_SECRET_BYTES]) -> Self {
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
