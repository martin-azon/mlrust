//! ML-KEM serialized object types.
//!
//! This module defines fixed-size wrappers for ML-KEM encapsulation keys,
//! decapsulation keys, ciphertexts, and shared secrets.
//! 
//! The generic wrappers enforce byte lengths at the type level. The public
//! aliases correspond to the final ML-KEM object sizes. The same wrappers may
//! also be reused internally for K-PKE objects, whose decapsulation-key lengths
//! are smaller than final ML-KEM decapsulation-key lengths.

use mlrust_core::params::Q3329;
use mlrust_core::poly::PolyVec;
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


/// ML-KEM Keypair.
#[derive(Clone, PartialEq, Eq)]
pub struct MlKemKeypair<const EK_BYTES: usize, const DK_BYTES: usize> {
    pub(crate) ek: EncapsulationKey<EK_BYTES>,
    pub(crate) dk: DecapsulationKey<DK_BYTES>,
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



impl<const EK_BYTES: usize, const DK_BYTES: usize> MlKemKeypair<EK_BYTES, DK_BYTES>
{
    #[must_use]
    pub const fn encapsulation_key(&self) -> &EncapsulationKey<EK_BYTES> {
        &self.ek
    }

    #[must_use]
    pub const fn decapsulation_key(&self) -> &DecapsulationKey<DK_BYTES> {
        &self.dk
    }

    #[must_use]
    pub const fn into_parts(
        self,
    ) -> (EncapsulationKey<EK_BYTES>, DecapsulationKey<DK_BYTES>) {
        (self.ek, self.dk)
    }

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

/// KPKE-512 encryption key.
pub(crate) type Kpke512EncryptionKey = KpkeEncryptionKey<800>;

/// KPKE-512 decryption key.
pub(crate) type Kpke512DecryptionKey = KpkeDecryptionKey<768>;

/// KPKE-768 encryption key.
pub(crate) type Kpke768EncryptionKey = KpkeEncryptionKey<1184>;

/// KPKE-768 decryption key.
pub(crate) type Kpke768DecryptionKey = KpkeDecryptionKey<1152>;

/// KPKE-1024 encryption key.
pub(crate) type Kpke1024EncryptionKey = KpkeEncryptionKey<1568>;

/// KPKE-1024 decryption key.
pub(crate) type Kpke1024DecryptionKey = KpkeDecryptionKey<1536>;

/// ML-KEM-512 encapsulation key.
pub type MlKem512EncapsulationKey =
    EncapsulationKey<ML_KEM_512_ENCAPS_KEY_BYTES>;

/// ML-KEM-512 decapsulation key.
pub type MlKem512DecapsulationKey =
    DecapsulationKey<ML_KEM_512_DECAPS_KEY_BYTES>;

/// ML-KEM-512 keypair.
pub type MlKem512Keypair =
MlKemKeypair<ML_KEM_512_ENCAPS_KEY_BYTES, ML_KEM_512_DECAPS_KEY_BYTES>;

/// ML-KEM-512 ciphertext.
pub type MlKem512Ciphertext =
    Ciphertext<ML_KEM_512_CIPHERTEXT_BYTES>;

/// ML-KEM-768 encapsulation key.
pub type MlKem768EncapsulationKey =
    EncapsulationKey<ML_KEM_768_ENCAPS_KEY_BYTES>;

/// ML-KEM-768 decapsulation key.
pub type MlKem768DecapsulationKey =
    DecapsulationKey<ML_KEM_768_DECAPS_KEY_BYTES>;

/// ML-KEM-768 keypair.
pub type MlKem768Keypair =
MlKemKeypair<ML_KEM_768_ENCAPS_KEY_BYTES, ML_KEM_768_DECAPS_KEY_BYTES>;

/// ML-KEM-768 ciphertext.
pub type MlKem768Ciphertext =
    Ciphertext<ML_KEM_768_CIPHERTEXT_BYTES>;

/// ML-KEM-1024 encapsulation key.
pub type MlKem1024EncapsulationKey =
    EncapsulationKey<ML_KEM_1024_ENCAPS_KEY_BYTES>;

/// ML-KEM-1024 decapsulation key.
pub type MlKem1024DecapsulationKey =
    DecapsulationKey<ML_KEM_1024_DECAPS_KEY_BYTES>;

/// ML-KEM-1024 keypair.
pub type MlKem1024Keypair =
MlKemKeypair<ML_KEM_1024_ENCAPS_KEY_BYTES, ML_KEM_1024_DECAPS_KEY_BYTES>;

/// ML-KEM-1024 ciphertext.
pub type MlKem1024Ciphertext =
    Ciphertext<ML_KEM_1024_CIPHERTEXT_BYTES>;



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

    /// Consumes the key and returns the serialized bytes
    #[must_use]
    pub(crate) const fn into_bytes(self) -> [u8; N] {
        self.bytes
    }
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

    /// Consumes the key and returns the serialized bytes
    #[must_use]
    pub(crate) const fn into_bytes(self) -> [u8; N] {
        self.bytes
    }
}



impl<const N: usize> EncapsulationKey<N> {
    /// Creates an encapsulation key from its serialized bytes
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Returns the serialized encapsulation key
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consumes the key and returns the serialized bytes
    #[must_use]
    pub(crate) const fn into_bytes(self) -> [u8; N] {
        self.bytes
    }
}



impl<const N: usize> DecapsulationKey<N> {
    /// Creates a decapsulation key from its serialized bytes.
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Returns the serialized decapsulation key.
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consumes the key and returns the serialized bytes.
    #[must_use]
    pub(crate) const fn into_bytes(self) -> [u8; N] {
        self.bytes
    }
}

impl<const N: usize> Ciphertext<N> {
    /// Creates a ciphertext from its serialized bytes.
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Returns the serialized ciphertext.
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consumes the ciphertext and returns the serialized bytes.
    #[must_use]
    pub(crate) const fn into_bytes(self) -> [u8; N] {
        self.bytes
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
    pub(crate) const fn as_bytes(&self) -> &[u8; ML_KEM_SHARED_SECRET_BYTES] {
        &self.bytes
    }

    /// Consumes the shared secret and returns the bytes.
    #[must_use]
    pub(crate) const fn into_bytes(self) -> [u8; ML_KEM_SHARED_SECRET_BYTES] {
        self.bytes
    }
}