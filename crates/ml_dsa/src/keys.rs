//! ML-DSA serialized key and signature wrappers.
//!
//! This module defines fixed-size owned byte wrappers for ML-DSA public keys,
//! secret keys, keypairs, and signatures.
//!
//! These types store the standardized serialized representations. They do not
//! eagerly decode or validate the algebraic contents. Length checking happens
//! at construction boundaries such as [`SecretKey::try_from_slice`],
//! [`PublicKey::try_from_slice`], and [`Signature::try_from_slice`].
//!
//! Semantic validation is performed by the object decoders in
//! [`crate::encoding`] and by the signing and verification algorithms.


use crate::constants::{
    ML_DSA_44_SECRET_KEY_BYTES,
    ML_DSA_44_PUBLIC_KEY_BYTES,
    ML_DSA_44_SIGNATURE_BYTES,
    ML_DSA_65_SECRET_KEY_BYTES,
    ML_DSA_65_PUBLIC_KEY_BYTES,
    ML_DSA_65_SIGNATURE_BYTES,
    ML_DSA_87_SECRET_KEY_BYTES,
    ML_DSA_87_PUBLIC_KEY_BYTES,
    ML_DSA_87_SIGNATURE_BYTES,
};


use crate::error::MlDsaError;



// --------------------------------------------------------------------
// Defining generic structs for the different keys
// --------------------------------------------------------------------


/// Fixed-size serialized ML-DSA secret key.
///
/// This type owns the exact byte representation of a secret key for one
/// parameter set. It does not decode or validate the secret-key components.
///
/// This type intentionally does not implement `Debug`, because it contains
/// secret material.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey<const N: usize> {
    bytes: [u8; N],
}

/// Fixed-size ML-DSA keypair.
///
/// The keypair contains a serialized secret key and its corresponding
/// serialized public key.
///
/// This type intentionally does not implement `Debug`, because it contains a
/// secret key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey<const N: usize> {
    bytes: [u8; N],
}

/// ML-DSA Keypair
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsaKeypair<const SK_BYTES: usize, const PK_BYTES: usize> {
    sk: SecretKey<SK_BYTES>,
    pk: PublicKey<PK_BYTES>,
}

/// Fixed-size serialized ML-DSA signature.
///
/// This type owns the exact byte representation of a signature for one
/// parameter set. It does not decode or validate the signature contents.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature<const N: usize> {
    bytes: [u8; N],
}


impl<const N: usize> SecretKey<N> {
    /// Constructs a secret key from an owned byte array.
    ///
    /// This performs no semantic validation. The byte array length is enforced
    /// by the type parameter `N`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Constructs a secret key from a byte slice.
    ///
    /// This checks only that `bytes.len() == N`. It does not decode or
    /// semantically validate the secret-key contents.
    ///
    /// # Errors
    ///
    /// Returns [`MlDsaError::InvalidLength`] if `bytes.len() != N`.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, MlDsaError> {
        if bytes.len() != N {
            return Err(MlDsaError::InvalidLength);
        }

        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(Self::from_bytes(out))
    }

    /// Returns the serialized secret-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consumes the secret key and returns the serialized byte array.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; N] {
        self.bytes
    }
}


impl<const N: usize> PublicKey<N> {
    /// Constructs a public key from an owned byte array.
    ///
    /// This performs no semantic validation. The byte array length is enforced
    /// by the type parameter `N`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Constructs a public key from a byte slice.
    ///
    /// This checks only that `bytes.len() == N`. It does not decode or
    /// semantically validate the secret-key contents.
    ///
    /// # Errors
    ///
    /// Returns [`MlDsaError::InvalidLength`] if `bytes.len() != N`.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, MlDsaError> {
        if bytes.len() != N {
            return Err(MlDsaError::InvalidLength);
        }

        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(Self::from_bytes(out))
    }

    /// Returns the serialized public-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consumes the public key and returns the serialized byte array.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; N] {
        self.bytes
    }
}



impl<const SK_BYTES: usize, const PK_BYTES: usize> MlDsaKeypair<SK_BYTES, PK_BYTES> {
    /// Returns the secret key.
    #[must_use]
    pub const fn secret_key(&self) -> &SecretKey<SK_BYTES> {
        &self.sk
    }

    /// Returns the public key.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey<PK_BYTES> {
        &self.pk
    }

    /// Splits the keypair into its secret and public keys.
    #[must_use]
    pub const fn into_parts(self) -> (SecretKey<SK_BYTES>, PublicKey<PK_BYTES>) {
        (self.sk, self.pk)
    }

    /// Constructs a keypair from a secret key and a public key.
    pub(crate) const fn from_parts(
        sk: SecretKey<SK_BYTES>,
        pk: PublicKey<PK_BYTES>,
    ) -> Self {
        Self { pk, sk }
    }
}



impl<const N: usize> Signature<N> {
    /// Constructs a signature from an owned byte array.
    ///
    /// This performs no semantic validation. The byte array length is enforced
    /// by the type parameter `N`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Constructs a signature from a byte slice.
    ///
    /// This checks only that `bytes.len() == N`. It does not decode or
    /// semantically validate the secret-key contents.
    ///
    /// # Errors
    ///
    /// Returns [`MlDsaError::InvalidLength`] if `bytes.len() != N`.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, MlDsaError> {
        if bytes.len() != N {
            return Err(MlDsaError::InvalidLength);
        }

        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(Self::from_bytes(out))
    }

    /// Returns the serialized signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Consumes the signature and returns the serialized byte array.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; N] {
        self.bytes
    }
}



// --------------------------------------------------------------------
// Defining key types for each of the instantiations of ML-DSA
// --------------------------------------------------------------------


/// ML-DSA-44 secret key.
pub type MlDsa44SecretKey = SecretKey<ML_DSA_44_SECRET_KEY_BYTES>;

/// ML-DSA-44 public key.
pub type MlDsa44PublicKey = PublicKey<ML_DSA_44_PUBLIC_KEY_BYTES>;

/// ML-DSA-44 keypair.
pub type MlDsa44Keypair = MlDsaKeypair<ML_DSA_44_SECRET_KEY_BYTES, ML_DSA_44_PUBLIC_KEY_BYTES>;

/// ML-DSA-44 signature.
pub type MlDsa44Signature = Signature<ML_DSA_44_SIGNATURE_BYTES>;


/// ML-DSA-65 secret key.
pub type MlDsa65SecretKey = SecretKey<ML_DSA_65_SECRET_KEY_BYTES>;

/// ML-DSA-65 public key.
pub type MlDsa65PublicKey = PublicKey<ML_DSA_65_PUBLIC_KEY_BYTES>;

/// ML-DSA-65 keypair.
pub type MlDsa65Keypair = MlDsaKeypair<ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_PUBLIC_KEY_BYTES>;

/// ML-DSA-65 signature.
pub type MlDsa65Signature = Signature<ML_DSA_65_SIGNATURE_BYTES>;


/// ML-DSA-87 secret key.
pub type MlDsa87SecretKey = SecretKey<ML_DSA_87_SECRET_KEY_BYTES>;

/// ML-DSA-87 public key.
pub type MlDsa87PublicKey = PublicKey<ML_DSA_87_PUBLIC_KEY_BYTES>;

/// ML-DSA-87 keypair.
pub type MlDsa87Keypair = MlDsaKeypair<ML_DSA_87_SECRET_KEY_BYTES, ML_DSA_87_PUBLIC_KEY_BYTES>;

/// ML-DSA-87 signature.
pub type MlDsa87Signature = Signature<ML_DSA_87_SIGNATURE_BYTES>;

