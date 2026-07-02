//! ML-DSA serialized keys.


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
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey<const N: usize> {
    bytes: [u8; N],
}

/// Fixed-size serialized ML-DSA public key.
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
#[derive(Clone, PartialEq, Eq)]
pub struct Signature<const N: usize> {
    bytes: [u8; N],
}


impl<const N: usize> SecretKey<N> {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, MlDsaError> {
        if bytes.len() != N {
            return Err(MlDsaError::InvalidLength);
        }

        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(Self::from_bytes(out))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; N] {
        self.bytes
    }
}


impl<const N: usize> PublicKey<N> {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, MlDsaError> {
        if bytes.len() != N {
            return Err(MlDsaError::InvalidLength);
        }

        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(Self::from_bytes(out))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

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
    
    /// Splits the keypair into its public and private keys.
    #[must_use]
    pub const fn into_parts(self) -> (SecretKey<SK_BYTES>, PublicKey<PK_BYTES>) {
        (self.sk, self.pk)
    }

    /// Constructs a keypair from an encapsulation key and a decapsulation key.
    pub(crate) const fn from_parts(
        pk: PublicKey<PK_BYTES>,
        sk: SecretKey<SK_BYTES>,
    ) -> Self {
        Self { pk, sk }
    }
}



impl<const N: usize> Signature<N> {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, MlDsaError> {
        if bytes.len() != N {
            return Err(MlDsaError::InvalidLength);
        }

        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(Self::from_bytes(out))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

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

/// ML-DSA-44 ciphertext.
pub type MlDsa44Signature = Signature<ML_DSA_44_SIGNATURE_BYTES>;


/// ML-DSA-65 secret key.
pub type MlDsa65SecretKey = SecretKey<ML_DSA_65_SECRET_KEY_BYTES>;

/// ML-DSA-65 public key.
pub type MlDsa65PublicKey = PublicKey<ML_DSA_65_PUBLIC_KEY_BYTES>;

/// ML-DSA-65 keypair.
pub type MlDsa65Keypair = MlDsaKeypair<ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_PUBLIC_KEY_BYTES>;

/// ML-DSA-65 ciphertext.
pub type MlDsa65Signature = Signature<ML_DSA_65_SIGNATURE_BYTES>;


/// ML-DSA-87 secret key.
pub type MlDsa87SecretKey = SecretKey<ML_DSA_87_SECRET_KEY_BYTES>;

/// ML-DSA-87 public key.
pub type MlDsa87PublicKey = PublicKey<ML_DSA_87_PUBLIC_KEY_BYTES>;

/// ML-DSA-87 keypair.
pub type MlDsa87Keypair = MlDsaKeypair<ML_DSA_87_SECRET_KEY_BYTES, ML_DSA_87_PUBLIC_KEY_BYTES>;

/// ML-DSA-87 ciphertext.
pub type MlDsa87Signature = Signature<ML_DSA_87_SIGNATURE_BYTES>;

