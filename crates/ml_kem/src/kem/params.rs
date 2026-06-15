use crate::keys::{
    MlKem512Ciphertext, MlKem512DecapsulationKey, MlKem512EncapsulationKey, MlKem512Keypair,
    MlKem768Ciphertext, MlKem768DecapsulationKey, MlKem768EncapsulationKey, MlKem768Keypair,
    MlKem1024Ciphertext, MlKem1024DecapsulationKey, MlKem1024EncapsulationKey, MlKem1024Keypair,
    SharedSecret,
};

use crate::constants::{
    KPKE_512_DECRYPT_KEY_BYTES, KPKE_512_ENCRYPT_KEY_BYTES, KPKE_768_DECRYPT_KEY_BYTES,
    KPKE_768_ENCRYPT_KEY_BYTES, KPKE_1024_DECRYPT_KEY_BYTES, KPKE_1024_ENCRYPT_KEY_BYTES,
    ML_KEM_512_CIPHERTEXT_BYTES, ML_KEM_512_DECAPS_KEY_BYTES, ML_KEM_512_DU, ML_KEM_512_DV,
    ML_KEM_512_ENCAPS_KEY_BYTES, ML_KEM_512_ETA1, ML_KEM_512_ETA2, ML_KEM_512_K,
    ML_KEM_768_CIPHERTEXT_BYTES, ML_KEM_768_DECAPS_KEY_BYTES, ML_KEM_768_DU, ML_KEM_768_DV,
    ML_KEM_768_ENCAPS_KEY_BYTES, ML_KEM_768_ETA1, ML_KEM_768_ETA2, ML_KEM_768_K,
    ML_KEM_1024_CIPHERTEXT_BYTES, ML_KEM_1024_DECAPS_KEY_BYTES, ML_KEM_1024_DU, ML_KEM_1024_DV,
    ML_KEM_1024_ENCAPS_KEY_BYTES, ML_KEM_1024_ETA1, ML_KEM_1024_ETA2, ML_KEM_1024_K, MlKem512,
    MlKem768, MlKem1024,
};

use super::internal::{ml_kem_decaps_internal, ml_kem_encaps_internal, ml_kem_keygen_internal};

/// Public ML-KEM parameter-set trait.
///
/// This trait provides a stable, concise API over the three ML-KEM parameter
/// sets without relying on associated constants in const-generic type
/// positions in public generic function signatures.
pub trait MlKemParams: Sized {
    /// Module rank `k`.
    const K: usize;

    /// Noise parameter used for secret-vector sampling.
    const ETA1: usize;

    /// Noise parameter used for encryption error sampling.
    const ETA2: usize;

    /// Compression width for the first ciphertext component.
    const DU: usize;

    /// Compression width for the second ciphertext component.
    const DV: usize;

    /// Serialized encapsulation-key length in bytes.
    const ENCAPS_KEY_BYTES: usize;

    /// Serialized decapsulation-key length in bytes.
    const DECAPS_KEY_BYTES: usize;

    /// Serialized ciphertext length in bytes.
    const CIPHERTEXT_BYTES: usize;

    /// Serialized K-PKE encryption-key length in bytes.
    const EK_PKE_BYTES: usize;

    /// Serialized K-PKE decryption-key length in bytes.
    const DK_PKE_BYTES: usize;

    /// Encapsulation-key type for this parameter set.
    type EncapsulationKey;

    /// Decapsulation-key type for this parameter set.
    type DecapsulationKey;

    /// Ciphertext type for this parameter set.
    type Ciphertext;

    /// Keypair type for this parameter set.
    type Keypair;

    /// Deterministically generates a keypair from the two 32-byte ML-KEM
    /// key-generation seeds.
    fn keygen_from_seed(d: &[u8; 32], z: &[u8; 32]) -> Self::Keypair;

    /// Deterministically encapsulates using a caller-provided 32-byte
    /// encapsulation seed.
    fn encaps_from_seed(
        ek: &Self::EncapsulationKey,
        m: &[u8; 32],
    ) -> (SharedSecret, Self::Ciphertext);

    /// Decapsulates a ciphertext using this parameter set.
    fn decaps(dk: &Self::DecapsulationKey, ciphertext: &Self::Ciphertext) -> SharedSecret;
}

impl MlKemParams for MlKem512 {
    const K: usize = ML_KEM_512_K;
    const ETA1: usize = ML_KEM_512_ETA1;
    const ETA2: usize = ML_KEM_512_ETA2;
    const DU: usize = ML_KEM_512_DU;
    const DV: usize = ML_KEM_512_DV;

    const ENCAPS_KEY_BYTES: usize = ML_KEM_512_ENCAPS_KEY_BYTES;
    const DECAPS_KEY_BYTES: usize = ML_KEM_512_DECAPS_KEY_BYTES;
    const CIPHERTEXT_BYTES: usize = ML_KEM_512_CIPHERTEXT_BYTES;
    const EK_PKE_BYTES: usize = KPKE_512_ENCRYPT_KEY_BYTES;
    const DK_PKE_BYTES: usize = KPKE_512_DECRYPT_KEY_BYTES;

    type EncapsulationKey = MlKem512EncapsulationKey;
    type DecapsulationKey = MlKem512DecapsulationKey;
    type Ciphertext = MlKem512Ciphertext;
    type Keypair = MlKem512Keypair;

    fn keygen_from_seed(d: &[u8; 32], z: &[u8; 32]) -> Self::Keypair {
        ml_kem_keygen_internal::<
            ML_KEM_512_K,
            ML_KEM_512_ENCAPS_KEY_BYTES,
            KPKE_512_ENCRYPT_KEY_BYTES,
            ML_KEM_512_DECAPS_KEY_BYTES,
            KPKE_512_DECRYPT_KEY_BYTES,
            ML_KEM_512_ETA1,
        >(d, z)
    }

    fn encaps_from_seed(
        ek: &Self::EncapsulationKey,
        m: &[u8; 32],
    ) -> (SharedSecret, Self::Ciphertext) {
        ml_kem_encaps_internal::<
            ML_KEM_512_K,
            ML_KEM_512_ENCAPS_KEY_BYTES,
            ML_KEM_512_CIPHERTEXT_BYTES,
            ML_KEM_512_ETA1,
            ML_KEM_512_ETA2,
            ML_KEM_512_DU,
            ML_KEM_512_DV,
        >(ek, m)
    }

    fn decaps(dk: &Self::DecapsulationKey, ciphertext: &Self::Ciphertext) -> SharedSecret {
        ml_kem_decaps_internal::<
            ML_KEM_512_K,
            ML_KEM_512_DECAPS_KEY_BYTES,
            KPKE_512_ENCRYPT_KEY_BYTES,
            KPKE_512_DECRYPT_KEY_BYTES,
            ML_KEM_512_CIPHERTEXT_BYTES,
            ML_KEM_512_ETA1,
            ML_KEM_512_ETA2,
            ML_KEM_512_DU,
            ML_KEM_512_DV,
        >(dk, ciphertext)
    }
}

impl MlKemParams for MlKem768 {
    const K: usize = ML_KEM_768_K;
    const ETA1: usize = ML_KEM_768_ETA1;
    const ETA2: usize = ML_KEM_768_ETA2;
    const DU: usize = ML_KEM_768_DU;
    const DV: usize = ML_KEM_768_DV;

    const ENCAPS_KEY_BYTES: usize = ML_KEM_768_ENCAPS_KEY_BYTES;
    const DECAPS_KEY_BYTES: usize = ML_KEM_768_DECAPS_KEY_BYTES;
    const CIPHERTEXT_BYTES: usize = ML_KEM_768_CIPHERTEXT_BYTES;
    const EK_PKE_BYTES: usize = KPKE_768_ENCRYPT_KEY_BYTES;
    const DK_PKE_BYTES: usize = KPKE_768_DECRYPT_KEY_BYTES;

    type EncapsulationKey = MlKem768EncapsulationKey;
    type DecapsulationKey = MlKem768DecapsulationKey;
    type Ciphertext = MlKem768Ciphertext;
    type Keypair = MlKem768Keypair;

    fn keygen_from_seed(d: &[u8; 32], z: &[u8; 32]) -> Self::Keypair {
        ml_kem_keygen_internal::<
            ML_KEM_768_K,
            ML_KEM_768_ENCAPS_KEY_BYTES,
            KPKE_768_ENCRYPT_KEY_BYTES,
            ML_KEM_768_DECAPS_KEY_BYTES,
            KPKE_768_DECRYPT_KEY_BYTES,
            ML_KEM_768_ETA1,
        >(d, z)
    }

    fn encaps_from_seed(
        ek: &Self::EncapsulationKey,
        m: &[u8; 32],
    ) -> (SharedSecret, Self::Ciphertext) {
        ml_kem_encaps_internal::<
            ML_KEM_768_K,
            ML_KEM_768_ENCAPS_KEY_BYTES,
            ML_KEM_768_CIPHERTEXT_BYTES,
            ML_KEM_768_ETA1,
            ML_KEM_768_ETA2,
            ML_KEM_768_DU,
            ML_KEM_768_DV,
        >(ek, m)
    }

    fn decaps(dk: &Self::DecapsulationKey, ciphertext: &Self::Ciphertext) -> SharedSecret {
        ml_kem_decaps_internal::<
            ML_KEM_768_K,
            ML_KEM_768_DECAPS_KEY_BYTES,
            KPKE_768_ENCRYPT_KEY_BYTES,
            KPKE_768_DECRYPT_KEY_BYTES,
            ML_KEM_768_CIPHERTEXT_BYTES,
            ML_KEM_768_ETA1,
            ML_KEM_768_ETA2,
            ML_KEM_768_DU,
            ML_KEM_768_DV,
        >(dk, ciphertext)
    }
}

impl MlKemParams for MlKem1024 {
    const K: usize = ML_KEM_1024_K;
    const ETA1: usize = ML_KEM_1024_ETA1;
    const ETA2: usize = ML_KEM_1024_ETA2;
    const DU: usize = ML_KEM_1024_DU;
    const DV: usize = ML_KEM_1024_DV;

    const ENCAPS_KEY_BYTES: usize = ML_KEM_1024_ENCAPS_KEY_BYTES;
    const DECAPS_KEY_BYTES: usize = ML_KEM_1024_DECAPS_KEY_BYTES;
    const CIPHERTEXT_BYTES: usize = ML_KEM_1024_CIPHERTEXT_BYTES;
    const EK_PKE_BYTES: usize = KPKE_1024_ENCRYPT_KEY_BYTES;
    const DK_PKE_BYTES: usize = KPKE_1024_DECRYPT_KEY_BYTES;

    type EncapsulationKey = MlKem1024EncapsulationKey;
    type DecapsulationKey = MlKem1024DecapsulationKey;
    type Ciphertext = MlKem1024Ciphertext;
    type Keypair = MlKem1024Keypair;

    fn keygen_from_seed(d: &[u8; 32], z: &[u8; 32]) -> Self::Keypair {
        ml_kem_keygen_internal::<
            ML_KEM_1024_K,
            ML_KEM_1024_ENCAPS_KEY_BYTES,
            KPKE_1024_ENCRYPT_KEY_BYTES,
            ML_KEM_1024_DECAPS_KEY_BYTES,
            KPKE_1024_DECRYPT_KEY_BYTES,
            ML_KEM_1024_ETA1,
        >(d, z)
    }

    fn encaps_from_seed(
        ek: &Self::EncapsulationKey,
        m: &[u8; 32],
    ) -> (SharedSecret, Self::Ciphertext) {
        ml_kem_encaps_internal::<
            ML_KEM_1024_K,
            ML_KEM_1024_ENCAPS_KEY_BYTES,
            ML_KEM_1024_CIPHERTEXT_BYTES,
            ML_KEM_1024_ETA1,
            ML_KEM_1024_ETA2,
            ML_KEM_1024_DU,
            ML_KEM_1024_DV,
        >(ek, m)
    }

    fn decaps(dk: &Self::DecapsulationKey, ciphertext: &Self::Ciphertext) -> SharedSecret {
        ml_kem_decaps_internal::<
            ML_KEM_1024_K,
            ML_KEM_1024_DECAPS_KEY_BYTES,
            KPKE_1024_ENCRYPT_KEY_BYTES,
            KPKE_1024_DECRYPT_KEY_BYTES,
            ML_KEM_1024_CIPHERTEXT_BYTES,
            ML_KEM_1024_ETA1,
            ML_KEM_1024_ETA2,
            ML_KEM_1024_DU,
            ML_KEM_1024_DV,
        >(dk, ciphertext)
    }
}
