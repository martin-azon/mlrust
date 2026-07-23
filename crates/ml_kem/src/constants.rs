//! ML-KEM parameter sets.
//!
//! This module defines the public parameter sets standardized for ML-KEM:
//!
//! - [`MlKem512`];
//! - [`MlKem768`];
//! - [`MlKem1024`].

/// Marker type for ML-KEM-512.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKem512 {}

/// Marker type for ML-KEM-768.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKem768 {}

/// Marker type for ML-KEM-1024.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKem1024 {}

/// Parameter K for ML-KEM-512.
pub(crate) const ML_KEM_512_K: usize = 2;

/// Parameter ETA_1 for ML-KEM-512.
pub(crate) const ML_KEM_512_ETA1: usize = 3;

/// Parameter ETA_2 for ML-KEM-512.
pub(crate) const ML_KEM_512_ETA2: usize = 2;

/// Parameter DU for ML-KEM-512.
pub(crate) const ML_KEM_512_DU: usize = 10;

/// Parameter DV for ML-KEM-512.
pub(crate) const ML_KEM_512_DV: usize = 4;

/// Parameter K for ML-KEM-768.
pub(crate) const ML_KEM_768_K: usize = 3;

/// Parameter ETA_1 for ML-KEM-768.
pub(crate) const ML_KEM_768_ETA1: usize = 2;

/// Parameter ETA_2 for ML-KEM-768.
pub(crate) const ML_KEM_768_ETA2: usize = 2;

/// Parameter DU for ML-KEM-768.
pub(crate) const ML_KEM_768_DU: usize = 10;

/// Parameter DV for ML-KEM-768.
pub(crate) const ML_KEM_768_DV: usize = 4;

/// Parameter K for ML-KEM-1024.
pub(crate) const ML_KEM_1024_K: usize = 4;

/// Parameter ETA_1 for ML-KEM-1024.
pub(crate) const ML_KEM_1024_ETA1: usize = 2;

/// Parameter ETA_2 for ML-KEM-1024.
pub(crate) const ML_KEM_1024_ETA2: usize = 2;

/// Parameter DU for ML-KEM-1024.
pub(crate) const ML_KEM_1024_DU: usize = 11;

/// Parameter DV for ML-KEM-1024.
pub(crate) const ML_KEM_1024_DV: usize = 5;

/// Length in bytes of an ML-KEM shared secret.
pub const ML_KEM_SHARED_SECRET_BYTES: usize = 32;

/// Length in bytes of an ML-KEM-512 encapsulation key.
pub const ML_KEM_512_ENCAPS_KEY_BYTES: usize = 800;

/// Length in bytes of an ML-KEM-512 decapsulation key.
pub const ML_KEM_512_DECAPS_KEY_BYTES: usize = 1632;

/// Length in bytes of an ML-KEM-512 ciphertext.
pub const ML_KEM_512_CIPHERTEXT_BYTES: usize = 768;

/// Length in bytes of a K-PKE-512 encryption key.
pub(crate) const KPKE_512_ENCRYPT_KEY_BYTES: usize = 800;

/// Length in bytes of a K-PKE-512 decryption key.
pub(crate) const KPKE_512_DECRYPT_KEY_BYTES: usize = 768;

/// Length in bytes of an ML-KEM-768 encapsulation key.
pub const ML_KEM_768_ENCAPS_KEY_BYTES: usize = 1184;

/// Length in bytes of an ML-KEM-768 decapsulation key.
pub const ML_KEM_768_DECAPS_KEY_BYTES: usize = 2400;

/// Length in bytes of an ML-KEM-768 ciphertext.
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;

/// Length in bytes of a K-PKE-768 encryption key.
pub(crate) const KPKE_768_ENCRYPT_KEY_BYTES: usize = 1184;

/// Length in bytes of a K-PKE-768 decryption key.
pub(crate) const KPKE_768_DECRYPT_KEY_BYTES: usize = 1152;

/// Length in bytes of an ML-KEM-1024 encapsulation key.
pub const ML_KEM_1024_ENCAPS_KEY_BYTES: usize = 1568;

/// Length in bytes of an ML-KEM-1024 decapsulation key.
pub const ML_KEM_1024_DECAPS_KEY_BYTES: usize = 3168;

/// Length in bytes of an ML-KEM-1024 ciphertext.
pub const ML_KEM_1024_CIPHERTEXT_BYTES: usize = 1568;

/// Length in bytes of a K-PKE-1024 encryption key.
pub(crate) const KPKE_1024_ENCRYPT_KEY_BYTES: usize = 1568;

/// Length in bytes of a K-PKE-1024 decryption key.
pub(crate) const KPKE_1024_DECRYPT_KEY_BYTES: usize = 1536;

#[cfg(test)]
mod tests {
    use super::*;

    const N: usize = 256;
    const SEED_BYTES: usize = 32;

    const fn poly_compressed_bytes(bits_per_coeff: usize) -> usize {
        N * bits_per_coeff / 8
    }

    const fn polyvec_compressed_bytes(k: usize, bits_per_coeff: usize) -> usize {
        k * poly_compressed_bytes(bits_per_coeff)
    }

    const fn kpke_encrypt_key_bytes(k: usize) -> usize {
        SEED_BYTES + polyvec_compressed_bytes(k, 12)
    }

    const fn kpke_decrypt_key_bytes(k: usize) -> usize {
        polyvec_compressed_bytes(k, 12)
    }

    const fn ciphertext_bytes(k: usize, du: usize, dv: usize) -> usize {
        polyvec_compressed_bytes(k, du) + poly_compressed_bytes(dv)
    }

    const fn ml_kem_decapsulation_key_bytes(
        encaps_key_bytes: usize,
        kpke_decrypt_key_bytes: usize,
    ) -> usize {
        kpke_decrypt_key_bytes
            + encaps_key_bytes
            + 32 // H(ek)
            + 32 // z
    }

    #[test]
    fn shared_secret_length_is_32_bytes() {
        assert_eq!(ML_KEM_SHARED_SECRET_BYTES, 32);
    }

    #[test]
    fn ml_kem512_parameters_match_standard_values() {
        assert_eq!(ML_KEM_512_K, 2);
        assert_eq!(ML_KEM_512_ETA1, 3);
        assert_eq!(ML_KEM_512_ETA2, 2);
        assert_eq!(ML_KEM_512_DU, 10);
        assert_eq!(ML_KEM_512_DV, 4);
    }

    #[test]
    fn ml_kem768_parameters_match_standard_values() {
        assert_eq!(ML_KEM_768_K, 3);
        assert_eq!(ML_KEM_768_ETA1, 2);
        assert_eq!(ML_KEM_768_ETA2, 2);
        assert_eq!(ML_KEM_768_DU, 10);
        assert_eq!(ML_KEM_768_DV, 4);
    }

    #[test]
    fn ml_kem1024_parameters_match_standard_values() {
        assert_eq!(ML_KEM_1024_K, 4);
        assert_eq!(ML_KEM_1024_ETA1, 2);
        assert_eq!(ML_KEM_1024_ETA2, 2);
        assert_eq!(ML_KEM_1024_DU, 11);
        assert_eq!(ML_KEM_1024_DV, 5);
    }

    #[test]
    fn kpke512_key_lengths_match_formulas() {
        assert_eq!(
            KPKE_512_ENCRYPT_KEY_BYTES,
            kpke_encrypt_key_bytes(ML_KEM_512_K)
        );
        assert_eq!(
            KPKE_512_DECRYPT_KEY_BYTES,
            kpke_decrypt_key_bytes(ML_KEM_512_K)
        );

        assert_eq!(KPKE_512_ENCRYPT_KEY_BYTES, 800);
        assert_eq!(KPKE_512_DECRYPT_KEY_BYTES, 768);
    }

    #[test]
    fn kpke768_key_lengths_match_formulas() {
        assert_eq!(
            KPKE_768_ENCRYPT_KEY_BYTES,
            kpke_encrypt_key_bytes(ML_KEM_768_K)
        );
        assert_eq!(
            KPKE_768_DECRYPT_KEY_BYTES,
            kpke_decrypt_key_bytes(ML_KEM_768_K)
        );

        assert_eq!(KPKE_768_ENCRYPT_KEY_BYTES, 1184);
        assert_eq!(KPKE_768_DECRYPT_KEY_BYTES, 1152);
    }

    #[test]
    fn kpke1024_key_lengths_match_formulas() {
        assert_eq!(
            KPKE_1024_ENCRYPT_KEY_BYTES,
            kpke_encrypt_key_bytes(ML_KEM_1024_K)
        );
        assert_eq!(
            KPKE_1024_DECRYPT_KEY_BYTES,
            kpke_decrypt_key_bytes(ML_KEM_1024_K)
        );

        assert_eq!(KPKE_1024_ENCRYPT_KEY_BYTES, 1568);
        assert_eq!(KPKE_1024_DECRYPT_KEY_BYTES, 1536);
    }

    #[test]
    fn ml_kem512_object_lengths_match_formulas() {
        assert_eq!(ML_KEM_512_ENCAPS_KEY_BYTES, KPKE_512_ENCRYPT_KEY_BYTES);
        assert_eq!(
            ML_KEM_512_CIPHERTEXT_BYTES,
            ciphertext_bytes(ML_KEM_512_K, ML_KEM_512_DU, ML_KEM_512_DV)
        );
        assert_eq!(
            ML_KEM_512_DECAPS_KEY_BYTES,
            ml_kem_decapsulation_key_bytes(ML_KEM_512_ENCAPS_KEY_BYTES, KPKE_512_DECRYPT_KEY_BYTES,)
        );

        assert_eq!(ML_KEM_512_ENCAPS_KEY_BYTES, 800);
        assert_eq!(ML_KEM_512_DECAPS_KEY_BYTES, 1632);
        assert_eq!(ML_KEM_512_CIPHERTEXT_BYTES, 768);
    }

    #[test]
    fn ml_kem768_object_lengths_match_formulas() {
        assert_eq!(ML_KEM_768_ENCAPS_KEY_BYTES, KPKE_768_ENCRYPT_KEY_BYTES);
        assert_eq!(
            ML_KEM_768_CIPHERTEXT_BYTES,
            ciphertext_bytes(ML_KEM_768_K, ML_KEM_768_DU, ML_KEM_768_DV)
        );
        assert_eq!(
            ML_KEM_768_DECAPS_KEY_BYTES,
            ml_kem_decapsulation_key_bytes(ML_KEM_768_ENCAPS_KEY_BYTES, KPKE_768_DECRYPT_KEY_BYTES,)
        );

        assert_eq!(ML_KEM_768_ENCAPS_KEY_BYTES, 1184);
        assert_eq!(ML_KEM_768_DECAPS_KEY_BYTES, 2400);
        assert_eq!(ML_KEM_768_CIPHERTEXT_BYTES, 1088);
    }

    #[test]
    fn ml_kem1024_object_lengths_match_formulas() {
        assert_eq!(ML_KEM_1024_ENCAPS_KEY_BYTES, KPKE_1024_ENCRYPT_KEY_BYTES);
        assert_eq!(
            ML_KEM_1024_CIPHERTEXT_BYTES,
            ciphertext_bytes(ML_KEM_1024_K, ML_KEM_1024_DU, ML_KEM_1024_DV)
        );
        assert_eq!(
            ML_KEM_1024_DECAPS_KEY_BYTES,
            ml_kem_decapsulation_key_bytes(
                ML_KEM_1024_ENCAPS_KEY_BYTES,
                KPKE_1024_DECRYPT_KEY_BYTES,
            )
        );

        assert_eq!(ML_KEM_1024_ENCAPS_KEY_BYTES, 1568);
        assert_eq!(ML_KEM_1024_DECAPS_KEY_BYTES, 3168);
        assert_eq!(ML_KEM_1024_CIPHERTEXT_BYTES, 1568);
    }

    #[test]
    fn ciphertext_lengths_decompose_into_u_and_v_parts() {
        assert_eq!(ML_KEM_512_CIPHERTEXT_BYTES, ML_KEM_512_K * 320 + 128);

        assert_eq!(ML_KEM_768_CIPHERTEXT_BYTES, ML_KEM_768_K * 320 + 128);

        assert_eq!(ML_KEM_1024_CIPHERTEXT_BYTES, ML_KEM_1024_K * 352 + 160);
    }

    #[test]
    fn decapsulation_key_lengths_decompose_into_expected_parts() {
        assert_eq!(
            ML_KEM_512_DECAPS_KEY_BYTES,
            KPKE_512_DECRYPT_KEY_BYTES + ML_KEM_512_ENCAPS_KEY_BYTES + 64
        );

        assert_eq!(
            ML_KEM_768_DECAPS_KEY_BYTES,
            KPKE_768_DECRYPT_KEY_BYTES + ML_KEM_768_ENCAPS_KEY_BYTES + 64
        );

        assert_eq!(
            ML_KEM_1024_DECAPS_KEY_BYTES,
            KPKE_1024_DECRYPT_KEY_BYTES + ML_KEM_1024_ENCAPS_KEY_BYTES + 64
        );
    }
}
