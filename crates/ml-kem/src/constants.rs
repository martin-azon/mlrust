//! ML-KEM parameter sets.
//!
//! This module defines the public parameter sets standardized for ML-KEM:
//!
//! - [`MlKem512`];
//! - [`MlKem768`];
//! - [`MlKem1024`].



/// Length in bytes of an ML-KEM shared secret.
pub const ML_KEM_SHARED_SECRET_BYTES: usize = 32;

/// Length in bytes of an ML-KEM-512 encapsulation key.
pub const ML_KEM_512_ENCAPS_KEY_BYTES: usize = 800;
/// Length in bytes of an ML-KEM-512 decapsulation key.
pub const ML_KEM_512_DECAPS_KEY_BYTES: usize = 1632;
/// Length in bytes of an ML-KEM-512 ciphertext.
pub const ML_KEM_512_CIPHERTEXT_BYTES: usize = 768;

/// Parameter K for ML-KEM-512.
pub const ML_KEM_512_K: usize = 2;
/// Parameter ETA_1 for ML-KEM-512.
pub const ML_KEM_512_ETA1: usize = 3;
/// Parameter ETA_2 for ML-KEM-512.
pub const ML_KEM_512_ETA2: usize = 2;
/// Parameter DU for ML-KEM-512.
pub const ML_KEM_512_DU: usize = 10;
/// Parameter DV for ML-KEM-512.
pub const ML_KEM_512_DV: usize = 4;

/// Length in bytes of a K-PKE-512 encryption key.
pub const KPKE_512_ENCRYPT_KEY_BYTES: usize = 800;
/// Length in bytes of a K-PKE-512 decryption key.
pub const KPKE_512_DECRYPT_KEY_BYTES: usize = 768;



/// Length in bytes of an ML-KEM-768 encapsulation key.
pub const ML_KEM_768_ENCAPS_KEY_BYTES: usize = 1184;
/// Length in bytes of an ML-KEM-768 decapsulation key.
pub const ML_KEM_768_DECAPS_KEY_BYTES: usize = 2400;
/// Length in bytes of an ML-KEM-768 ciphertext.
pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;

/// Parameter K for ML-KEM-768.
pub const ML_KEM_768_K: usize = 3;
/// Parameter ETA_1 for ML-KEM-768.
pub const ML_KEM_768_ETA1: usize = 2;
/// Parameter ETA_2 for ML-KEM-768.
pub const ML_KEM_768_ETA2: usize = 2;
/// Parameter DU for ML-KEM-768.
pub const ML_KEM_768_DU: usize = 10;
/// Parameter DV for ML-KEM-768.
pub const ML_KEM_768_DV: usize = 4;

/// Length in bytes of a K-PKE-768 encryption key.
pub const KPKE_768_ENCRYPT_KEY_BYTES: usize = 1184;
/// Length in bytes of a K-PKE-768 decryption key.
pub const KPKE_768_DECRYPT_KEY_BYTES: usize = 1152;



/// Length in bytes of an ML-KEM-1024 encapsulation key.
pub const ML_KEM_1024_ENCAPS_KEY_BYTES: usize = 1568;
/// Length in bytes of an ML-KEM-1024 decapsulation key.
pub const ML_KEM_1024_DECAPS_KEY_BYTES: usize = 3168;
/// Length in bytes of an ML-KEM-1024 ciphertext.
pub const ML_KEM_1024_CIPHERTEXT_BYTES: usize = 1568;

/// Parameter K for ML-KEM-1024.
pub const ML_KEM_1024_K: usize = 4;
/// Parameter ETA_1 for ML-KEM-1024.
pub const ML_KEM_1024_ETA1: usize = 2;
/// Parameter ETA_2 for ML-KEM-1024.
pub const ML_KEM_1024_ETA2: usize = 2;
/// Parameter DU for ML-KEM-1024.
pub const ML_KEM_1024_DU: usize = 11;
/// Parameter DV for ML-KEM-1024.
pub const ML_KEM_1024_DV: usize = 5;

/// Length in bytes of a K-PKE-1024 encryption key.
pub const KPKE_1024_ENCRYPT_KEY_BYTES: usize = 1568;
/// Length in bytes of a K-PKE-1024 decryption key.
pub const KPKE_1024_DECRYPT_KEY_BYTES: usize = 1536;



/// Marker type for ML-KEM-512.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKem512 {}

/// Marker type for ML-KEM-768.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKem768 {}

/// Marker type for ML-KEM-1024.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKem1024 {}