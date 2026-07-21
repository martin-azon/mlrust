//! ML-KEM public API.
//!
//! This module re-exports the ML-KEM key encapsulation API from the
//! implementation crate.

pub use ml_kem::{
    MlKem512,
    MlKem512EncapsulationKey, MlKem512DecapsulationKey, MlKem512Ciphertext, MlKem512Keypair,
    MlKem768,
    MlKem768EncapsulationKey, MlKem768DecapsulationKey, MlKem768Ciphertext, MlKem768Keypair,
    MlKem1024,
    MlKem1024EncapsulationKey, MlKem1024DecapsulationKey, MlKem1024Ciphertext, MlKem1024Keypair,
    MlKemError,
    ml_kem512_keygen_with_rbg,
    ml_kem512_encaps_with_rbg,
    ml_kem512_decaps,
    ml_kem768_keygen_with_rbg,
    ml_kem768_encaps_with_rbg,
    ml_kem768_decaps,
    ml_kem1024_keygen_with_rbg,
    ml_kem1024_encaps_with_rbg,
    ml_kem1024_decaps,
};

#[cfg(feature = "getrandom")]
pub use ml_kem::{
    ml_kem512_keygen,
    ml_kem512_encaps,
    ml_kem768_keygen,
    ml_kem768_encaps,
    ml_kem1024_keygen,
    ml_kem1024_encaps,
};
