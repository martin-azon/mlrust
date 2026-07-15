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
    ml_kem_keygen512, ml_kem_encaps512, ml_kem_decaps512,
    ml_kem_keygen768, ml_kem_encaps768, ml_kem_decaps768,
    ml_kem_keygen1024, ml_kem_encaps1024, ml_kem_decaps1024,
};
