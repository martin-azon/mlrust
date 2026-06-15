// ml-kem/src/kem/mod.rs

//! ML-KEM key generation, encapsulation, and decapsulation.

mod internal;
mod params;
mod api;

#[cfg(test)]
mod tests;


pub use params::MlKemParams;

pub use api::{
    ml_kem_keygen,
    ml_kem_encaps,
    ml_kem_decaps,
    ml_kem_keygen512,
    ml_kem_encaps512,
    ml_kem_decaps512,
    ml_kem_keygen768,
    ml_kem_encaps768,
    ml_kem_decaps768,
    ml_kem_keygen1024,
    ml_kem_encaps1024,
    ml_kem_decaps1024,
};