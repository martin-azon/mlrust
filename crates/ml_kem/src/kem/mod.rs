//! ML-KEM key generation, encapsulation, and decapsulation.

pub(crate) mod api;
pub(crate) mod internal;
pub(crate) mod params;

#[cfg(test)]
mod tests;

pub use params::MlKemParams;

pub use api::{
    ml_kem_keygen_with_rbg,
    ml_kem_encaps_with_rbg,
    ml_kem_decaps,
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
pub use api::{
    ml_kem_keygen,
    ml_kem_encaps,
    ml_kem512_keygen,
    ml_kem512_encaps,
    ml_kem768_keygen,
    ml_kem768_encaps,
    ml_kem1024_keygen,
    ml_kem1024_encaps,
};
