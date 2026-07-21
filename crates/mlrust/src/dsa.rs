//! ML-DSA public API.
//!
//! This module re-exports the ML-DSA signing API from the
//! implementation crate.

pub use ml_dsa::{
    MlDsa44, MlDsa44Keypair, MlDsa44PublicKey, MlDsa44SecretKey, MlDsa44Signature, MlDsa65,
    MlDsa65Keypair, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, MlDsa87, MlDsa87Keypair,
    MlDsa87PublicKey, MlDsa87SecretKey, MlDsa87Signature, ml_dsa44_keygen_with_rbg,
    ml_dsa44_sign_with_rbg, ml_dsa44_verify, ml_dsa65_keygen_with_rbg, ml_dsa65_sign_with_rbg,
    ml_dsa65_verify, ml_dsa87_keygen_with_rbg, ml_dsa87_sign_with_rbg, ml_dsa87_verify,
};

#[cfg(feature = "getrandom")]
pub use ml_dsa::{
    ml_dsa44_keygen, ml_dsa44_sign, ml_dsa65_keygen, ml_dsa65_sign, ml_dsa87_keygen, ml_dsa87_sign,
};
