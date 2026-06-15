//! ML-KEM K-PKE algorithms.
//!
//! This module implements the deterministic public-key encryption component
//! used internally by ML-KEM.

pub(crate) mod internal;
mod kpke;

pub(crate) use kpke::{
    derive_k_pke_keygen_seeds,
    kpke_keygen,
    kpke_encrypt,
    kpke_decrypt,
    kpke_keygen512,
    kpke_keygen768,
    kpke_keygen1024,
    kpke_encrypt512,
    kpke_encrypt768,
    kpke_encrypt1024,
    kpke_decrypt512,
    kpke_decrypt768,
    kpke_decrypt1024,
};