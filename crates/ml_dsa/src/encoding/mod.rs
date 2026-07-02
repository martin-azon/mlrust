//! ML-DSA object encoding and decoding.
//!
//! This module contains object-level encoders and decoders for ML-DSA public
//! keys, secret keys, signatures, and the `w1` challenge-hash representation.
//!
//! Low-level coefficient and hint packing routines live in `mlrust_core`.

pub(crate) mod keys;
pub(crate) mod signature;
pub(crate) mod w1;

pub(crate) use keys::{
    pk_decode,
    pk_encode,
    sk_decode,
    sk_encode,
    DecodedPublicKey,
    DecodedSecretKey,
};

pub(crate) use signature::{
    sig_decode,
    sig_encode,
    DecodedSignature,
};

pub(crate) use w1::w1_encode;