//! ML-DSA object encoding and decoding.
//!
//! This module contains object-level encoders and decoders for ML-DSA public
//! keys, secret keys, signatures, and the `w1` challenge-hash representation.
//!
//! Low-level coefficient and hint packing routines live in `mlrust_core`.
//! This module is responsible for assembling those primitive encodings into
//! complete ML-DSA byte strings.
//!
//! These functions are internal to the ML-DSA crate. Public wrappers should
//! expose typed [`crate::keys::PublicKey`], [`crate::keys::SecretKey`], and
//! [`crate::keys::Signature`] values rather than decoded algebraic structures.


pub(crate) mod keys;
pub(crate) mod signatures;
pub(crate) mod w1;

pub(crate) use keys::{
    pk_decode,
    pk_encode,
    sk_decode,
    sk_encode,
    DecodedPublicKey,
    DecodedSecretKey,
};

pub(crate) use signatures::{
    sig_decode,
    sig_encode,
    DecodedSignature,
};

pub(crate) use w1::w1_encode;