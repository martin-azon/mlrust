//! ML-DSA encoding and decoding primitives.
//!
//! This module contains the FIPS 204 coefficient, bit-packing, hint-packing,
//! and object-encoding routines used by ML-DSA.

pub mod coeff;
pub mod bitpack;
pub mod hint;



pub use coeff::{
    coeff_from_half_byte,
    coeff_from_three_bytes,
};

pub use bitpack::{
    bit_pack_signed_q8380417,
    bit_unpack_q8380417,
    simple_bit_pack_q8380417,
    simple_bit_unpack_q8380417,
};

pub use hint::{
    hint_bit_pack,
    hint_bit_unpack,
};