#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod params;

pub mod field;
pub mod ntt;
pub mod poly;