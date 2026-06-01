#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod params;

pub mod field;
pub mod ntt;
pub mod poly;
pub mod encode;
pub mod symmetric;
//pub mod sampling;
pub mod ct;

pub use error::PqcCoreError;
pub use params::{N, RingParams, NttParams};
//pub use poly::{Poly, PolyVec, Matrix};
