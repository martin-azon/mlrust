//! Constant-time utility functions.
//!
//! This module contains small wrappers for byte-slice and i32 equality, zero checks,
//! conditional selection, and conditional assignment. These helpers are used
//! to avoid secret-dependent branches in higher-level ML-KEM and ML-DSA code.

pub mod bytes;
pub mod i32;

pub use bytes::{ct_conditional_assign_bytes, ct_eq, ct_is_zero, ct_select_bytes};
