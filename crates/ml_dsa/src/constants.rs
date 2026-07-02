//! ML-DSA parameter sets.
//!
//! This module defines the public parameter sets standardized for ML-DSA:
//!
//! - [`MlDsa44`];
//! - [`MlDsa65`];
//! - [`MlDsa87`].



/// Marker type for ML-DSA-44.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsa44 {}

/// Marker type for ML-DSA-65.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsa65 {}

/// Marker type for ML-DSA-87.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsa87 {}


/// Bitlen of the Q - 1, where Q is the modulus Q = 8384017.
pub const BITLEN_Q_MINUS_ONE: usize = 23;
/// Bitlen(Q - 1) - D, where Q is the modulus Q = 8384017 and D = 13.
pub const BITLEN_Q_MINUS_ONE_MINUS_D: usize = 10;


/// Length in bytes of an ML-DSA-44 secret key.
pub const ML_DSA_44_SECRET_KEY_BYTES: usize = 2560;

/// Length in bytes of an ML-DSA-44 public key.
pub const ML_DSA_44_PUBLIC_KEY_BYTES: usize = 1312;

/// Length in bytes of an ML-DSA-44 signature.
pub const ML_DSA_44_SIGNATURE_BYTES: usize = 2420;


/// Length in bytes of an ML-DSA-65 secret key.
pub const ML_DSA_65_SECRET_KEY_BYTES: usize = 4032;

/// Length in bytes of an ML-DSA-65 public key.
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;

/// Length in bytes of an ML-DSA-65 signature.
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;


/// Length in bytes of an ML-DSA-87 secret key.
pub const ML_DSA_87_SECRET_KEY_BYTES: usize = 4896;

/// Length in bytes of an ML-DSA-87 public key.
pub const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2592;

/// Length in bytes of an ML-DSA-87 signature.
pub const ML_DSA_87_SIGNATURE_BYTES: usize = 4627;


/// Number of rows of matrix A in ML-DSA-44
pub const ML_DSA_44_K: usize = 4;
/// Number of columns of matrix A in ML-DSA-44
pub const ML_DSA_44_L: usize = 4;
/// Parameter ETA for ML-DSA-44
pub const ML_DSA_44_ETA: usize = 2;
/// Parameter TAU for ML-DSA-44
pub const ML_DSA_44_TAU: usize = 39;
/// Parameter BETA for ML-DSA-44
pub const ML_DSA_44_BETA: i32 = 78;
/// Parameter GAMMA1 for ML-DSA-44
pub const ML_DSA_44_GAMMA1: i32 = 1 << 17;
/// Parameter GAMMA2 for ML-DSA-44  (this corresponds to (Q - 1)/88 )
pub const ML_DSA_44_GAMMA2: i32 = 95232;
/// Parameter OMEGA for ML-DSA-44
pub const ML_DSA_44_OMEGA: usize = 80;


/// Number of rows of matrix A in ML-DSA-65
pub const ML_DSA_65_K: usize = 6;
/// Number of columns of matrix A in ML-DSA-65
pub const ML_DSA_65_L: usize = 5;
/// Parameter ETA for ML-DSA-65
pub const ML_DSA_65_ETA: usize = 4;
/// Parameter TAU for ML-DSA-65
pub const ML_DSA_65_TAU: usize = 49;
/// Parameter BETA for ML-DSA-65
pub const ML_DSA_65_BETA: i32 = 196;
/// Parameter GAMMA1 for ML-DSA-65
pub const ML_DSA_65_GAMMA1: i32 = 1 << 19;
/// Parameter GAMMA2 for ML-DSA-65  (this corresponds to (Q - 1)/32 )
pub const ML_DSA_65_GAMMA2: i32 = 261888;
/// Parameter OMEGA for ML-DSA-65
pub const ML_DSA_65_OMEGA: usize = 55;


/// Number of rows of matrix A in ML-DSA-87
pub const ML_DSA_87_K: usize = 8;
/// Number of columns of matrix A in ML-DSA-87
pub const ML_DSA_87_L: usize = 7;
/// Parameter ETA for ML-DSA-87
pub const ML_DSA_87_ETA: usize = 2;
/// Parameter TAU for ML-DSA-87
pub const ML_DSA_87_TAU: usize = 60;
/// Parameter BETA for ML-DSA-87
pub const ML_DSA_87_BETA: i32 = 120;
/// Parameter GAMMA1 for ML-DSA-87
pub const ML_DSA_87_GAMMA1: i32 = 1 << 19;
/// Parameter GAMMA2 for ML-DSA-87  (this corresponds to (Q - 1)/32 )
pub const ML_DSA_87_GAMMA2: i32 = 261888;
/// Parameter OMEGA for ML-DSA-87
pub const ML_DSA_87_OMEGA: usize = 75;