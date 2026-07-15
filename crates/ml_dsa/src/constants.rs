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



/// Number of rows of matrix A in ML-DSA-44
pub const ML_DSA_44_K: usize = 4;

/// Number of columns of matrix A in ML-DSA-44
pub const ML_DSA_44_L: usize = 4;

/// Parameter D for ML-DSA-44
pub const ML_DSA_44_D: usize = 13;

/// Parameter TAU for ML-DSA-44
pub const ML_DSA_44_TAU: usize = 39;

/// Parameter LAMBDA_OVER_4 for ML-DSA-44
pub const ML_DSA_44_LAMBDA_OVER_4: usize = 32;

/// Parameter GAMMA1 for ML-DSA-44
pub const ML_DSA_44_GAMMA1: usize = 1 << 17;

/// Numerical value bit_length(2 * GAMMA1 - 1) for ML-DSA-44
pub const ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE: usize = 18;

/// Numerical value 32 * bit_length(2 * GAMMA1 - 1) for ML-DSA-44
pub const ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize = 576;

/// Parameter GAMMA2 for ML-DSA-44  (this corresponds to (Q - 1)/88 )
pub const ML_DSA_44_GAMMA2: usize = 95232;

/// Numerical value bit_length((Q - 1) / (2 * GAMMA2) - 1) for ML-DSA-44
pub const ML_DSA_44_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = 6;

/// Numerical value 32 * K * bit_length((Q - 1) / (2 * GAMMA2) - 1) for ML-DSA-44
pub const ML_DSA_44_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = 768;

/// Parameter ETA for ML-DSA-44
pub const ML_DSA_44_ETA: usize = 2;

/// Numerical value bit_length(2 * ETA) for ML-DSA-44
pub const ML_DSA_44_BITLEN_2ETA: usize = 3;

/// Parameter BETA for ML-DSA-44
pub const ML_DSA_44_BETA: usize = 78;

/// Parameter OMEGA for ML-DSA-44
pub const ML_DSA_44_OMEGA: usize = 80;




/// Number of rows of matrix A in ML-DSA-65
pub const ML_DSA_65_K: usize = 6;

/// Number of columns of matrix A in ML-DSA-65
pub const ML_DSA_65_L: usize = 5;

/// Parameter D for ML-DSA-65
pub const ML_DSA_65_D: usize = 13;

/// Parameter TAU for ML-DSA-65
pub const ML_DSA_65_TAU: usize = 49;

/// Parameter LAMBDA_OVER_4 for ML-DSA-65
pub const ML_DSA_65_LAMBDA_OVER_4: usize = 48;

/// Parameter GAMMA1 for ML-DSA-65
pub const ML_DSA_65_GAMMA1: usize = 1 << 19;

/// Numerical value bit_length(2 * GAMMA1 - 1) for ML-DSA-65
pub const ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE: usize = 20;

/// Numerical value 32 * bit_length(2 * GAMMA1 - 1) for ML-DSA-65
pub const ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize = 640;

/// Parameter GAMMA2 for ML-DSA-65  (this corresponds to (Q - 1)/32 )
pub const ML_DSA_65_GAMMA2: usize = 261888;

/// Numerical value bit_length((Q - 1) / (2 * GAMMA2) - 1) for ML-DSA-65
pub const ML_DSA_65_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = 4;

/// Numerical value 32 * K * bit_length((Q - 1) / (2 * GAMMA2) - 1) for ML-DSA-65
pub const ML_DSA_65_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = 768;

/// Parameter ETA for ML-DSA-65
pub const ML_DSA_65_ETA: usize = 4;

/// Numerical value bit_length(2 * ETA) for ML-DSA-65
pub const ML_DSA_65_BITLEN_2ETA: usize = 4;

/// Parameter BETA for ML-DSA-65
pub const ML_DSA_65_BETA: usize = 196;

/// Parameter OMEGA for ML-DSA-65
pub const ML_DSA_65_OMEGA: usize = 55;




/// Number of rows of matrix A in ML-DSA-87
pub const ML_DSA_87_K: usize = 8;

/// Number of columns of matrix A in ML-DSA-87
pub const ML_DSA_87_L: usize = 7;

/// Parameter D for ML-DSA-87
pub const ML_DSA_87_D: usize = 13;

/// Parameter TAU for ML-DSA-87
pub const ML_DSA_87_TAU: usize = 60;

/// Parameter LAMBDA_OVER_4 for ML-DSA-87
pub const ML_DSA_87_LAMBDA_OVER_4: usize = 64;

/// Parameter GAMMA1 for ML-DSA-87
pub const ML_DSA_87_GAMMA1: usize = 1 << 19;

/// Numerical value bit_length(2 * GAMMA1 - 1) for ML-DSA-87
pub const ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE: usize = 20;

/// Numerical value 32 * bit_length(2 * GAMMA1 - 1) for ML-DSA-87
pub const ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize = 640;

/// Parameter GAMMA2 for ML-DSA-87  (this corresponds to (Q - 1)/32 )
pub const ML_DSA_87_GAMMA2: usize = 261888;

/// Numerical value bit_length((Q - 1) / (2 * GAMMA2) - 1) for ML-DSA-87
pub const ML_DSA_87_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = 4;

/// Numerical value 32 * K * bit_length((Q - 1) / (2 * GAMMA2) - 1) for ML-DSA-87
pub const ML_DSA_87_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = 1024;

/// Parameter ETA for ML-DSA-87
pub const ML_DSA_87_ETA: usize = 2;

/// Numerical value bit_length(2 * ETA) for ML-DSA-87
pub const ML_DSA_87_BITLEN_2ETA: usize = 3;

/// Parameter BETA for ML-DSA-87
pub const ML_DSA_87_BETA: usize = 120;

/// Parameter 768OMEGA for ML-DSA-87
pub const ML_DSA_87_OMEGA: usize = 75;




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