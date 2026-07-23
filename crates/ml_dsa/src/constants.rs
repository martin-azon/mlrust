//! ML-DSA parameter-set constants.
//!
//! This module defines the three standardized ML-DSA parameter sets:
//!
//! - [`MlDsa44`];
//! - [`MlDsa65`];
//! - [`MlDsa87`].
//!
//! It also defines the crate-internal numerical constants used by encoding,
//! sampling, rounding, signing, and verification. The public constants in this
//! module are the serialized object sizes that are part of the external ML-DSA
//! API contract.
//!
//! The ML-DSA modulus is:
//!
//! ```text
//! q = 8_380_417
//! ```
//!
//! The marker types are zero-sized types used to select a parameter set at the
//! type level. The associated constants themselves are plain `usize` values so
//! that lower-level const-generic routines can be instantiated directly.

/// Zero-sized marker type for ML-DSA-44.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsa44 {}

/// Zero-sized marker type for ML-DSA-65.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsa65 {}

/// Zero-sized marker type for ML-DSA-87.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsa87 {}

/// Bit length of `q - 1`, where `q = 8_380_417`.
pub(crate) const BITLEN_Q_MINUS_ONE: usize = 23;

/// Number of bits used to encode one `t1` coefficient.
///
/// This is:
///
/// ```text
/// bitlen(q - 1) - d
/// ```
///
/// where `q = 8_380_417` and `d = 13`.
pub(crate) const BITLEN_Q_MINUS_ONE_MINUS_D: usize = 10;

/// Matrix row dimension `k` for ML-DSA-44.
pub(crate) const ML_DSA_44_K: usize = 4;

/// Matrix column dimension `l` for ML-DSA-44.
pub(crate) const ML_DSA_44_L: usize = 4;

/// Number of low bits split from `t` by `Power2Round`.
pub(crate) const ML_DSA_44_D: usize = 13;

/// Number of nonzero coefficients in the challenge polynomial `c`.
pub(crate) const ML_DSA_44_TAU: usize = 39;

/// Challenge digest length in bytes, equal to `lambda / 4`.
pub(crate) const ML_DSA_44_LAMBDA_OVER_4: usize = 32;

/// Masking bound `gamma1`.
pub(crate) const ML_DSA_44_GAMMA1: usize = 1 << 17;

/// Number of bits used to encode one `z` coefficient:
///
/// ```text
/// bitlen(2 * gamma1 - 1)
/// ```
pub(crate) const ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE: usize = 18;

/// Number of bytes used to encode one `z` polynomial:
///
/// ```text
/// 32 * bitlen(2 * gamma1 - 1)
/// ```
pub(crate) const ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize = 576;

/// Rounding parameter `gamma2`.
///
/// For ML-DSA-44:
///
/// ```text
/// gamma2 = (q - 1) / 88
/// ```
pub(crate) const ML_DSA_44_GAMMA2: usize = 95_232;

/// Number of bits used to encode one `w1` coefficient:
///
/// ```text
/// bitlen((q - 1) / (2 * gamma2) - 1)
/// ```
pub(crate) const ML_DSA_44_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = 6;

/// Number of bytes used to encode the full `w1` vector:
///
/// ```text
/// 32 * k * bitlen((q - 1) / (2 * gamma2) - 1)
/// ```
pub(crate) const ML_DSA_44_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = 768;

/// Secret-vector sampling bound `eta`.
pub(crate) const ML_DSA_44_ETA: usize = 2;

/// Number of bits used to encode one short secret coefficient:
///
/// ```text
/// bitlen(2 * eta)
/// ```
pub(crate) const ML_DSA_44_BITLEN_2ETA: usize = 3;

/// Signing rejection offset:
///
/// ```text
/// beta = tau * eta
/// ```
pub(crate) const ML_DSA_44_BETA: usize = 78;

/// Maximum allowed hint weight.
pub(crate) const ML_DSA_44_OMEGA: usize = 80;

/// Matrix row dimension `k` for ML-DSA-65.
pub(crate) const ML_DSA_65_K: usize = 6;

/// Matrix column dimension `l` for ML-DSA-65.
pub(crate) const ML_DSA_65_L: usize = 5;

/// Number of low bits split from `t` by `Power2Round`.
pub(crate) const ML_DSA_65_D: usize = 13;

/// Number of nonzero coefficients in the challenge polynomial `c`.
pub(crate) const ML_DSA_65_TAU: usize = 49;

/// Challenge digest length in bytes, equal to `lambda / 4`.
pub(crate) const ML_DSA_65_LAMBDA_OVER_4: usize = 48;

/// Masking bound `gamma1`.
pub(crate) const ML_DSA_65_GAMMA1: usize = 1 << 19;

/// Number of bits used to encode one `z` coefficient:
///
/// ```text
/// bitlen(2 * gamma1 - 1)
/// ```
pub(crate) const ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE: usize = 20;

/// Number of bytes used to encode one `z` polynomial:
///
/// ```text
/// 32 * bitlen(2 * gamma1 - 1)
/// ```
pub(crate) const ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize = 640;

/// Rounding parameter `gamma2`.
///
/// For ML-DSA-65:
///
/// ```text
/// gamma2 = (q - 1) / 88
/// ```
pub(crate) const ML_DSA_65_GAMMA2: usize = 261_888;

/// Number of bits used to encode one `w1` coefficient:
///
/// ```text
/// bitlen((q - 1) / (2 * gamma2) - 1)
/// ```
pub(crate) const ML_DSA_65_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = 4;

/// Number of bytes used to encode the full `w1` vector:
///
/// ```text
/// 32 * k * bitlen((q - 1) / (2 * gamma2) - 1)
/// ```
pub(crate) const ML_DSA_65_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = 768;

/// Secret-vector sampling bound `eta`.
pub(crate) const ML_DSA_65_ETA: usize = 4;

/// Number of bits used to encode one short secret coefficient:
///
/// ```text
/// bitlen(2 * eta)
/// ```
pub(crate) const ML_DSA_65_BITLEN_2ETA: usize = 4;

/// Signing rejection offset:
///
/// ```text
/// beta = tau * eta
/// ```
pub(crate) const ML_DSA_65_BETA: usize = 196;

/// Maximum allowed hint weight.
pub(crate) const ML_DSA_65_OMEGA: usize = 55;

/// Matrix row dimension `k` for ML-DSA-87.
pub(crate) const ML_DSA_87_K: usize = 8;

/// Matrix column dimension `l` for ML-DSA-87.
pub(crate) const ML_DSA_87_L: usize = 7;

/// Number of low bits split from `t` by `Power2Round`.
pub(crate) const ML_DSA_87_D: usize = 13;

/// Number of nonzero coefficients in the challenge polynomial `c`.
pub(crate) const ML_DSA_87_TAU: usize = 60;

/// Challenge digest length in bytes, equal to `lambda / 4`.
pub(crate) const ML_DSA_87_LAMBDA_OVER_4: usize = 64;

/// Masking bound `gamma1`.
pub(crate) const ML_DSA_87_GAMMA1: usize = 1 << 19;

/// Number of bits used to encode one `z` coefficient:
///
/// ```text
/// bitlen(2 * gamma1 - 1)
/// ```
pub(crate) const ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE: usize = 20;

/// Number of bytes used to encode one `z` polynomial:
///
/// ```text
/// 32 * bitlen(2 * gamma1 - 1)
/// ```
pub(crate) const ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32: usize = 640;

/// Rounding parameter `gamma2`.
///
/// For ML-DSA-87:
///
/// ```text
/// gamma2 = (q - 1) / 88
/// ```
pub(crate) const ML_DSA_87_GAMMA2: usize = 261_888;

/// Number of bits used to encode one `w1` coefficient:
///
/// ```text
/// bitlen((q - 1) / (2 * gamma2) - 1)
/// ```
pub(crate) const ML_DSA_87_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = 4;

/// Number of bytes used to encode the full `w1` vector:
///
/// ```text
/// 32 * k * bitlen((q - 1) / (2 * gamma2) - 1)
/// ```
pub(crate) const ML_DSA_87_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE: usize = 1024;

/// Secret-vector sampling bound `eta`.
pub(crate) const ML_DSA_87_ETA: usize = 2;

/// Number of bits used to encode one short secret coefficient:
///
/// ```text
/// bitlen(2 * eta)
/// ```
pub(crate) const ML_DSA_87_BITLEN_2ETA: usize = 3;

/// Signing rejection offset:
///
/// ```text
/// beta = tau * eta
/// ```
pub(crate) const ML_DSA_87_BETA: usize = 120;

/// Maximum allowed hint weight.
pub(crate) const ML_DSA_87_OMEGA: usize = 75;

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

#[cfg(test)]
mod tests {
    use super::*;
    use mlrust_core::encode::bits::bitlen_u32;
    use mlrust_core::params::{Q8380417, RingParams};

    const Q: i32 = Q8380417::Q;

    #[test]
    fn shared_bit_lengths_are_consistent() {
        assert_eq!(Q, 8_380_417);

        assert_eq!(BITLEN_Q_MINUS_ONE, bitlen_u32((Q - 1) as u32));

        assert_eq!(BITLEN_Q_MINUS_ONE_MINUS_D, BITLEN_Q_MINUS_ONE - ML_DSA_44_D);

        assert_eq!(ML_DSA_44_D, 13);
        assert_eq!(ML_DSA_65_D, 13);
        assert_eq!(ML_DSA_87_D, 13);
    }

    fn check_parameter_set(
        k: usize,
        l: usize,
        d: usize,
        tau: usize,
        lambda_over_4: usize,
        gamma1: usize,
        bitlen_2gamma1_minus_one: usize,
        bitlen_2gamma1_minus_one_times_32: usize,
        gamma2: usize,
        bitlen_w1_coeff: usize,
        w1_encoded_bytes: usize,
        eta: usize,
        bitlen_2eta: usize,
        beta: usize,
        omega: usize,
        sk_bytes: usize,
        pk_bytes: usize,
        sig_bytes: usize,
    ) {
        assert!(k > 0);
        assert!(l > 0);
        assert_eq!(d, 13);

        assert_eq!(bitlen_2eta, bitlen_u32((2 * eta) as u32));

        assert_eq!(
            bitlen_2gamma1_minus_one,
            bitlen_u32((2 * gamma1 - 1) as u32)
        );

        assert_eq!(
            bitlen_2gamma1_minus_one_times_32,
            32 * bitlen_2gamma1_minus_one
        );

        assert_eq!(
            bitlen_w1_coeff,
            bitlen_u32(((Q - 1) / (2 * gamma2 as i32)) as u32 - 1)
        );

        assert_eq!(w1_encoded_bytes, 32 * k * bitlen_w1_coeff);

        assert_eq!(beta, tau * eta);

        assert_eq!(pk_bytes, 32 + 32 * k * (bitlen_u32((Q - 1) as u32) - d));

        assert_eq!(sk_bytes, 128 + 32 * ((l + k) * bitlen_2eta + d * k));

        assert_eq!(
            sig_bytes,
            lambda_over_4 + l * 32 * bitlen_2gamma1_minus_one + omega + k
        );
    }

    #[test]
    fn mldsa44_constants_are_self_consistent() {
        assert_eq!(ML_DSA_44_GAMMA2, ((Q - 1) / 88) as usize);

        check_parameter_set(
            ML_DSA_44_K,
            ML_DSA_44_L,
            ML_DSA_44_D,
            ML_DSA_44_TAU,
            ML_DSA_44_LAMBDA_OVER_4,
            ML_DSA_44_GAMMA1,
            ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE,
            ML_DSA_44_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
            ML_DSA_44_GAMMA2,
            ML_DSA_44_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_44_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_44_ETA,
            ML_DSA_44_BITLEN_2ETA,
            ML_DSA_44_BETA,
            ML_DSA_44_OMEGA,
            ML_DSA_44_SECRET_KEY_BYTES,
            ML_DSA_44_PUBLIC_KEY_BYTES,
            ML_DSA_44_SIGNATURE_BYTES,
        );
    }

    #[test]
    fn mldsa65_constants_are_self_consistent() {
        assert_eq!(ML_DSA_65_GAMMA2, ((Q - 1) / 32) as usize);

        check_parameter_set(
            ML_DSA_65_K,
            ML_DSA_65_L,
            ML_DSA_65_D,
            ML_DSA_65_TAU,
            ML_DSA_65_LAMBDA_OVER_4,
            ML_DSA_65_GAMMA1,
            ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE,
            ML_DSA_65_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
            ML_DSA_65_GAMMA2,
            ML_DSA_65_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_65_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_65_ETA,
            ML_DSA_65_BITLEN_2ETA,
            ML_DSA_65_BETA,
            ML_DSA_65_OMEGA,
            ML_DSA_65_SECRET_KEY_BYTES,
            ML_DSA_65_PUBLIC_KEY_BYTES,
            ML_DSA_65_SIGNATURE_BYTES,
        );
    }

    #[test]
    fn mldsa87_constants_are_self_consistent() {
        assert_eq!(ML_DSA_87_GAMMA2, ((Q - 1) / 32) as usize);

        check_parameter_set(
            ML_DSA_87_K,
            ML_DSA_87_L,
            ML_DSA_87_D,
            ML_DSA_87_TAU,
            ML_DSA_87_LAMBDA_OVER_4,
            ML_DSA_87_GAMMA1,
            ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE,
            ML_DSA_87_BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
            ML_DSA_87_GAMMA2,
            ML_DSA_87_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_87_K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
            ML_DSA_87_ETA,
            ML_DSA_87_BITLEN_2ETA,
            ML_DSA_87_BETA,
            ML_DSA_87_OMEGA,
            ML_DSA_87_SECRET_KEY_BYTES,
            ML_DSA_87_PUBLIC_KEY_BYTES,
            ML_DSA_87_SIGNATURE_BYTES,
        );
    }

    #[test]
    fn mldsa_parameter_sets_have_expected_security_strengths() {
        assert_eq!(ML_DSA_44_LAMBDA_OVER_4, 32);
        assert_eq!(ML_DSA_65_LAMBDA_OVER_4, 48);
        assert_eq!(ML_DSA_87_LAMBDA_OVER_4, 64);
    }
}
