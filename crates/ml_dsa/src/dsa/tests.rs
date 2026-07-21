use super::internal::{ml_dsa_keygen_internal, ml_dsa_sign_internal, ml_dsa_verify_internal};
use super::params::MlDsaParams;

use crate::constants::*;
use crate::error::MlDsaError;

use mlrust_core::encode::bits::bitlen_u32;
use mlrust_core::params::{Q8380417, RingParams};

const EMPTY_CONTEXT: &[u8] = b"";

fn check_param_trait<P: MlDsaParams>() {
    assert_eq!(P::BITLEN_2ETA, bitlen_u32((2 * P::ETA) as u32));

    assert_eq!(
        P::BITLEN_2GAMMA1_MINUS_ONE,
        bitlen_u32((2 * P::GAMMA1 - 1) as u32)
    );

    assert_eq!(
        P::BITLEN_2GAMMA1_MINUS_ONE_TIMES_32,
        32 * P::BITLEN_2GAMMA1_MINUS_ONE
    );

    assert_eq!(
        P::BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
        bitlen_u32(((Q8380417::Q - 1) / (2 * P::GAMMA2 as i32)) as u32 - 1)
    );

    assert_eq!(
        P::K_TIMES_32_TIMES_BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE,
        32 * P::K * P::BITLEN_Q_MINUS_ONE_OVER_2GAMMA2_MINUS_ONE
    );

    assert_eq!(P::BETA, P::TAU * P::ETA);

    assert_eq!(
        P::PK_BYTES,
        32 + 32 * P::K * (bitlen_u32((Q8380417::Q - 1) as u32) - P::D)
    );

    assert_eq!(
        P::SK_BYTES,
        128 + 32 * ((P::L + P::K) * P::BITLEN_2ETA + P::D * P::K)
    );

    assert_eq!(
        P::SIG_BYTES,
        P::LAMBDA_OVER_4 + P::L * 32 * P::BITLEN_2GAMMA1_MINUS_ONE + P::OMEGA + P::K
    );
}

#[test]
fn mldsa44_param_trait_is_self_consistent() {
    check_param_trait::<MlDsa44>();
}

#[test]
fn mldsa65_param_trait_is_self_consistent() {
    check_param_trait::<MlDsa65>();
}

#[test]
fn mldsa87_param_trait_is_self_consistent() {
    check_param_trait::<MlDsa87>();
}

#[test]
fn mldsa44_keygen_from_seed_matches_direct_internal_keygen() {
    let xi = [0x44u8; 32];

    let via_params = <MlDsa44 as MlDsaParams>::keygen_from_seed(&xi);

    let direct = ml_dsa_keygen_internal::<
        ML_DSA_44_K,
        ML_DSA_44_L,
        ML_DSA_44_D,
        ML_DSA_44_ETA,
        ML_DSA_44_BITLEN_2ETA,
        ML_DSA_44_SECRET_KEY_BYTES,
        ML_DSA_44_PUBLIC_KEY_BYTES,
    >(&xi);

    assert_eq!(
        via_params.public_key().as_bytes(),
        direct.public_key().as_bytes()
    );
    assert_eq!(
        via_params.secret_key().as_bytes(),
        direct.secret_key().as_bytes()
    );
}

#[test]
fn mldsa65_keygen_from_seed_matches_direct_internal_keygen() {
    let xi = [0x65u8; 32];

    let via_params = <MlDsa65 as MlDsaParams>::keygen_from_seed(&xi);

    let direct = ml_dsa_keygen_internal::<
        ML_DSA_65_K,
        ML_DSA_65_L,
        ML_DSA_65_D,
        ML_DSA_65_ETA,
        ML_DSA_65_BITLEN_2ETA,
        ML_DSA_65_SECRET_KEY_BYTES,
        ML_DSA_65_PUBLIC_KEY_BYTES,
    >(&xi);

    assert_eq!(
        via_params.public_key().as_bytes(),
        direct.public_key().as_bytes()
    );
    assert_eq!(
        via_params.secret_key().as_bytes(),
        direct.secret_key().as_bytes()
    );
}

#[test]
fn mldsa87_keygen_from_seed_matches_direct_internal_keygen() {
    let xi = [0x87u8; 32];

    let via_params = <MlDsa87 as MlDsaParams>::keygen_from_seed(&xi);

    let direct = ml_dsa_keygen_internal::<
        ML_DSA_87_K,
        ML_DSA_87_L,
        ML_DSA_87_D,
        ML_DSA_87_ETA,
        ML_DSA_87_BITLEN_2ETA,
        ML_DSA_87_SECRET_KEY_BYTES,
        ML_DSA_87_PUBLIC_KEY_BYTES,
    >(&xi);

    assert_eq!(
        via_params.public_key().as_bytes(),
        direct.public_key().as_bytes()
    );
    assert_eq!(
        via_params.secret_key().as_bytes(),
        direct.secret_key().as_bytes()
    );
}

#[test]
fn mldsa44_internal_sign_verify_roundtrip() {
    let xi = [0x11u8; 32];
    let randomness = [0xA1u8; 32];
    let message = b"ML-DSA-44 internal roundtrip";

    let keypair = ml_dsa_keygen_internal::<
        ML_DSA_44_K,
        ML_DSA_44_L,
        ML_DSA_44_D,
        ML_DSA_44_ETA,
        ML_DSA_44_BITLEN_2ETA,
        ML_DSA_44_SECRET_KEY_BYTES,
        ML_DSA_44_PUBLIC_KEY_BYTES,
    >(&xi);

    let signature = ml_dsa_sign_internal::<
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
        ML_DSA_44_SIGNATURE_BYTES,
    >(keypair.secret_key(), message, EMPTY_CONTEXT, &randomness)
    .expect("signing should succeed");

    assert_eq!(signature.as_bytes().len(), ML_DSA_44_SIGNATURE_BYTES);

    let ok = ml_dsa_verify_internal::<
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
        ML_DSA_44_PUBLIC_KEY_BYTES,
        ML_DSA_44_SIGNATURE_BYTES,
    >(keypair.public_key(), message, EMPTY_CONTEXT, &signature)
    .expect("verification should not error");

    assert!(ok);
}

#[test]
fn mldsa44_param_sign_verify_roundtrip() {
    let xi = [0x22u8; 32];
    let randomness = [0xA2u8; 32];
    let message = b"ML-DSA-44 parameter roundtrip";

    let keypair = <MlDsa44 as MlDsaParams>::keygen_from_seed(&xi);

    let signature = <MlDsa44 as MlDsaParams>::sign_from_seed(
        keypair.secret_key(),
        message,
        EMPTY_CONTEXT,
        &randomness,
    )
    .expect("signing should succeed");

    let ok =
        <MlDsa44 as MlDsaParams>::verify(keypair.public_key(), message, EMPTY_CONTEXT, &signature)
            .expect("verification should not error");

    assert!(ok);
}

#[test]
fn mldsa65_param_sign_verify_roundtrip() {
    let xi = [0x33u8; 32];
    let randomness = [0xA3u8; 32];
    let message = b"ML-DSA-65 parameter roundtrip";

    let keypair = <MlDsa65 as MlDsaParams>::keygen_from_seed(&xi);

    let signature = <MlDsa65 as MlDsaParams>::sign_from_seed(
        keypair.secret_key(),
        message,
        EMPTY_CONTEXT,
        &randomness,
    )
    .expect("signing should succeed");

    let ok =
        <MlDsa65 as MlDsaParams>::verify(keypair.public_key(), message, EMPTY_CONTEXT, &signature)
            .expect("verification should not error");

    assert!(ok);
}

#[test]
fn mldsa87_param_sign_verify_roundtrip() {
    let xi = [0x44u8; 32];
    let randomness = [0xA4u8; 32];
    let message = b"ML-DSA-87 parameter roundtrip";

    let keypair = <MlDsa87 as MlDsaParams>::keygen_from_seed(&xi);

    let signature = <MlDsa87 as MlDsaParams>::sign_from_seed(
        keypair.secret_key(),
        message,
        EMPTY_CONTEXT,
        &randomness,
    )
    .expect("signing should succeed");

    let ok =
        <MlDsa87 as MlDsaParams>::verify(keypair.public_key(), message, EMPTY_CONTEXT, &signature)
            .expect("verification should not error");

    assert!(ok);
}

#[test]
fn mldsa44_verify_rejects_modified_message() {
    let xi = [0x55u8; 32];
    let randomness = [0xB1u8; 32];

    let message = b"original message";
    let modified_message = b"modified message";

    let keypair = <MlDsa44 as MlDsaParams>::keygen_from_seed(&xi);

    let signature = <MlDsa44 as MlDsaParams>::sign_from_seed(
        keypair.secret_key(),
        message,
        EMPTY_CONTEXT,
        &randomness,
    )
    .expect("signing should succeed");

    let ok = <MlDsa44 as MlDsaParams>::verify(
        keypair.public_key(),
        modified_message,
        EMPTY_CONTEXT,
        &signature,
    )
    .expect("verification should not error");

    assert!(!ok);
}

#[test]
fn mldsa44_verify_rejects_modified_context() {
    let xi = [0x56u8; 32];
    let randomness = [0xB2u8; 32];

    let message = b"context binding message";
    let signing_context = b"context A";
    let verification_context = b"context B";

    let keypair = <MlDsa44 as MlDsaParams>::keygen_from_seed(&xi);

    let signature = <MlDsa44 as MlDsaParams>::sign_from_seed(
        keypair.secret_key(),
        message,
        signing_context,
        &randomness,
    )
    .expect("signing should succeed");

    let ok = <MlDsa44 as MlDsaParams>::verify(
        keypair.public_key(),
        message,
        verification_context,
        &signature,
    )
    .expect("verification should not error");

    assert!(!ok);
}

#[test]
fn mldsa44_rejects_context_longer_than_255_bytes() {
    let xi = [0x57u8; 32];
    let randomness = [0xB3u8; 32];
    let message = b"context length test";
    let context = [0u8; 256];

    let keypair = <MlDsa44 as MlDsaParams>::keygen_from_seed(&xi);

    let sign_result = <MlDsa44 as MlDsaParams>::sign_from_seed(
        keypair.secret_key(),
        message,
        &context,
        &randomness,
    );

    assert!(matches!(sign_result, Err(MlDsaError::InvalidLength)));
}

#[test]
fn mldsa44_signing_is_deterministic_for_fixed_inputs() {
    let xi = [0x66u8; 32];
    let randomness = [0xB2u8; 32];
    let message = b"deterministic signing";

    let keypair = <MlDsa44 as MlDsaParams>::keygen_from_seed(&xi);

    let sig0 = <MlDsa44 as MlDsaParams>::sign_from_seed(
        keypair.secret_key(),
        message,
        EMPTY_CONTEXT,
        &randomness,
    )
    .expect("first signing should succeed");

    let sig1 = <MlDsa44 as MlDsaParams>::sign_from_seed(
        keypair.secret_key(),
        message,
        EMPTY_CONTEXT,
        &randomness,
    )
    .expect("second signing should succeed");

    assert_eq!(sig0.as_bytes(), sig1.as_bytes());
}

#[test]
fn mldsa44_param_sign_matches_direct_internal_sign() {
    let xi = [0x77u8; 32];
    let randomness = [0xB3u8; 32];
    let message = b"parameter dispatch signing";

    let keypair = <MlDsa44 as MlDsaParams>::keygen_from_seed(&xi);

    let via_params = <MlDsa44 as MlDsaParams>::sign_from_seed(
        keypair.secret_key(),
        message,
        EMPTY_CONTEXT,
        &randomness,
    )
    .expect("parameter signing should succeed");

    let direct = ml_dsa_sign_internal::<
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
        ML_DSA_44_SIGNATURE_BYTES,
    >(keypair.secret_key(), message, EMPTY_CONTEXT, &randomness)
    .expect("direct signing should succeed");

    assert_eq!(via_params.as_bytes(), direct.as_bytes());
}

#[test]
fn mldsa44_param_verify_matches_direct_internal_verify() {
    let xi = [0x88u8; 32];
    let randomness = [0xB4u8; 32];
    let message = b"parameter dispatch verification";

    let keypair = <MlDsa44 as MlDsaParams>::keygen_from_seed(&xi);

    let signature = <MlDsa44 as MlDsaParams>::sign_from_seed(
        keypair.secret_key(),
        message,
        EMPTY_CONTEXT,
        &randomness,
    )
    .expect("signing should succeed");

    let via_params =
        <MlDsa44 as MlDsaParams>::verify(keypair.public_key(), message, EMPTY_CONTEXT, &signature)
            .expect("parameter verification should not error");

    let direct = ml_dsa_verify_internal::<
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
        ML_DSA_44_PUBLIC_KEY_BYTES,
        ML_DSA_44_SIGNATURE_BYTES,
    >(keypair.public_key(), message, EMPTY_CONTEXT, &signature)
    .expect("direct verification should not error");

    assert_eq!(via_params, direct);
}
