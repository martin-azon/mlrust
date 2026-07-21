mod common;

use common::{FailingRbg, FixedChunksRbg};

use ml_dsa::{
    ml_dsa44_keygen_with_rbg,
    ml_dsa44_sign_with_rbg,
    ml_dsa44_verify,
    ml_dsa65_keygen_with_rbg,
    ml_dsa65_sign_with_rbg,
    ml_dsa65_verify,
    ml_dsa87_keygen_with_rbg,
    ml_dsa87_sign_with_rbg,
    ml_dsa87_verify,
    MlDsaError,
};

macro_rules! define_mldsa_public_api_tests {
    (
        $roundtrip_test:ident,
        $modified_message_test:ident,
        $modified_context_test:ident,
        $too_long_context_test:ident,
        $deterministic_test:ident,
        $wrong_key_test:ident,
        $keygen:path,
        $sign:path,
        $verify:path,
        $xi:expr,
        $other_xi:expr,
        $randomness:expr,
        $label:expr
    ) => {
        #[test]
        fn $roundtrip_test() {
            let xi = $xi;
            let randomness = $randomness;

            let message = concat!($label, " public API roundtrip").as_bytes();
            let context = b"";

            let keygen_chunks: [&[u8]; 1] = [xi.as_ref()];
            let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);
            let keypair = $keygen(&mut keygen_rbg).expect("key generation succeeds");

            let sign_chunks: [&[u8]; 1] = [randomness.as_ref()];
            let mut sign_rbg = FixedChunksRbg::new(&sign_chunks);
            let signature = $sign(
                keypair.secret_key(),
                message,
                context,
                &mut sign_rbg,
            )
            .expect("signing succeeds");

            let ok = $verify(
                keypair.public_key(),
                message,
                context,
                &signature,
            )
            .expect("verification does not error");

            assert!(ok);
        }

        #[test]
        fn $modified_message_test() {
            let xi = $xi;
            let randomness = $randomness;

            let message = b"original message";
            let modified_message = b"modified message";
            let context = b"";

            let keygen_chunks: [&[u8]; 1] = [xi.as_ref()];
            let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);
            let keypair = $keygen(&mut keygen_rbg).expect("key generation succeeds");

            let sign_chunks: [&[u8]; 1] = [randomness.as_ref()];
            let mut sign_rbg = FixedChunksRbg::new(&sign_chunks);
            let signature = $sign(
                keypair.secret_key(),
                message,
                context,
                &mut sign_rbg,
            )
            .expect("signing succeeds");

            let ok = $verify(
                keypair.public_key(),
                modified_message,
                context,
                &signature,
            )
            .expect("verification does not error");

            assert!(!ok);
        }

        #[test]
        fn $modified_context_test() {
            let xi = $xi;
            let randomness = $randomness;

            let message = b"context binding message";
            let signing_context = b"context A";
            let verification_context = b"context B";

            let keygen_chunks: [&[u8]; 1] = [xi.as_ref()];
            let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);
            let keypair = $keygen(&mut keygen_rbg).expect("key generation succeeds");

            let sign_chunks: [&[u8]; 1] = [randomness.as_ref()];
            let mut sign_rbg = FixedChunksRbg::new(&sign_chunks);
            let signature = $sign(
                keypair.secret_key(),
                message,
                signing_context,
                &mut sign_rbg,
            )
            .expect("signing succeeds");

            let ok = $verify(
                keypair.public_key(),
                message,
                verification_context,
                &signature,
            )
            .expect("verification does not error");

            assert!(!ok);
        }

        #[test]
        fn $too_long_context_test() {
            let xi = $xi;
            let randomness = $randomness;

            let message = b"context length test";
            let context = [0u8; 256];

            let keygen_chunks: [&[u8]; 1] = [xi.as_ref()];
            let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);
            let keypair = $keygen(&mut keygen_rbg).expect("key generation succeeds");

            let sign_chunks: [&[u8]; 1] = [randomness.as_ref()];
            let mut sign_rbg = FixedChunksRbg::new(&sign_chunks);
            let result = $sign(
                keypair.secret_key(),
                message,
                &context,
                &mut sign_rbg,
            );

            assert!(matches!(result, Err(MlDsaError::InvalidLength)));
        }

        #[test]
        fn $deterministic_test() {
            let xi = $xi;
            let randomness = $randomness;

            let message = concat!($label, " deterministic signing").as_bytes();
            let context = b"deterministic-test-context";

            let keygen_chunks: [&[u8]; 1] = [xi.as_ref()];
            let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);
            let keypair = $keygen(&mut keygen_rbg).expect("key generation succeeds");

            let sign_chunks0: [&[u8]; 1] = [randomness.as_ref()];
            let mut sign_rbg0 = FixedChunksRbg::new(&sign_chunks0);
            let sig0 = $sign(
                keypair.secret_key(),
                message,
                context,
                &mut sign_rbg0,
            )
            .expect("first signing succeeds");

            let sign_chunks1: [&[u8]; 1] = [randomness.as_ref()];
            let mut sign_rbg1 = FixedChunksRbg::new(&sign_chunks1);
            let sig1 = $sign(
                keypair.secret_key(),
                message,
                context,
                &mut sign_rbg1,
            )
            .expect("second signing succeeds");

            assert_eq!(sig0.as_bytes(), sig1.as_bytes());
        }

        #[test]
        fn $wrong_key_test() {
            let xi = $xi;
            let other_xi = $other_xi;
            let randomness = $randomness;

            let message = concat!($label, " wrong public key rejection").as_bytes();
            let context = b"";

            let signing_chunks: [&[u8]; 1] = [xi.as_ref()];
            let mut signing_rbg = FixedChunksRbg::new(&signing_chunks);
            let signing_keypair = $keygen(&mut signing_rbg).expect("key generation succeeds");

            let verifying_chunks: [&[u8]; 1] = [other_xi.as_ref()];
            let mut verifying_rbg = FixedChunksRbg::new(&verifying_chunks);
            let verifying_keypair = $keygen(&mut verifying_rbg).expect("key generation succeeds");

            let sign_chunks: [&[u8]; 1] = [randomness.as_ref()];
            let mut sign_rbg = FixedChunksRbg::new(&sign_chunks);
            let signature = $sign(
                signing_keypair.secret_key(),
                message,
                context,
                &mut sign_rbg,
            )
            .expect("signing succeeds");

            let ok = $verify(
                verifying_keypair.public_key(),
                message,
                context,
                &signature,
            )
            .expect("verification does not error");

            assert!(!ok);
        }
    };
}

define_mldsa_public_api_tests!(
    ml_dsa44_public_api_seeded_roundtrip,
    ml_dsa44_public_api_rejects_modified_message,
    ml_dsa44_public_api_rejects_modified_context,
    ml_dsa44_public_api_rejects_too_long_context,
    ml_dsa44_public_api_signing_is_deterministic_for_fixed_inputs,
    ml_dsa44_public_api_rejects_wrong_public_key,
    ml_dsa44_keygen_with_rbg,
    ml_dsa44_sign_with_rbg,
    ml_dsa44_verify,
    [0x44u8; 32],
    [0x45u8; 32],
    [0xA4u8; 32],
    "ML-DSA-44"
);

define_mldsa_public_api_tests!(
    ml_dsa65_public_api_seeded_roundtrip,
    ml_dsa65_public_api_rejects_modified_message,
    ml_dsa65_public_api_rejects_modified_context,
    ml_dsa65_public_api_rejects_too_long_context,
    ml_dsa65_public_api_signing_is_deterministic_for_fixed_inputs,
    ml_dsa65_public_api_rejects_wrong_public_key,
    ml_dsa65_keygen_with_rbg,
    ml_dsa65_sign_with_rbg,
    ml_dsa65_verify,
    [0x65u8; 32],
    [0x66u8; 32],
    [0xA5u8; 32],
    "ML-DSA-65"
);

define_mldsa_public_api_tests!(
    ml_dsa87_public_api_seeded_roundtrip,
    ml_dsa87_public_api_rejects_modified_message,
    ml_dsa87_public_api_rejects_modified_context,
    ml_dsa87_public_api_rejects_too_long_context,
    ml_dsa87_public_api_signing_is_deterministic_for_fixed_inputs,
    ml_dsa87_public_api_rejects_wrong_public_key,
    ml_dsa87_keygen_with_rbg,
    ml_dsa87_sign_with_rbg,
    ml_dsa87_verify,
    [0x87u8; 32],
    [0x88u8; 32],
    [0xA7u8; 32],
    "ML-DSA-87"
);


#[test]
fn ml_dsa44_keygen_with_rbg_maps_randomness_failure() {
    let mut rbg = FailingRbg;

    let result = ml_dsa44_keygen_with_rbg(&mut rbg);

    assert!(matches!(result, Err(MlDsaError::RandomnessFailure)));
}

#[test]
fn ml_dsa44_sign_with_rbg_maps_randomness_failure() {
    let xi = [0x91u8; 32];
    let keygen_chunks: [&[u8]; 1] = [xi.as_ref()];
    let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);
    let keypair = ml_dsa44_keygen_with_rbg(&mut keygen_rbg)
        .expect("key generation succeeds");

    let mut sign_rbg = FailingRbg;
    let result = ml_dsa44_sign_with_rbg(
        keypair.secret_key(),
        b"message",
        b"",
        &mut sign_rbg,
    );

    assert!(matches!(result, Err(MlDsaError::RandomnessFailure)));
}
