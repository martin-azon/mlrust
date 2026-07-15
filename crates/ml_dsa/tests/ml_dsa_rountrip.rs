use ml_dsa::{
    ml_dsa_keygen44_from_seed,
    ml_dsa_keygen65_from_seed,
    ml_dsa_keygen87_from_seed,
    ml_dsa_sign44_from_seed,
    ml_dsa_sign65_from_seed,
    ml_dsa_sign87_from_seed,
    ml_dsa_verify44,
    ml_dsa_verify65,
    ml_dsa_verify87,
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

            let keypair = $keygen(&xi);

            let signature = $sign(
                keypair.secret_key(),
                message,
                context,
                &randomness,
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

            let keypair = $keygen(&xi);

            let signature = $sign(
                keypair.secret_key(),
                message,
                context,
                &randomness,
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

            let keypair = $keygen(&xi);

            let signature = $sign(
                keypair.secret_key(),
                message,
                signing_context,
                &randomness,
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

            let keypair = $keygen(&xi);

            let result = $sign(
                keypair.secret_key(),
                message,
                &context,
                &randomness,
            );

            assert!(matches!(result, Err(MlDsaError::InvalidLength)));
        }

        #[test]
        fn $deterministic_test() {
            let xi = $xi;
            let randomness = $randomness;

            let message = concat!($label, " deterministic signing").as_bytes();
            let context = b"deterministic-test-context";

            let keypair = $keygen(&xi);

            let sig0 = $sign(
                keypair.secret_key(),
                message,
                context,
                &randomness,
            )
            .expect("first signing succeeds");

            let sig1 = $sign(
                keypair.secret_key(),
                message,
                context,
                &randomness,
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

            let signing_keypair = $keygen(&xi);
            let verifying_keypair = $keygen(&other_xi);

            let signature = $sign(
                signing_keypair.secret_key(),
                message,
                context,
                &randomness,
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
    ml_dsa_keygen44_from_seed,
    ml_dsa_sign44_from_seed,
    ml_dsa_verify44,
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
    ml_dsa_keygen65_from_seed,
    ml_dsa_sign65_from_seed,
    ml_dsa_verify65,
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
    ml_dsa_keygen87_from_seed,
    ml_dsa_sign87_from_seed,
    ml_dsa_verify87,
    [0x87u8; 32],
    [0x88u8; 32],
    [0xA7u8; 32],
    "ML-DSA-87"
);