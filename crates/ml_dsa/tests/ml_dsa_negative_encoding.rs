mod common;

use common::rbg::{FailingRbg, FixedChunksRbg};

use ml_dsa::{
    MlDsa44SecretKey, MlDsa44Signature, MlDsa65SecretKey, MlDsa65Signature, MlDsa87SecretKey,
    MlDsa87Signature, MlDsaError, ml_dsa44_keygen_with_rbg, ml_dsa44_sign_with_rbg,
    ml_dsa44_verify, ml_dsa65_keygen_with_rbg, ml_dsa65_sign_with_rbg, ml_dsa65_verify,
    ml_dsa87_keygen_with_rbg, ml_dsa87_sign_with_rbg, ml_dsa87_verify,
};

macro_rules! define_mldsa_negative_tests {
    (
        $invalid_sk_test:ident,
        $invalid_sig_test:ident,
        $verify_long_context_test:ident,
        $keygen_rng_failure_test:ident,
        $sign_rng_failure_test:ident,
        $wrong_key_test:ident,
        $keygen:path,
        $sign:path,
        $verify:path,
        $secret_key_ty:ty,
        $signature_ty:ty,
        $sk_bytes:expr,
        $sig_bytes:expr,
        $seed:expr,
        $other_seed:expr,
        $randomness:expr
    ) => {
        #[test]
        fn $invalid_sk_test() {
            let invalid_sk = <$secret_key_ty>::from_bytes([0xffu8; $sk_bytes]);
            let randomness = $randomness;
            let chunks: [&[u8]; 1] = [randomness.as_ref()];
            let mut rbg = FixedChunksRbg::new(&chunks);

            let result = $sign(&invalid_sk, b"message", b"", &mut rbg);

            assert!(matches!(result, Err(MlDsaError::InvalidSecretKey)));
        }

        #[test]
        fn $invalid_sig_test() {
            let seed = $seed;
            let chunks: [&[u8]; 1] = [seed.as_ref()];
            let mut rbg = FixedChunksRbg::new(&chunks);

            let keypair = $keygen(&mut rbg).expect("keygen succeeds");

            let invalid_sig = <$signature_ty>::from_bytes([0xffu8; $sig_bytes]);

            let result = $verify(keypair.public_key(), b"message", b"", &invalid_sig);

            assert!(matches!(result, Err(MlDsaError::InvalidSignature)));
        }

        #[test]
        fn $verify_long_context_test() {
            let seed = $seed;
            let randomness = $randomness;

            let keygen_chunks: [&[u8]; 1] = [seed.as_ref()];
            let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);

            let keypair = $keygen(&mut keygen_rbg).expect("keygen succeeds");

            let sign_chunks: [&[u8]; 1] = [randomness.as_ref()];
            let mut sign_rbg = FixedChunksRbg::new(&sign_chunks);

            let sig = $sign(keypair.secret_key(), b"message", b"", &mut sign_rbg)
                .expect("signing succeeds");

            let too_long_context = [0u8; 256];

            let result = $verify(keypair.public_key(), b"message", &too_long_context, &sig);

            assert!(matches!(result, Err(MlDsaError::InvalidLength)));
        }

        #[test]
        fn $keygen_rng_failure_test() {
            let mut rbg = FailingRbg;

            let result = $keygen(&mut rbg);

            assert!(matches!(result, Err(MlDsaError::RandomnessFailure)));
        }

        #[test]
        fn $sign_rng_failure_test() {
            let seed = $seed;
            let chunks: [&[u8]; 1] = [seed.as_ref()];
            let mut rbg = FixedChunksRbg::new(&chunks);

            let keypair = $keygen(&mut rbg).expect("keygen succeeds");

            let mut failing = FailingRbg;

            let result = $sign(keypair.secret_key(), b"message", b"", &mut failing);

            assert!(matches!(result, Err(MlDsaError::RandomnessFailure)));
        }

        #[test]
        fn $wrong_key_test() {
            let seed = $seed;
            let other_seed = $other_seed;
            let randomness = $randomness;

            let keygen_chunks_a: [&[u8]; 1] = [seed.as_ref()];
            let mut keygen_rbg_a = FixedChunksRbg::new(&keygen_chunks_a);

            let keypair_a = $keygen(&mut keygen_rbg_a).expect("keygen A succeeds");

            let keygen_chunks_b: [&[u8]; 1] = [other_seed.as_ref()];
            let mut keygen_rbg_b = FixedChunksRbg::new(&keygen_chunks_b);

            let keypair_b = $keygen(&mut keygen_rbg_b).expect("keygen B succeeds");

            let sign_chunks: [&[u8]; 1] = [randomness.as_ref()];
            let mut sign_rbg = FixedChunksRbg::new(&sign_chunks);

            let sig = $sign(keypair_a.secret_key(), b"message", b"", &mut sign_rbg)
                .expect("signing succeeds");

            let ok = $verify(keypair_b.public_key(), b"message", b"", &sig)
                .expect("verification should not return an encoding error");

            assert!(!ok);
        }
    };
}

define_mldsa_negative_tests!(
    mldsa44_invalid_secret_key_is_rejected,
    mldsa44_invalid_signature_is_rejected,
    mldsa44_verify_rejects_too_long_context,
    mldsa44_keygen_maps_rbg_failure,
    mldsa44_sign_maps_rbg_failure,
    mldsa44_well_formed_signature_with_wrong_key_returns_false,
    ml_dsa44_keygen_with_rbg,
    ml_dsa44_sign_with_rbg,
    ml_dsa44_verify,
    MlDsa44SecretKey,
    MlDsa44Signature,
    2560,
    2420,
    [0x44u8; 32],
    [0x45u8; 32],
    [0xA4u8; 32]
);

define_mldsa_negative_tests!(
    mldsa65_invalid_secret_key_is_rejected,
    mldsa65_invalid_signature_is_rejected,
    mldsa65_verify_rejects_too_long_context,
    mldsa65_keygen_maps_rbg_failure,
    mldsa65_sign_maps_rbg_failure,
    mldsa65_well_formed_signature_with_wrong_key_returns_false,
    ml_dsa65_keygen_with_rbg,
    ml_dsa65_sign_with_rbg,
    ml_dsa65_verify,
    MlDsa65SecretKey,
    MlDsa65Signature,
    4032,
    3309,
    [0x65u8; 32],
    [0x66u8; 32],
    [0xA5u8; 32]
);

define_mldsa_negative_tests!(
    mldsa87_invalid_secret_key_is_rejected,
    mldsa87_invalid_signature_is_rejected,
    mldsa87_verify_rejects_too_long_context,
    mldsa87_keygen_maps_rbg_failure,
    mldsa87_sign_maps_rbg_failure,
    mldsa87_well_formed_signature_with_wrong_key_returns_false,
    ml_dsa87_keygen_with_rbg,
    ml_dsa87_sign_with_rbg,
    ml_dsa87_verify,
    MlDsa87SecretKey,
    MlDsa87Signature,
    4896,
    4627,
    [0x87u8; 32],
    [0x88u8; 32],
    [0xA7u8; 32]
);
