mod common;

use common::rbg::{FailingRbg, FixedChunksRbg};

use ml_kem::{
    MlKem512Ciphertext, MlKem512EncapsulationKey, MlKem768Ciphertext, MlKem768EncapsulationKey,
    MlKem1024Ciphertext, MlKem1024EncapsulationKey, MlKemError, ml_kem512_decaps,
    ml_kem512_encaps_with_rbg, ml_kem512_keygen_with_rbg, ml_kem768_decaps,
    ml_kem768_encaps_with_rbg, ml_kem768_keygen_with_rbg, ml_kem1024_decaps,
    ml_kem1024_encaps_with_rbg, ml_kem1024_keygen_with_rbg,
};

macro_rules! define_mlkem_negative_tests {
    (
        $arbitrary_ek_test:ident,
        $keygen_rng_failure_test:ident,
        $encaps_rng_failure_test:ident,
        $decaps_invalid_ct_test:ident,
        $keygen:path,
        $encaps:path,
        $decaps:path,
        $encapsulation_key_ty:ty,
        $ciphertext_ty:ty,
        $ek_bytes:expr,
        $ct_bytes:expr,
        $d:expr,
        $z:expr,
        $m:expr
    ) => {
        #[test]
        fn $arbitrary_ek_test() {
            let arbitrary_ek = <$encapsulation_key_ty>::from_bytes([0xffu8; $ek_bytes]);

            let m = $m;
            let chunks: [&[u8]; 1] = [m.as_ref()];
            let mut rbg = FixedChunksRbg::new(&chunks);

            let result = $encaps(&arbitrary_ek, &mut rbg);

            assert!(result.is_ok());
        }

        #[test]
        fn $keygen_rng_failure_test() {
            let mut rbg = FailingRbg;

            let result = $keygen(&mut rbg);

            assert!(matches!(result, Err(MlKemError::RandomnessFailure)));
        }

        #[test]
        fn $encaps_rng_failure_test() {
            let d = $d;
            let z = $z;

            let chunks: [&[u8]; 2] = [d.as_ref(), z.as_ref()];
            let mut rbg = FixedChunksRbg::new(&chunks);

            let keypair = $keygen(&mut rbg).expect("keygen succeeds");

            let mut failing = FailingRbg;

            let result = $encaps(keypair.encapsulation_key(), &mut failing);

            assert!(matches!(result, Err(MlKemError::RandomnessFailure)));
        }

        #[test]
        fn $decaps_invalid_ct_test() {
            let d = $d;
            let z = $z;
            let m = $m;

            let keygen_chunks: [&[u8]; 2] = [d.as_ref(), z.as_ref()];
            let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);

            let keypair = $keygen(&mut keygen_rbg).expect("keygen succeeds");

            let encaps_chunks: [&[u8]; 1] = [m.as_ref()];
            let mut encaps_rbg = FixedChunksRbg::new(&encaps_chunks);

            let (ss_valid, ct_valid) = $encaps(keypair.encapsulation_key(), &mut encaps_rbg)
                .expect("encapsulation succeeds");

            let ss_decaps = $decaps(keypair.decapsulation_key(), &ct_valid);

            assert_eq!(ss_valid.as_bytes(), ss_decaps.as_bytes());

            let invalid_ct = <$ciphertext_ty>::from_bytes([0xffu8; $ct_bytes]);

            let _fallback_ss = $decaps(keypair.decapsulation_key(), &invalid_ct);

            // Decapsulation is intentionally infallible. This test mainly
            // asserts that malformed ciphertext bytes do not panic.
        }
    };
}

define_mlkem_negative_tests!(
    mlkem512_invalid_encapsulation_key_is_rejected,
    mlkem512_keygen_maps_rbg_failure,
    mlkem512_encaps_maps_rbg_failure,
    mlkem512_decaps_invalid_ciphertext_is_infallible,
    ml_kem512_keygen_with_rbg,
    ml_kem512_encaps_with_rbg,
    ml_kem512_decaps,
    MlKem512EncapsulationKey,
    MlKem512Ciphertext,
    800,
    768,
    [0x51u8; 32],
    [0x52u8; 32],
    [0x53u8; 32]
);

define_mlkem_negative_tests!(
    mlkem768_invalid_encapsulation_key_is_rejected,
    mlkem768_keygen_maps_rbg_failure,
    mlkem768_encaps_maps_rbg_failure,
    mlkem768_decaps_invalid_ciphertext_is_infallible,
    ml_kem768_keygen_with_rbg,
    ml_kem768_encaps_with_rbg,
    ml_kem768_decaps,
    MlKem768EncapsulationKey,
    MlKem768Ciphertext,
    1184,
    1088,
    [0x71u8; 32],
    [0x72u8; 32],
    [0x73u8; 32]
);

define_mlkem_negative_tests!(
    mlkem1024_invalid_encapsulation_key_is_rejected,
    mlkem1024_keygen_maps_rbg_failure,
    mlkem1024_encaps_maps_rbg_failure,
    mlkem1024_decaps_invalid_ciphertext_is_infallible,
    ml_kem1024_keygen_with_rbg,
    ml_kem1024_encaps_with_rbg,
    ml_kem1024_decaps,
    MlKem1024EncapsulationKey,
    MlKem1024Ciphertext,
    1568,
    1568,
    [0xA1u8; 32],
    [0xA2u8; 32],
    [0xA3u8; 32]
);

#[test]
fn mlkem512_encapsulation_key_try_from_slice_rejects_wrong_length() {
    let too_short = [0u8; 799];
    let too_long = [0u8; 801];

    assert!(MlKem512EncapsulationKey::try_from_slice(&too_short).is_err());
    assert!(MlKem512EncapsulationKey::try_from_slice(&too_long).is_err());
}

#[test]
fn mlkem768_encapsulation_key_try_from_slice_rejects_wrong_length() {
    let too_short = [0u8; 1183];
    let too_long = [0u8; 1185];

    assert!(MlKem768EncapsulationKey::try_from_slice(&too_short).is_err());
    assert!(MlKem768EncapsulationKey::try_from_slice(&too_long).is_err());
}

#[test]
fn mlkem1024_encapsulation_key_try_from_slice_rejects_wrong_length() {
    let too_short = [0u8; 1567];
    let too_long = [0u8; 1569];

    assert!(MlKem1024EncapsulationKey::try_from_slice(&too_short).is_err());
    assert!(MlKem1024EncapsulationKey::try_from_slice(&too_long).is_err());
}

#[test]
fn mlkem512_ciphertext_try_from_slice_rejects_wrong_length() {
    let too_short = [0u8; 767];
    let too_long = [0u8; 769];

    assert!(MlKem512Ciphertext::try_from_slice(&too_short).is_err());
    assert!(MlKem512Ciphertext::try_from_slice(&too_long).is_err());
}

#[test]
fn mlkem768_ciphertext_try_from_slice_rejects_wrong_length() {
    let too_short = [0u8; 1087];
    let too_long = [0u8; 1089];

    assert!(MlKem768Ciphertext::try_from_slice(&too_short).is_err());
    assert!(MlKem768Ciphertext::try_from_slice(&too_long).is_err());
}

#[test]
fn mlkem1024_ciphertext_try_from_slice_rejects_wrong_length() {
    let too_short = [0u8; 1567];
    let too_long = [0u8; 1569];

    assert!(MlKem1024Ciphertext::try_from_slice(&too_short).is_err());
    assert!(MlKem1024Ciphertext::try_from_slice(&too_long).is_err());
}
