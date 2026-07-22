mod common;

use common::rbg::{FixedChunksRbg, FailingRbg, RepeatingRbg};

use ml_kem::{
    MlKemError, ml_kem512_decaps, ml_kem512_encaps, ml_kem512_encaps_with_rbg, ml_kem512_keygen,
    ml_kem512_keygen_with_rbg, ml_kem768_decaps, ml_kem768_encaps, ml_kem768_keygen,
    ml_kem1024_decaps, ml_kem1024_encaps, ml_kem1024_keygen,
};

const ROUNDS: usize = 10;

#[test]
fn ml_kem512_public_api_roundtrip() {
    for _ in 0..ROUNDS {
        let kp = ml_kem512_keygen().expect("key generation succeeds");

        let (ss_enc, ciphertext) =
            ml_kem512_encaps(kp.encapsulation_key()).expect("encapsulation succeeds");

        let ss_dec = ml_kem512_decaps(kp.decapsulation_key(), &ciphertext);

        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }
}

#[test]
fn ml_kem768_public_api_roundtrip() {
    for _ in 0..ROUNDS {
        let kp = ml_kem768_keygen().expect("key generation succeeds");

        let (ss_enc, ciphertext) =
            ml_kem768_encaps(kp.encapsulation_key()).expect("encapsulation succeeds");

        let ss_dec = ml_kem768_decaps(kp.decapsulation_key(), &ciphertext);

        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }
}

#[test]
fn ml_kem1024_public_api_roundtrip() {
    for _ in 0..ROUNDS {
        let kp = ml_kem1024_keygen().expect("key generation succeeds");

        let (ss_enc, ciphertext) =
            ml_kem1024_encaps(kp.encapsulation_key()).expect("encapsulation succeeds");

        let ss_dec = ml_kem1024_decaps(kp.decapsulation_key(), &ciphertext);

        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }
}

#[test]
fn ml_kem512_keygen_with_rbg_maps_randomness_failure() {
    let mut rbg = FailingRbg;

    let result = ml_kem512_keygen_with_rbg(&mut rbg);

    assert!(matches!(result, Err(MlKemError::RandomnessFailure)));
}

#[test]
fn ml_kem512_encaps_with_rbg_maps_randomness_failure() {
    let mut keygen_rbg = RepeatingRbg { byte: 0x42 };
    let keypair = ml_kem512_keygen_with_rbg(&mut keygen_rbg).expect("key generation succeeds");

    let mut encaps_rbg = FailingRbg;
    let result = ml_kem512_encaps_with_rbg(keypair.encapsulation_key(), &mut encaps_rbg);

    assert!(matches!(result, Err(MlKemError::RandomnessFailure)));
}

#[test]
fn ml_kem512_keygen_with_rbg_consumes_two_chunks() {
    let d = [0x51u8; 32];
    let z = [0x52u8; 32];

    let chunks: [&[u8]; 2] = [d.as_ref(), z.as_ref()];
    let mut rbg = FixedChunksRbg::new(&chunks);

    let _keypair = ml_kem512_keygen_with_rbg(&mut rbg)
        .expect("keygen succeeds");

    assert_eq!(rbg.consumed_chunks(), 2);
}

#[test]
fn ml_kem512_encaps_with_rbg_consumes_one_chunk() {
    let d = [0x51u8; 32];
    let z = [0x52u8; 32];
    let m = [0x53u8; 32];

    let keygen_chunks: [&[u8]; 2] = [d.as_ref(), z.as_ref()];
    let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);

    let keypair = ml_kem512_keygen_with_rbg(&mut keygen_rbg)
        .expect("keygen succeeds");

    let encaps_chunks: [&[u8]; 1] = [m.as_ref()];
    let mut encaps_rbg = FixedChunksRbg::new(&encaps_chunks);

    let _ = ml_kem512_encaps_with_rbg(
        keypair.encapsulation_key(),
        &mut encaps_rbg,
    )
        .expect("encapsulation succeeds");

    assert_eq!(encaps_rbg.consumed_chunks(), 1);
}
