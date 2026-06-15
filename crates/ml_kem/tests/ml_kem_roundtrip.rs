use ml_kem::{
    ml_kem_decaps512, ml_kem_decaps768, ml_kem_decaps1024, ml_kem_encaps512, ml_kem_encaps768,
    ml_kem_encaps1024, ml_kem_keygen512, ml_kem_keygen768, ml_kem_keygen1024,
};

const ROUNDS: usize = 10;

#[test]
fn ml_kem512_public_api_roundtrip() {
    for _ in 0..ROUNDS {
        let kp = ml_kem_keygen512().expect("key generation succeeds");

        let (ss_enc, ciphertext) =
            ml_kem_encaps512(kp.encapsulation_key()).expect("encapsulation succeeds");

        let ss_dec = ml_kem_decaps512(kp.decapsulation_key(), &ciphertext);

        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }
}

#[test]
fn ml_kem768_public_api_roundtrip() {
    for _ in 0..ROUNDS {
        let kp = ml_kem_keygen768().expect("key generation succeeds");

        let (ss_enc, ciphertext) =
            ml_kem_encaps768(kp.encapsulation_key()).expect("encapsulation succeeds");

        let ss_dec = ml_kem_decaps768(kp.decapsulation_key(), &ciphertext);

        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }
}

#[test]
fn ml_kem1024_public_api_roundtrip() {
    for _ in 0..ROUNDS {
        let kp = ml_kem_keygen1024().expect("key generation succeeds");

        let (ss_enc, ciphertext) =
            ml_kem_encaps1024(kp.encapsulation_key()).expect("encapsulation succeeds");

        let ss_dec = ml_kem_decaps1024(kp.decapsulation_key(), &ciphertext);

        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }
}
