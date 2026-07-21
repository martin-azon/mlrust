use ml_kem::{
    MlKemError, ml_kem512_decaps, ml_kem512_encaps, ml_kem512_encaps_with_rbg, ml_kem512_keygen,
    ml_kem512_keygen_with_rbg, ml_kem768_decaps, ml_kem768_encaps, ml_kem768_keygen,
    ml_kem1024_decaps, ml_kem1024_encaps, ml_kem1024_keygen,
};

use mlrust_core::sampling::random::{RandomByteGenerator, RandomError};

struct FailingRbg;

impl RandomByteGenerator for FailingRbg {
    fn fill_bytes(&mut self, _output: &mut [u8]) -> Result<(), RandomError> {
        Err(RandomError::GeneratorFailure)
    }
}

struct RepeatingRbg {
    byte: u8,
}

impl RandomByteGenerator for RepeatingRbg {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), RandomError> {
        output.fill(self.byte);
        self.byte = self.byte.wrapping_add(1);

        Ok(())
    }
}

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
