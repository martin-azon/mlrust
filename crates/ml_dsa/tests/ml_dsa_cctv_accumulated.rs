mod common;

use common::expected_hash;

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
};

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

const ML_DSA_44_VECTORS: &str = include_str!("vectors/cctv/ML-DSA-44.txt");
const ML_DSA_65_VECTORS: &str = include_str!("vectors/cctv/ML-DSA-65.txt");
const ML_DSA_87_VECTORS: &str = include_str!("vectors/cctv/ML-DSA-87.txt");

fn cctv_accumulated_mldsa44(iterations: usize) -> [u8; 32] {
    let mut seed_source = Shake128::default().finalize_xof();
    let mut accumulator = Shake128::default();

    let message = b"";
    let context = b"";
    let randomness = [0u8; 32];

    for _ in 0..iterations {
        let mut seed = [0u8; 32];
        seed_source.read(&mut seed);

        let keypair = ml_dsa_keygen44_from_seed(&seed);

        let signature = ml_dsa_sign44_from_seed(
            keypair.secret_key(),
            message,
            context,
            &randomness,
        )
            .expect("CCTV ML-DSA-44 signing should succeed");

        let ok = ml_dsa_verify44(
            keypair.public_key(),
            message,
            context,
            &signature,
        )
            .expect("CCTV ML-DSA-44 verification should not error");

        assert!(ok);

        accumulator.update(keypair.public_key().as_bytes());
        accumulator.update(signature.as_bytes());
    }

    let mut out = [0u8; 32];
    let mut reader = accumulator.finalize_xof();
    reader.read(&mut out);

    out
}

fn cctv_accumulated_mldsa65(iterations: usize) -> [u8; 32] {
    let mut seed_source = Shake128::default().finalize_xof();
    let mut accumulator = Shake128::default();

    let message = b"";
    let context = b"";
    let randomness = [0u8; 32];

    for _ in 0..iterations {
        let mut seed = [0u8; 32];
        seed_source.read(&mut seed);

        let keypair = ml_dsa_keygen65_from_seed(&seed);

        let signature = ml_dsa_sign65_from_seed(
            keypair.secret_key(),
            message,
            context,
            &randomness,
        )
            .expect("CCTV ML-DSA-65 signing should succeed");

        let ok = ml_dsa_verify65(
            keypair.public_key(),
            message,
            context,
            &signature,
        )
            .expect("CCTV ML-DSA-65 verification should not error");

        assert!(ok);

        accumulator.update(keypair.public_key().as_bytes());
        accumulator.update(signature.as_bytes());
    }

    let mut out = [0u8; 32];
    let mut reader = accumulator.finalize_xof();
    reader.read(&mut out);

    out
}

fn cctv_accumulated_mldsa87(iterations: usize) -> [u8; 32] {
    let mut seed_source = Shake128::default().finalize_xof();
    let mut accumulator = Shake128::default();

    let message = b"";
    let context = b"";
    let randomness = [0u8; 32];

    for _ in 0..iterations {
        let mut seed = [0u8; 32];
        seed_source.read(&mut seed);

        let keypair = ml_dsa_keygen87_from_seed(&seed);

        let signature = ml_dsa_sign87_from_seed(
            keypair.secret_key(),
            message,
            context,
            &randomness,
        )
            .expect("CCTV ML-DSA-87 signing should succeed");

        let ok = ml_dsa_verify87(
            keypair.public_key(),
            message,
            context,
            &signature,
        )
            .expect("CCTV ML-DSA-87 verification should not error");

        assert!(ok);

        accumulator.update(keypair.public_key().as_bytes());
        accumulator.update(signature.as_bytes());
    }

    let mut out = [0u8; 32];
    let mut reader = accumulator.finalize_xof();
    reader.read(&mut out);

    out
}

#[test]
//#[ignore = "CCTV accumulated vector test; run with `cargo test -p ml_dsa cctv -- --ignored`"]
fn cctv_accumulated_mldsa44_100_iterations() {
    let expected = expected_hash(ML_DSA_44_VECTORS, 100);
    let actual = cctv_accumulated_mldsa44(100);

    assert_eq!(actual, expected);
}

#[test]
//#[ignore = "CCTV accumulated vector test; run with `cargo test -p ml_dsa cctv -- --ignored`"]
fn cctv_accumulated_mldsa65_100_iterations() {
    let expected = expected_hash(ML_DSA_65_VECTORS, 100);
    let actual = cctv_accumulated_mldsa65(100);

    assert_eq!(actual, expected);
}

#[test]
//#[ignore = "CCTV accumulated vector test; run with `cargo test -p ml_dsa cctv -- --ignored`"]
fn cctv_accumulated_mldsa87_100_iterations() {
    let expected = expected_hash(ML_DSA_87_VECTORS, 100);
    let actual = cctv_accumulated_mldsa87(100);

    assert_eq!(actual, expected);
}

#[test]
#[ignore = "long CCTV accumulated vector test"]
fn cctv_accumulated_mldsa44_10_000_iterations() {
    let expected = expected_hash(ML_DSA_44_VECTORS, 10_000);
    let actual = cctv_accumulated_mldsa44(10_000);

    assert_eq!(actual, expected);
}

#[test]
#[ignore = "long CCTV accumulated vector test"]
fn cctv_accumulated_mldsa65_10_000_iterations() {
    let expected = expected_hash(ML_DSA_65_VECTORS, 10_000);
    let actual = cctv_accumulated_mldsa65(10_000);

    assert_eq!(actual, expected);
}

#[test]
#[ignore = "long CCTV accumulated vector test"]
fn cctv_accumulated_mldsa87_10_000_iterations() {
    let expected = expected_hash(ML_DSA_87_VECTORS, 10_000);
    let actual = cctv_accumulated_mldsa87(10_000);

    assert_eq!(actual, expected);
}