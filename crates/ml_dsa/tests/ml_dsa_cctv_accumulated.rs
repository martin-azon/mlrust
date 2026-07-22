mod common;

use common::hex::expected_hash;
use common::rbg::FixedChunksRbg;

use ml_dsa::{
    ml_dsa44_keygen_with_rbg, ml_dsa44_sign_with_rbg, ml_dsa44_verify, ml_dsa65_keygen_with_rbg,
    ml_dsa65_sign_with_rbg, ml_dsa65_verify, ml_dsa87_keygen_with_rbg, ml_dsa87_sign_with_rbg,
    ml_dsa87_verify,
};

use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
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

        let keygen_chunks: [&[u8]; 1] = [seed.as_ref()];
        let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);
        let keypair = ml_dsa44_keygen_with_rbg(&mut keygen_rbg)
            .expect("CCTV ML-DSA-44 key generation should succeed");

        let sign_chunks: [&[u8]; 1] = [randomness.as_ref()];
        let mut sign_rbg = FixedChunksRbg::new(&sign_chunks);
        let signature =
            ml_dsa44_sign_with_rbg(keypair.secret_key(), message, context, &mut sign_rbg)
                .expect("CCTV ML-DSA-44 signing should succeed");

        let ok = ml_dsa44_verify(keypair.public_key(), message, context, &signature)
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

        let keygen_chunks: [&[u8]; 1] = [seed.as_ref()];
        let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);
        let keypair = ml_dsa65_keygen_with_rbg(&mut keygen_rbg)
            .expect("CCTV ML-DSA-65 key generation should succeed");

        let sign_chunks: [&[u8]; 1] = [randomness.as_ref()];
        let mut sign_rbg = FixedChunksRbg::new(&sign_chunks);
        let signature =
            ml_dsa65_sign_with_rbg(keypair.secret_key(), message, context, &mut sign_rbg)
                .expect("CCTV ML-DSA-65 signing should succeed");

        let ok = ml_dsa65_verify(keypair.public_key(), message, context, &signature)
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

        let keygen_chunks: [&[u8]; 1] = [seed.as_ref()];
        let mut keygen_rbg = FixedChunksRbg::new(&keygen_chunks);
        let keypair = ml_dsa87_keygen_with_rbg(&mut keygen_rbg)
            .expect("CCTV ML-DSA-87 key generation should succeed");

        let sign_chunks: [&[u8]; 1] = [randomness.as_ref()];
        let mut sign_rbg = FixedChunksRbg::new(&sign_chunks);
        let signature =
            ml_dsa87_sign_with_rbg(keypair.secret_key(), message, context, &mut sign_rbg)
                .expect("CCTV ML-DSA-87 signing should succeed");

        let ok = ml_dsa87_verify(keypair.public_key(), message, context, &signature)
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
#[ignore = "CCTV accumulated vector test"]
fn cctv_accumulated_mldsa44_100_iterations() {
    let expected = expected_hash(ML_DSA_44_VECTORS, 100);
    let actual = cctv_accumulated_mldsa44(100);

    assert_eq!(actual, expected);
}

#[test]
#[ignore = "CCTV accumulated vector test"]
fn cctv_accumulated_mldsa65_100_iterations() {
    let expected = expected_hash(ML_DSA_65_VECTORS, 100);
    let actual = cctv_accumulated_mldsa65(100);

    assert_eq!(actual, expected);
}

#[test]
#[ignore = "CCTV accumulated vector test"]
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
