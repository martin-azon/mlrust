use super::internal::{ml_kem_decaps_internal, ml_kem_encaps_internal, ml_kem_keygen_internal};

use crate::keys::{
    Ciphertext, DecapsulationKey, EncapsulationKey, KpkeDecryptionKey, KpkeEncryptionKey,
    KpkeKeypair, MlKemKeypair,
};

use crate::kpke::internal::{
    compute_t_hat, expand_a_hat, sample_error_vector, sample_secret_vector,
};

use crate::test_utils::{hex_array, hex_field, hex_field_any};

use mlrust_core::encode::ml_kem::byte_encode_polyvec_q3329;
use mlrust_core::symmetric::ml_kem::{g, h, j_concat};

const POLY_ENCODED_BYTES: usize = 384;

fn pattern32(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];

    for (i, byte) in out.iter_mut().enumerate() {
        *byte = seed.wrapping_add((17 * i) as u8);
    }

    out
}

fn assert_keygen_layout<
    const K: usize,
    const EK_BYTES: usize,
    const EK_PKE_BYTES: usize,
    const DK_BYTES: usize,
    const DK_PKE_BYTES: usize,
    const ETA1: usize,
>() {
    assert_eq!(EK_BYTES, EK_PKE_BYTES);

    let d = pattern32(0x11);
    let z = pattern32(0x73);

    let kp =
        ml_kem_keygen_internal::<K, EK_BYTES, EK_PKE_BYTES, DK_BYTES, DK_PKE_BYTES, ETA1>(&d, &z);

    assert_eq!(kp.encapsulation_key().as_bytes().len(), EK_BYTES);
    assert_eq!(kp.decapsulation_key().as_bytes().len(), DK_BYTES);

    let ek = kp.encapsulation_key().as_bytes();
    let dk = kp.decapsulation_key().as_bytes();

    assert_eq!(
        &dk[DK_PKE_BYTES..(DK_PKE_BYTES + EK_BYTES)],
        ek,
        "dk must contain ek after dk_pke",
    );

    let mut expected_h = [0u8; 32];
    h(ek, &mut expected_h);

    assert_eq!(
        &dk[(DK_PKE_BYTES + EK_BYTES)..(DK_PKE_BYTES + EK_BYTES + 32)],
        &expected_h,
        "dk must contain H(ek)",
    );

    assert_eq!(
        &dk[(DK_PKE_BYTES + EK_BYTES + 32)..],
        &z,
        "dk must end with z",
    );
}

fn assert_encaps_decaps_roundtrip<
    const K: usize,
    const EK_BYTES: usize,
    const EK_PKE_BYTES: usize,
    const DK_BYTES: usize,
    const DK_PKE_BYTES: usize,
    const CT_BYTES: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>() {
    assert_eq!(EK_BYTES, EK_PKE_BYTES);

    let d = pattern32(0x21);
    let z = pattern32(0x42);
    let m = pattern32(0x99);

    let kp =
        ml_kem_keygen_internal::<K, EK_BYTES, EK_PKE_BYTES, DK_BYTES, DK_PKE_BYTES, ETA1>(&d, &z);

    let (ss_enc, ciphertext) = ml_kem_encaps_internal::<K, EK_BYTES, CT_BYTES, ETA1, ETA2, DU, DV>(
        kp.encapsulation_key(),
        &m,
    );

    let ss_dec = ml_kem_decaps_internal::<
        K,
        DK_BYTES,
        EK_PKE_BYTES,
        DK_PKE_BYTES,
        CT_BYTES,
        ETA1,
        ETA2,
        DU,
        DV,
    >(&kp.decapsulation_key().clone(), &ciphertext.clone());

    assert_eq!(ss_dec.as_bytes(), ss_enc.as_bytes());
}

fn assert_tampered_ciphertext_uses_fallback<
    const K: usize,
    const EK_BYTES: usize,
    const EK_PKE_BYTES: usize,
    const DK_BYTES: usize,
    const DK_PKE_BYTES: usize,
    const CT_BYTES: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>() {
    assert_eq!(EK_BYTES, EK_PKE_BYTES);

    let d = pattern32(0x31);
    let z = pattern32(0x56);
    let m = pattern32(0xa7);

    let kp =
        ml_kem_keygen_internal::<K, EK_BYTES, EK_PKE_BYTES, DK_BYTES, DK_PKE_BYTES, ETA1>(&d, &z);

    let (_ss_enc, ciphertext) = ml_kem_encaps_internal::<K, EK_BYTES, CT_BYTES, ETA1, ETA2, DU, DV>(
        kp.encapsulation_key(),
        &m,
    );

    let mut tampered_bytes = ciphertext.into_bytes();
    tampered_bytes[0] ^= 0x01;

    let tampered_ciphertext = Ciphertext::<CT_BYTES>::from_bytes(tampered_bytes);

    let mut expected_fallback = [0u8; 32];
    j_concat(&z, tampered_ciphertext.as_bytes(), &mut expected_fallback);

    let ss_dec = ml_kem_decaps_internal::<
        K,
        DK_BYTES,
        EK_PKE_BYTES,
        DK_PKE_BYTES,
        CT_BYTES,
        ETA1,
        ETA2,
        DU,
        DV,
    >(kp.decapsulation_key(), &tampered_ciphertext);

    assert_eq!(
        ss_dec.as_bytes(),
        &expected_fallback,
        "decapsulation of invalid ciphertext must return J(z || c)",
    );
}

#[test]
fn ml_kem512_keygen_layout_is_correct() {
    assert_keygen_layout::<2, 800, 800, 1632, 768, 3>();
}

#[test]
fn ml_kem768_keygen_layout_is_correct() {
    assert_keygen_layout::<3, 1184, 1184, 2400, 1152, 2>();
}

#[test]
fn ml_kem1024_keygen_layout_is_correct() {
    assert_keygen_layout::<4, 1568, 1568, 3168, 1536, 2>();
}

#[test]
fn ml_kem512_encaps_decaps_roundtrip() {
    assert_encaps_decaps_roundtrip::<2, 800, 800, 1632, 768, 768, 3, 2, 10, 4>();
}

#[test]
fn ml_kem768_encaps_decaps_roundtrip() {
    assert_encaps_decaps_roundtrip::<3, 1184, 1184, 2400, 1152, 1088, 2, 2, 10, 4>();
}

#[test]
fn ml_kem1024_encaps_decaps_roundtrip() {
    assert_encaps_decaps_roundtrip::<4, 1568, 1568, 3168, 1536, 1568, 2, 2, 11, 5>();
}

#[test]
fn ml_kem512_tampered_ciphertext_uses_fallback() {
    assert_tampered_ciphertext_uses_fallback::<2, 800, 800, 1632, 768, 768, 3, 2, 10, 4>();
}

#[test]
fn ml_kem768_tampered_ciphertext_uses_fallback() {
    assert_tampered_ciphertext_uses_fallback::<3, 1184, 1184, 2400, 1152, 1088, 2, 2, 10, 4>();
}

#[test]
fn ml_kem1024_tampered_ciphertext_uses_fallback() {
    assert_tampered_ciphertext_uses_fallback::<4, 1568, 1568, 3168, 1536, 1568, 2, 2, 11, 5>();
}

/// CCTV intermediate vectors use legacy K-PKE seed derivation `G(d)`.
///
/// This is intentionally test-only. Production ML-KEM keeps `G(d || k)`.
#[must_use]
fn derive_kpke_keygen_seeds_cctv_legacy(d: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];

    g(d, &mut rho, &mut sigma);

    (rho, sigma)
}

#[must_use]
fn kpke_keygen_cctv_legacy<
    const K: usize,
    const EK_BYTES: usize,
    const DK_BYTES: usize,
    const ETA1: usize,
>(
    d: &[u8; 32],
) -> KpkeKeypair<EK_BYTES, DK_BYTES> {
    assert_eq!(EK_BYTES, K * POLY_ENCODED_BYTES + 32);
    assert_eq!(DK_BYTES, K * POLY_ENCODED_BYTES);

    let (rho, sigma) = derive_kpke_keygen_seeds_cctv_legacy(d);

    let a_hat = expand_a_hat::<K>(&rho);

    let mut s_hat = sample_secret_vector::<K, ETA1>(&sigma, 0);
    let mut e_hat = sample_error_vector::<K, ETA1>(&sigma, K as u8);

    s_hat.ntt();
    e_hat.ntt();

    let t_hat = compute_t_hat::<K>(&a_hat, &s_hat, &e_hat);

    let t_hat = t_hat.coeffs_from_montgomery();
    let s_hat = s_hat.coeffs_from_montgomery();

    let mut ek_bytes = [0u8; EK_BYTES];
    let mut dk_bytes = [0u8; DK_BYTES];

    byte_encode_polyvec_q3329::<K, 12>(&t_hat, &mut ek_bytes[..K * POLY_ENCODED_BYTES]);

    ek_bytes[K * POLY_ENCODED_BYTES..].copy_from_slice(&rho);

    byte_encode_polyvec_q3329::<K, 12>(&s_hat, &mut dk_bytes);

    KpkeKeypair {
        ek_pke: KpkeEncryptionKey::<EK_BYTES>::from_bytes(ek_bytes),
        dk_pke: KpkeDecryptionKey::<DK_BYTES>::from_bytes(dk_bytes),
    }
}

#[must_use]
fn ml_kem_keygen_internal_cctv_legacy<
    const K: usize,
    const EK_BYTES: usize,
    const DK_BYTES: usize,
    const DK_PKE_BYTES: usize,
    const ETA1: usize,
>(
    d: &[u8; 32],
    z: &[u8; 32],
) -> MlKemKeypair<EK_BYTES, DK_BYTES> {
    assert_eq!(EK_BYTES, K * POLY_ENCODED_BYTES + 32);
    assert_eq!(DK_PKE_BYTES, K * POLY_ENCODED_BYTES);
    assert_eq!(DK_BYTES, DK_PKE_BYTES + EK_BYTES + 64);

    let kpke = kpke_keygen_cctv_legacy::<K, EK_BYTES, DK_PKE_BYTES, ETA1>(d);

    let ek_bytes = *kpke.ek_pke.as_bytes();

    let mut h_ek = [0u8; 32];
    h(&ek_bytes, &mut h_ek);

    let mut dk_bytes = [0u8; DK_BYTES];

    dk_bytes[..DK_PKE_BYTES].copy_from_slice(kpke.dk_pke.as_bytes());
    dk_bytes[DK_PKE_BYTES..(DK_PKE_BYTES + EK_BYTES)].copy_from_slice(&ek_bytes);
    dk_bytes[(DK_PKE_BYTES + EK_BYTES)..(DK_PKE_BYTES + EK_BYTES + 32)].copy_from_slice(&h_ek);
    dk_bytes[(DK_PKE_BYTES + EK_BYTES + 32)..].copy_from_slice(z);

    MlKemKeypair::from_parts(
        EncapsulationKey::<EK_BYTES>::from_bytes(ek_bytes),
        DecapsulationKey::<DK_BYTES>::from_bytes(dk_bytes),
    )
}

fn assert_cctv_kem_keygen<
    const K: usize,
    const EK_BYTES: usize,
    const DK_BYTES: usize,
    const DK_PKE_BYTES: usize,
    const ETA1: usize,
>(
    vector: &str,
) {
    let d = hex_array::<32>(hex_field(vector, "d"));
    let z = hex_array::<32>(hex_field(vector, "z"));

    let expected_ek = hex_array::<EK_BYTES>(hex_field(vector, "ek"));
    let expected_dk = hex_array::<DK_BYTES>(hex_field(vector, "dk"));

    let kp =
        ml_kem_keygen_internal_cctv_legacy::<K, EK_BYTES, DK_BYTES, DK_PKE_BYTES, ETA1>(&d, &z);

    assert_eq!(kp.encapsulation_key().as_bytes(), &expected_ek);
    assert_eq!(kp.decapsulation_key().as_bytes(), &expected_dk);
}

fn assert_cctv_kem_encaps<
    const K: usize,
    const EK_BYTES: usize,
    const CT_BYTES: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    vector: &str,
) {
    let ek = hex_array::<EK_BYTES>(hex_field(vector, "ek"));
    let m = hex_array::<32>(hex_field(vector, "m"));

    let expected_shared_secret =
        hex_array::<32>(hex_field_any(vector, &["K", "ss", "shared_secret"]));

    let expected_ciphertext = hex_array::<CT_BYTES>(hex_field(vector, "c"));

    let ek = EncapsulationKey::<EK_BYTES>::from_bytes(ek);

    let (shared_secret, ciphertext) =
        ml_kem_encaps_internal::<K, EK_BYTES, CT_BYTES, ETA1, ETA2, DU, DV>(&ek, &m);

    assert_eq!(shared_secret.as_bytes(), &expected_shared_secret);
    assert_eq!(ciphertext.as_bytes(), &expected_ciphertext);
}

fn assert_cctv_kem_decaps<
    const K: usize,
    const DK_BYTES: usize,
    const EK_PKE_BYTES: usize,
    const DK_PKE_BYTES: usize,
    const CT_BYTES: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    vector: &str,
) {
    let dk = hex_array::<DK_BYTES>(hex_field(vector, "dk"));
    let c = hex_array::<CT_BYTES>(hex_field(vector, "c"));

    let expected_shared_secret =
        hex_array::<32>(hex_field_any(vector, &["K", "ss", "shared_secret"]));

    let dk = DecapsulationKey::<DK_BYTES>::from_bytes(dk);
    let c = Ciphertext::<CT_BYTES>::from_bytes(c);

    let shared_secret = ml_kem_decaps_internal::<
        K,
        DK_BYTES,
        EK_PKE_BYTES,
        DK_PKE_BYTES,
        CT_BYTES,
        ETA1,
        ETA2,
        DU,
        DV,
    >(&dk, &c);

    assert_eq!(shared_secret.as_bytes(), &expected_shared_secret);
}

#[test]
fn cctv_ml_kem512_keygen_matches_intermediate_vector() {
    const V: &str = include_str!("../../tests/vectors/cctv/intermediate/ML-KEM-512.txt");

    assert_cctv_kem_keygen::<2, 800, 1632, 768, 3>(V);
}

#[test]
fn cctv_ml_kem768_keygen_matches_intermediate_vector() {
    const V: &str = include_str!("../../tests/vectors/cctv/intermediate/ML-KEM-768.txt");

    assert_cctv_kem_keygen::<3, 1184, 2400, 1152, 2>(V);
}

#[test]
fn cctv_ml_kem1024_keygen_matches_intermediate_vector() {
    const V: &str = include_str!("../../tests/vectors/cctv/intermediate/ML-KEM-1024.txt");

    assert_cctv_kem_keygen::<4, 1568, 3168, 1536, 2>(V);
}

#[test]
fn cctv_ml_kem512_encaps_matches_intermediate_vector() {
    const V: &str = include_str!("../../tests/vectors/cctv/intermediate/ML-KEM-512.txt");

    assert_cctv_kem_encaps::<2, 800, 768, 3, 2, 10, 4>(V);
}

#[test]
fn cctv_ml_kem768_encaps_matches_intermediate_vector() {
    const V: &str = include_str!("../../tests/vectors/cctv/intermediate/ML-KEM-768.txt");

    assert_cctv_kem_encaps::<3, 1184, 1088, 2, 2, 10, 4>(V);
}

#[test]
fn cctv_ml_kem1024_encaps_matches_intermediate_vector() {
    const V: &str = include_str!("../../tests/vectors/cctv/intermediate/ML-KEM-1024.txt");

    assert_cctv_kem_encaps::<4, 1568, 1568, 2, 2, 11, 5>(V);
}

#[test]
fn cctv_ml_kem512_decaps_matches_intermediate_vector() {
    const V: &str = include_str!("../../tests/vectors/cctv/intermediate/ML-KEM-512.txt");

    assert_cctv_kem_decaps::<2, 1632, 800, 768, 768, 3, 2, 10, 4>(V);
}

#[test]
fn cctv_ml_kem768_decaps_matches_intermediate_vector() {
    const V: &str = include_str!("../../tests/vectors/cctv/intermediate/ML-KEM-768.txt");

    assert_cctv_kem_decaps::<3, 2400, 1184, 1152, 1088, 2, 2, 10, 4>(V);
}

#[test]
fn cctv_ml_kem1024_decaps_matches_intermediate_vector() {
    const V: &str = include_str!("../../tests/vectors/cctv/intermediate/ML-KEM-1024.txt");

    assert_cctv_kem_decaps::<4, 3168, 1568, 1536, 1568, 2, 2, 11, 5>(V);
}
