use super::internal::{compute_t_hat, expand_a_hat, sample_error_vector, sample_secret_vector};

use crate::keys::{
    Ciphertext, KpkeDecryptionKey, KpkeEncryptionKey, KpkeInternalKeypair, KpkeKeypair,
};
use crate::kpke::kpke::*;

use crate::test_utils::{hex_array, hex_field, hex_field_nth};

use mlrust_core::encode::ml_kem::{
    byte_decode_poly_q3329, byte_decode_polyvec_q3329, byte_encode_poly_q3329,
    byte_encode_polyvec_q3329,
};
use mlrust_core::params::{Q3329, RingParams};
use mlrust_core::poly::{Poly, PolyMat};
use mlrust_core::symmetric::ml_kem::g;

use alloc::vec::Vec;
use alloc::vec;

// -----------------------------------------------------
// Parameter-set wrappers
// -----------------------------------------------------

/// Generates a serialized K-PKE keypair for ML-KEM-512.
#[must_use]
pub(crate) fn kpke_keygen512(d: &[u8; 32]) -> KpkeKeypair<800, 768> {
    kpke_keygen::<2, 800, 768, 3>(d)
}

/// Generates a serialized K-PKE keypair for ML-KEM-768.
#[must_use]
pub(crate) fn kpke_keygen768(d: &[u8; 32]) -> KpkeKeypair<1184, 1152> {
    kpke_keygen::<3, 1184, 1152, 2>(d)
}

/// Generates a serialized K-PKE keypair for ML-KEM-1024.
#[must_use]
pub(crate) fn kpke_keygen1024(d: &[u8; 32]) -> KpkeKeypair<1568, 1536> {
    kpke_keygen::<4, 1568, 1536, 2>(d)
}

/// Encrypts using the K-PKE parameters underlying ML-KEM-512.
#[must_use]
pub(crate) fn kpke_encrypt512(
    ek: &KpkeEncryptionKey<800>,
    message: &[u8; 32],
    randomness: &[u8; 32],
) -> Ciphertext<768> {
    kpke_encrypt::<2, 800, 768, 3, 2, 10, 4>(ek, message, randomness)
}

/// Encrypts using the K-PKE parameters underlying ML-KEM-768.
#[must_use]
pub(crate) fn kpke_encrypt768(
    ek: &KpkeEncryptionKey<1184>,
    message: &[u8; 32],
    randomness: &[u8; 32],
) -> Ciphertext<1088> {
    kpke_encrypt::<3, 1184, 1088, 2, 2, 10, 4>(ek, message, randomness)
}

/// Encrypts using the K-PKE parameters underlying ML-KEM-1024.
#[must_use]
pub(crate) fn kpke_encrypt1024(
    ek: &KpkeEncryptionKey<1568>,
    message: &[u8; 32],
    randomness: &[u8; 32],
) -> Ciphertext<1568> {
    kpke_encrypt::<4, 1568, 1568, 2, 2, 11, 5>(ek, message, randomness)
}

/// Decrypts using the K-PKE parameters underlying ML-KEM-512.
#[must_use]
pub(crate) fn kpke_decrypt512(
    dk: &KpkeDecryptionKey<768>,
    ciphertext: &Ciphertext<768>,
) -> [u8; 32] {
    kpke_decrypt::<2, 768, 768, 10, 4>(dk, ciphertext)
}

/// Decrypts using the K-PKE parameters underlying ML-KEM-768.
#[must_use]
pub(crate) fn kpke_decrypt768(
    dk: &KpkeDecryptionKey<1152>,
    ciphertext: &Ciphertext<1088>,
) -> [u8; 32] {
    kpke_decrypt::<3, 1152, 1088, 10, 4>(dk, ciphertext)
}

/// Decrypts using the K-PKE parameters underlying ML-KEM-1024.
#[must_use]
pub(crate) fn kpke_decrypt1024(
    dk: &KpkeDecryptionKey<1536>,
    ciphertext: &Ciphertext<1568>,
) -> [u8; 32] {
    kpke_decrypt::<4, 1536, 1568, 11, 5>(dk, ciphertext)
}

#[test]
fn derive_k_pke_keygen_seeds_is_deterministic() {
    let d = [0x42u8; 32];

    let a = derive_k_pke_keygen_seeds(&d, 2);
    let b = derive_k_pke_keygen_seeds(&d, 2);

    assert_eq!(a, b);
}

#[test]
fn derive_k_pke_keygen_seeds_depends_on_k() {
    let d = [0x42u8; 32];

    let k2 = derive_k_pke_keygen_seeds(&d, 2);
    let k3 = derive_k_pke_keygen_seeds(&d, 3);

    assert_ne!(k2, k3);
}

#[test]
fn kpke_keygen_internal_is_deterministic() {
    let d = [0x13u8; 32];

    let a = kpke_keygen_internal::<2, 3>(&d);
    let b = kpke_keygen_internal::<2, 3>(&d);

    assert!(a == b);
}

#[test]
fn kpke_keygen_internal_changes_with_seed() {
    let d0 = [0x13u8; 32];
    let d1 = [0x14u8; 32];

    let a = kpke_keygen_internal::<2, 3>(&d0);
    let b = kpke_keygen_internal::<2, 3>(&d1);

    assert!(a != b);
}

#[test]
fn kpke_keygen512_is_deterministic() {
    let d = [0x42u8; 32];

    let a = kpke_keygen512(&d);
    let b = kpke_keygen512(&d);

    assert!(a == b);
}

#[test]
fn kpke_keygen512_changes_with_seed() {
    let d0 = [0x42u8; 32];
    let d1 = [0x43u8; 32];

    let a = kpke_keygen512(&d0);
    let b = kpke_keygen512(&d1);

    assert!(a != b);
}

#[test]
fn kpke_keygen512_outputs_expected_lengths() {
    let d = [0x42u8; 32];

    let kp = kpke_keygen512(&d);

    assert_eq!(kp.ek_pke.as_bytes().len(), 800);
    assert_eq!(kp.dk_pke.as_bytes().len(), 768);
}

#[test]
fn kpke_keygen768_outputs_expected_lengths() {
    let d = [0x42u8; 32];

    let kp = kpke_keygen768(&d);

    assert_eq!(kp.ek_pke.as_bytes().len(), 1184);
    assert_eq!(kp.dk_pke.as_bytes().len(), 1152);
}

#[test]
fn kpke_keygen1024_outputs_expected_lengths() {
    let d = [0x42u8; 32];

    let kp = kpke_keygen1024(&d);

    assert_eq!(kp.ek_pke.as_bytes().len(), 1568);
    assert_eq!(kp.dk_pke.as_bytes().len(), 1536);
}

#[test]
fn message_to_mu_maps_zero_message_to_zero_poly() {
    let message = [0u8; 32];

    let mu = message_to_mu(&message);

    assert!(mu.coeffs().iter().all(|&c| c == 0));
}

#[test]
fn message_to_mu_maps_all_one_bits_to_round_q_over_2() {
    let message = [0xffu8; 32];

    let mu = message_to_mu(&message);

    let expected = 1665;

    assert!(
        mu.coeffs().iter().all(|&c| c == expected),
        "expected every coefficient to be {expected}"
    );
}

#[test]
fn message_to_mu_uses_little_endian_bit_order() {
    let mut message = [0u8; 32];

    message[0] = 0b0000_0101;

    let mu = message_to_mu(&message);

    assert_eq!(mu.coeffs()[0], 1665);
    assert_eq!(mu.coeffs()[1], 0);
    assert_eq!(mu.coeffs()[2], 1665);
    assert_eq!(mu.coeffs()[3], 0);

    for i in 4..256 {
        assert_eq!(mu.coeffs()[i], 0);
    }
}

#[test]
fn kpke_encrypt512_is_deterministic_for_fixed_inputs() {
    let d = [0x42u8; 32];
    let message = [0x13u8; 32];
    let randomness = [0x99u8; 32];

    let kp = kpke_keygen512(&d);

    let c0 = kpke_encrypt512(&kp.ek_pke, &message, &randomness);
    let c1 = kpke_encrypt512(&kp.ek_pke, &message, &randomness);

    assert_eq!(c0.as_bytes(), c1.as_bytes());
}

#[test]
fn kpke_encrypt512_changes_with_message() {
    let d = [0x42u8; 32];
    let randomness = [0x99u8; 32];

    let m0 = [0x00u8; 32];
    let m1 = [0x01u8; 32];

    let kp = kpke_keygen512(&d);

    let c0 = kpke_encrypt512(&kp.ek_pke, &m0, &randomness);
    let c1 = kpke_encrypt512(&kp.ek_pke, &m1, &randomness);

    assert_ne!(c0.as_bytes(), c1.as_bytes());
}

#[test]
fn kpke_encrypt512_changes_with_randomness() {
    let d = [0x42u8; 32];
    let message = [0x13u8; 32];

    let r0 = [0x99u8; 32];
    let r1 = [0x9au8; 32];

    let kp = kpke_keygen512(&d);

    let c0 = kpke_encrypt512(&kp.ek_pke, &message, &r0);
    let c1 = kpke_encrypt512(&kp.ek_pke, &message, &r1);

    assert_ne!(c0.as_bytes(), c1.as_bytes());
}

#[test]
fn kpke_encrypt512_outputs_expected_length() {
    let d = [0x42u8; 32];
    let message = [0x13u8; 32];
    let randomness = [0x99u8; 32];

    let kp = kpke_keygen512(&d);

    let c = kpke_encrypt512(&kp.ek_pke, &message, &randomness);

    assert_eq!(c.as_bytes().len(), 768);
}

#[test]
fn kpke_encrypt768_outputs_expected_length() {
    let d = [0x42u8; 32];
    let message = [0x13u8; 32];
    let randomness = [0x99u8; 32];

    let kp = kpke_keygen768(&d);

    let c = kpke_encrypt768(&kp.ek_pke, &message, &randomness);

    assert_eq!(c.as_bytes().len(), 1088);
}

#[test]
fn kpke_encrypt1024_outputs_expected_length() {
    let d = [0x42u8; 32];
    let message = [0x13u8; 32];
    let randomness = [0x99u8; 32];

    let kp = kpke_keygen1024(&d);

    let c = kpke_encrypt1024(&kp.ek_pke, &message, &randomness);

    assert_eq!(c.as_bytes().len(), 1568);
}

#[test]
fn kpke_encrypt512_ciphertext_components_decode_with_expected_widths() {
    let d = [0x42u8; 32];
    let message = [0x13u8; 32];
    let randomness = [0x99u8; 32];

    let kp = kpke_keygen512(&d);
    let c = kpke_encrypt512(&kp.ek_pke, &message, &randomness);
    let bytes = c.as_bytes();

    let c1_len = 32 * 10 * 2;
    let c2_len = 32 * 4;

    assert_eq!(bytes.len(), c1_len + c2_len);

    let u_compressed = byte_decode_polyvec_q3329::<2, 10>(&bytes[..c1_len]);
    let v_compressed = byte_decode_poly_q3329::<4>(&bytes[c1_len..]);

    for poly in u_compressed.polys() {
        for &coeff in poly.coeffs() {
            assert!(
                (0..(1 << 10)).contains(&coeff),
                "u compressed coefficient out of range: {coeff}"
            );
        }
    }

    for &coeff in v_compressed.coeffs() {
        assert!(
            (0..(1 << 4)).contains(&coeff),
            "v compressed coefficient out of range: {coeff}"
        );
    }
}

#[test]
fn mu_to_message_inverts_message_to_mu_for_zero_message() {
    let message = [0u8; 32];

    let mu = message_to_mu(&message);
    let recovered = mu_to_message(&mu);

    assert_eq!(recovered, message);
}

#[test]
fn mu_to_message_inverts_message_to_mu_for_all_ones_message() {
    let message = [0xffu8; 32];

    let mu = message_to_mu(&message);
    let recovered = mu_to_message(&mu);

    assert_eq!(recovered, message);
}

#[test]
fn mu_to_message_inverts_message_to_mu_for_patterned_message() {
    let mut message = [0u8; 32];

    for (i, byte) in message.iter_mut().enumerate() {
        *byte = (17 * i + 91) as u8;
    }

    let mu = message_to_mu(&message);
    let recovered = mu_to_message(&mu);

    assert_eq!(recovered, message);
}

#[test]
fn kpke_decrypt512_recovers_encrypted_message() {
    let d = [0x42u8; 32];
    let randomness = [0x99u8; 32];

    let mut message = [0u8; 32];
    for (i, byte) in message.iter_mut().enumerate() {
        *byte = (11 * i + 7) as u8;
    }

    let kp = kpke_keygen512(&d);
    let c = kpke_encrypt512(&kp.ek_pke, &message, &randomness);
    let recovered = kpke_decrypt512(&kp.dk_pke, &c);

    assert_eq!(recovered, message);
}

#[test]
fn kpke_decrypt768_recovers_encrypted_message() {
    let d = [0x42u8; 32];
    let randomness = [0x99u8; 32];

    let mut message = [0u8; 32];
    for (i, byte) in message.iter_mut().enumerate() {
        *byte = (13 * i + 3) as u8;
    }

    let kp = kpke_keygen768(&d);
    let c = kpke_encrypt768(&kp.ek_pke, &message, &randomness);
    let recovered = kpke_decrypt768(&kp.dk_pke, &c);

    assert_eq!(recovered, message);
}

#[test]
fn kpke_decrypt1024_recovers_encrypted_message() {
    let d = [0x42u8; 32];
    let randomness = [0x99u8; 32];

    let mut message = [0u8; 32];
    for (i, byte) in message.iter_mut().enumerate() {
        *byte = (19 * i + 5) as u8;
    }

    let kp = kpke_keygen1024(&d);
    let c = kpke_encrypt1024(&kp.ek_pke, &message, &randomness);
    let recovered = kpke_decrypt1024(&kp.dk_pke, &c);

    assert_eq!(recovered, message);
}

#[test]
fn kpke_decrypt512_recovers_zero_message() {
    let d = [0x42u8; 32];
    let message = [0u8; 32];
    let randomness = [0x99u8; 32];

    let kp = kpke_keygen512(&d);
    let c = kpke_encrypt512(&kp.ek_pke, &message, &randomness);
    let recovered = kpke_decrypt512(&kp.dk_pke, &c);

    assert_eq!(recovered, message);
}

#[test]
fn kpke_decrypt512_recovers_all_ones_message() {
    let d = [0x42u8; 32];
    let message = [0xffu8; 32];
    let randomness = [0x99u8; 32];

    let kp = kpke_keygen512(&d);
    let c = kpke_encrypt512(&kp.ek_pke, &message, &randomness);
    let recovered = kpke_decrypt512(&kp.dk_pke, &c);

    assert_eq!(recovered, message);
}

#[test]
fn kpke_decrypt512_works_for_different_randomness_values() {
    let d = [0x42u8; 32];

    let mut message = [0u8; 32];
    for (i, byte) in message.iter_mut().enumerate() {
        *byte = (23 * i + 1) as u8;
    }

    let r0 = [0x11u8; 32];
    let r1 = [0x22u8; 32];

    let kp = kpke_keygen512(&d);

    let c0 = kpke_encrypt512(&kp.ek_pke, &message, &r0);
    let c1 = kpke_encrypt512(&kp.ek_pke, &message, &r1);

    assert_ne!(c0.as_bytes(), c1.as_bytes());

    let recovered0 = kpke_decrypt512(&kp.dk_pke, &c0);
    let recovered1 = kpke_decrypt512(&kp.dk_pke, &c1);

    assert_eq!(recovered0, message);
    assert_eq!(recovered1, message);
}

#[test]
fn kpke_encrypt_decrypt512_is_deterministic_for_fixed_inputs() {
    let d = [0x13u8; 32];
    let message = [0x37u8; 32];
    let randomness = [0x59u8; 32];

    let kp = kpke_keygen512(&d);

    let c0 = kpke_encrypt512(&kp.ek_pke, &message, &randomness);
    let c1 = kpke_encrypt512(&kp.ek_pke, &message, &randomness);

    assert_eq!(c0.as_bytes(), c1.as_bytes());

    let recovered = kpke_decrypt512(&kp.dk_pke, &c0);

    assert_eq!(recovered, message);
}

// ---------------------------------------------------------------
// Comparing results with CCTV/ML-KEM/intermediate, available at
//
// https://github.com/C2SP/CCTV/tree/main/ML-KEM/intermediate
//
// ---------------------------------------------------------------

const CCTV_POLY_ENCODED_BYTES: usize = 384;

/// CCTV intermediate vectors use the legacy derivation:
///
/// ```text
/// G(d)
/// ```
///
/// instead of the final FIPS-style derivation:
///
/// ```text
/// G(d || k)
/// ```
///
/// This helper is test-only and must not replace the production derivation.
#[must_use]
fn derive_kpke_keygen_seeds_cctv_legacy(d: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];

    g(d, &mut rho, &mut sigma);

    (rho, sigma)
}

/// CCTV-compatible algebraic K-PKE key generation.
///
/// This differs from production key generation only in the seed derivation:
/// it uses `G(d)` instead of `G(d || k)`.
#[must_use]
fn kpke_keygen_internal_cctv_legacy<const K: usize, const ETA1: usize>(
    d: &[u8; 32],
) -> KpkeInternalKeypair<K> {
    let (rho, sigma) = derive_kpke_keygen_seeds_cctv_legacy(d);

    let a_hat = expand_a_hat::<K>(&rho);

    let mut s_hat = sample_secret_vector::<K, ETA1>(&sigma, 0);
    let mut e_hat = sample_error_vector::<K, ETA1>(&sigma, K as u8);

    s_hat.ntt();
    e_hat.ntt();

    let t_hat = compute_t_hat::<K>(&a_hat, &s_hat, &e_hat);

    KpkeInternalKeypair { rho, s_hat, t_hat }
}

/// CCTV-compatible serialized K-PKE key generation.
///
/// This is a test-only adapter for the CCTV intermediate vectors.
#[must_use]
fn kpke_keygen_cctv_legacy<
    const K: usize,
    const EK_PKE_BYTES: usize,
    const DK_PKE_BYTES: usize,
    const ETA1: usize,
>(
    d: &[u8; 32],
) -> KpkeKeypair<EK_PKE_BYTES, DK_PKE_BYTES> {
    assert_eq!(EK_PKE_BYTES, K * CCTV_POLY_ENCODED_BYTES + 32);
    assert_eq!(DK_PKE_BYTES, K * CCTV_POLY_ENCODED_BYTES);

    let internal_key = kpke_keygen_internal_cctv_legacy::<K, ETA1>(d);

    let t_hat = internal_key.t_hat.coeffs_from_montgomery();
    let s_hat = internal_key.s_hat.coeffs_from_montgomery();

    let mut encaps_key = [0u8; EK_PKE_BYTES];
    let mut decaps_key = [0u8; DK_PKE_BYTES];

    byte_encode_polyvec_q3329::<K, 12>(&t_hat, &mut encaps_key[..K * CCTV_POLY_ENCODED_BYTES]);

    encaps_key[K * CCTV_POLY_ENCODED_BYTES..].copy_from_slice(&internal_key.rho);

    byte_encode_polyvec_q3329::<K, 12>(&s_hat, &mut decaps_key);

    let ek_pke = KpkeEncryptionKey::from_bytes(encaps_key);
    let dk_pke = KpkeDecryptionKey::from_bytes(decaps_key);

    KpkeKeypair { ek_pke, dk_pke }
}

#[must_use]
fn kpke_keygen512_cctv_legacy(d: &[u8; 32]) -> KpkeKeypair<800, 768> {
    kpke_keygen_cctv_legacy::<2, 800, 768, 3>(d)
}

#[must_use]
fn kpke_keygen768_cctv_legacy(d: &[u8; 32]) -> KpkeKeypair<1184, 1152> {
    kpke_keygen_cctv_legacy::<3, 1184, 1152, 2>(d)
}

#[must_use]
fn kpke_keygen1024_cctv_legacy(d: &[u8; 32]) -> KpkeKeypair<1568, 1536> {
    kpke_keygen_cctv_legacy::<4, 1568, 1536, 2>(d)
}

fn poly_coeffs_from_montgomery(poly: &Poly<Q3329>) -> Poly<Q3329> {
    let mut coeffs = *poly.coeffs();

    for coeff in coeffs.iter_mut() {
        *coeff = Q3329::freeze(Q3329::from_montgomery(*coeff));
    }

    Poly::<Q3329>::from_coeffs(coeffs)
}

fn byte_encode_poly_q3329_from_montgomery(poly: &Poly<Q3329>) -> [u8; 384] {
    let poly = poly_coeffs_from_montgomery(poly);

    let mut out = [0u8; 384];
    byte_encode_poly_q3329::<12>(&poly, &mut out);

    out
}

fn byte_encode_polymat_q3329_from_montgomery<const K: usize>(
    mat: &PolyMat<Q3329, K, K>,
) -> Vec<u8> {
    let mut out = vec![0u8; K * K * 384];

    for i in 0..K {
        for j in 0..K {
            let start = (i * K + j) * 384;
            let end = start + 384;

            let poly = mat.get(i, j).expect("matrix entry exists");
            let encoded = byte_encode_poly_q3329_from_montgomery(poly);

            out[start..end].copy_from_slice(&encoded);
        }
    }

    out
}

#[test]
fn cctv_kpke512_rho_sigma_match_legacy_derivation() {
    const V: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/cctv/intermediate/ML-KEM-512.txt"
    ));

    let d = hex_array::<32>(hex_field(V, "d"));
    let expected_rho = hex_array::<32>(hex_field(V, "ρ"));
    let expected_sigma = hex_array::<32>(hex_field(V, "σ"));

    let (rho, sigma) = derive_kpke_keygen_seeds_cctv_legacy(&d);

    assert_eq!(rho, expected_rho, "rho mismatch");
    assert_eq!(sigma, expected_sigma, "sigma mismatch");
}

#[test]
fn cctv_kpke512_a_00_matches_legacy_derivation() {
    const V: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/cctv/intermediate/ML-KEM-512.txt"
    ));

    let d = hex_array::<32>(hex_field(V, "d"));
    let expected_a00 = hex_array::<384>(hex_field(V, "A[0, 0]"));

    let (rho, _) = derive_kpke_keygen_seeds_cctv_legacy(&d);
    let a_hat = expand_a_hat::<2>(&rho);

    let got = byte_encode_poly_q3329_from_montgomery(a_hat.get(0, 0).expect("A[0,0] exists"));

    assert_eq!(got, expected_a00);
}

#[test]
fn cctv_kpke512_a_matrix_matches_legacy_derivation() {
    const V: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/cctv/intermediate/ML-KEM-512.txt"
    ));

    let d = hex_array::<32>(hex_field(V, "d"));
    let expected_a = hex::decode(hex_field(V, "A")).expect("valid A hex");

    assert_eq!(expected_a.len(), 2 * 2 * 384);

    let (rho, _) = derive_kpke_keygen_seeds_cctv_legacy(&d);
    let a_hat = expand_a_hat::<2>(&rho);

    let got = byte_encode_polymat_q3329_from_montgomery::<2>(&a_hat);

    assert_eq!(got, expected_a);
}

#[test]
fn cctv_kpke_keygen512_matches_intermediate_vector_legacy_derivation() {
    const V: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/cctv/intermediate/ML-KEM-512.txt"
    ));

    let d = hex_array::<32>(hex_field(V, "d"));
    let expected_ek = hex_array::<800>(hex_field(V, "ek"));
    let expected_dk_pke = hex_array::<768>(hex_field(V, "dkPKE"));

    let kp = kpke_keygen512_cctv_legacy(&d);

    assert_eq!(kp.ek_pke.as_bytes(), &expected_ek);
    assert_eq!(kp.dk_pke.as_bytes(), &expected_dk_pke);
}

#[test]
fn cctv_kpke_keygen768_matches_intermediate_vector_legacy_derivation() {
    const V: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/cctv/intermediate/ML-KEM-768.txt"
    ));

    let d = hex_array::<32>(hex_field(V, "d"));
    let expected_ek = hex_array::<1184>(hex_field(V, "ek"));
    let expected_dk_pke = hex_array::<1152>(hex_field(V, "dkPKE"));

    let kp = kpke_keygen768_cctv_legacy(&d);

    assert_eq!(kp.ek_pke.as_bytes(), &expected_ek);
    assert_eq!(kp.dk_pke.as_bytes(), &expected_dk_pke);
}

#[test]
fn cctv_kpke_keygen1024_matches_intermediate_vector_legacy_derivation() {
    const V: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/cctv/intermediate/ML-KEM-1024.txt"
    ));

    let d = hex_array::<32>(hex_field(V, "d"));
    let expected_ek = hex_array::<1568>(hex_field(V, "ek"));
    let expected_dk_pke = hex_array::<1536>(hex_field(V, "dkPKE"));

    let kp = kpke_keygen1024_cctv_legacy(&d);

    assert_eq!(kp.ek_pke.as_bytes(), &expected_ek);
    assert_eq!(kp.dk_pke.as_bytes(), &expected_dk_pke);
}

#[test]
fn cctv_kpke_encrypt512_matches_intermediate_vector() {
    const V: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/cctv/intermediate/ML-KEM-512.txt"
    ));

    let ek = hex_array::<800>(hex_field(V, "ek"));
    let message = hex_array::<32>(hex_field(V, "m"));
    let randomness = hex_array::<32>(hex_field_nth(V, "r", 0));
    let expected_ciphertext = hex_array::<768>(hex_field(V, "c"));

    let ek = KpkeEncryptionKey::<800>::from_bytes(ek);
    let ciphertext = kpke_encrypt512(&ek, &message, &randomness);

    assert_eq!(ciphertext.as_bytes(), &expected_ciphertext);
}

#[test]
fn cctv_kpke_encrypt768_matches_intermediate_vector() {
    const V: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/cctv/intermediate/ML-KEM-768.txt"
    ));

    let ek = hex_array::<1184>(hex_field(V, "ek"));
    let message = hex_array::<32>(hex_field(V, "m"));
    let randomness = hex_array::<32>(hex_field_nth(V, "r", 0));
    let expected_ciphertext = hex_array::<1088>(hex_field(V, "c"));

    let ek = KpkeEncryptionKey::<1184>::from_bytes(ek);
    let ciphertext = kpke_encrypt768(&ek, &message, &randomness);

    assert_eq!(ciphertext.as_bytes(), &expected_ciphertext);
}

#[test]
fn cctv_kpke_encrypt1024_matches_intermediate_vector() {
    const V: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/cctv/intermediate/ML-KEM-1024.txt"
    ));

    let ek = hex_array::<1568>(hex_field(V, "ek"));
    let message = hex_array::<32>(hex_field(V, "m"));
    let randomness = hex_array::<32>(hex_field_nth(V, "r", 0));
    let expected_ciphertext = hex_array::<1568>(hex_field(V, "c"));

    let ek = KpkeEncryptionKey::<1568>::from_bytes(ek);
    let ciphertext = kpke_encrypt1024(&ek, &message, &randomness);

    assert_eq!(ciphertext.as_bytes(), &expected_ciphertext);
}

#[test]
fn cctv_kpke_decrypt512_matches_intermediate_vector() {
    const V: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/cctv/intermediate/ML-KEM-512.txt"
    ));

    let dk_pke = hex_array::<768>(hex_field(V, "dkPKE"));
    let ciphertext = hex_array::<768>(hex_field(V, "c"));
    let expected_message = hex_array::<32>(hex_field(V, "m"));

    let dk_pke = KpkeDecryptionKey::<768>::from_bytes(dk_pke);
    let ciphertext = Ciphertext::<768>::from_bytes(ciphertext);

    let message = kpke_decrypt512(&dk_pke, &ciphertext);

    assert_eq!(message, expected_message);
}

#[test]
fn cctv_kpke_decrypt768_matches_intermediate_vector() {
    const V: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/cctv/intermediate/ML-KEM-768.txt"
    ));

    let dk_pke = hex_array::<1152>(hex_field(V, "dkPKE"));
    let ciphertext = hex_array::<1088>(hex_field(V, "c"));
    let expected_message = hex_array::<32>(hex_field(V, "m"));

    let dk_pke = KpkeDecryptionKey::<1152>::from_bytes(dk_pke);
    let ciphertext = Ciphertext::<1088>::from_bytes(ciphertext);

    let message = kpke_decrypt768(&dk_pke, &ciphertext);

    assert_eq!(message, expected_message);
}

#[test]
fn cctv_kpke_decrypt1024_matches_intermediate_vector() {
    const V: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/cctv/intermediate/ML-KEM-1024.txt"
    ));

    let dk_pke = hex_array::<1536>(hex_field(V, "dkPKE"));
    let ciphertext = hex_array::<1568>(hex_field(V, "c"));
    let expected_message = hex_array::<32>(hex_field(V, "m"));

    let dk_pke = KpkeDecryptionKey::<1536>::from_bytes(dk_pke);
    let ciphertext = Ciphertext::<1568>::from_bytes(ciphertext);

    let message = kpke_decrypt1024(&dk_pke, &ciphertext);

    assert_eq!(message, expected_message);
}

#[test]
fn cctv_kpke512_keygen_encrypt_decrypt_match_intermediate_vector() {
    const V: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/cctv/intermediate/ML-KEM-512.txt"
    ));

    let d = hex_array::<32>(hex_field(V, "d"));
    let message = hex_array::<32>(hex_field(V, "m"));
    let randomness = hex_array::<32>(hex_field_nth(V, "r", 0));

    let expected_ek = hex_array::<800>(hex_field(V, "ek"));
    let expected_dk_pke = hex_array::<768>(hex_field(V, "dkPKE"));
    let expected_ciphertext = hex_array::<768>(hex_field(V, "c"));

    let kp = kpke_keygen512_cctv_legacy(&d);

    assert_eq!(kp.ek_pke.as_bytes(), &expected_ek);
    assert_eq!(kp.dk_pke.as_bytes(), &expected_dk_pke);

    let ciphertext = kpke_encrypt512(&kp.ek_pke, &message, &randomness);

    assert_eq!(ciphertext.as_bytes(), &expected_ciphertext);

    let recovered = kpke_decrypt512(&kp.dk_pke, &ciphertext);

    assert_eq!(recovered, message);
}
