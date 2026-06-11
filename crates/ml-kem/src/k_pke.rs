//! ML-KEM K-PKE algorithms.
//!
//! This module implements the deterministic public-key encryption component
//! used internally by ML-KEM.
//!
//! These routines are crate-internal. The public ML-KEM API is implemented
//! separately in the KEM layer.



use mlrust_core::params::Q3329;
use mlrust_core::poly::{Poly, PolyVec};
use mlrust_core::symmetric::ml_kem::g;
use mlrust_core::encode::ml_kem::{
    byte_decode_poly_q3329,
    byte_encode_polyvec_q3329,
    byte_decode_polyvec_q3329,
    decompress_q3329_poly,
    compress_q3329_poly,
    byte_encode_poly_q3329,
    compress_q3329_polyvec
};

use crate::internal::{
    expand_a_hat,
    compute_t_hat,
    sample_polyvec_from_prf,
    sample_error_vector,
    sample_secret_vector,
    sample_poly_from_prf,
    expand_a_hat_transposed
};

use crate::keys::{EncapsulationKey, DecapsulationKey, Ciphertext};


/// Internal algebraic K-PKE keypair before serialization.
///
/// This type is useful for testing and for separating the algebraic key
/// generation logic from FIPS byte encoding.
///
/// # Representation
///
/// Both `s_hat` and `t_hat` are in the NTT/Montgomery domain.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KpkeInternalKeypair<const K: usize> {
    pub(crate) rho: [u8; 32],
    pub(crate) s_hat: PolyVec<Q3329, K>,
    pub(crate) t_hat: PolyVec<Q3329, K>,
}


/// Serialized K-PKE keypair.
///
/// This is not the final ML-KEM keypair. In particular, `dk_pke` is the
/// serialized K-PKE secret key `ByteEncode_12(s_hat)`, whose length is
/// `384 * K`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KpkeKeypair<const EK_BYTES: usize, const DK_BYTES: usize> {
    pub(crate) ek_pke: EncapsulationKey<EK_BYTES>,
    pub(crate) dk_pke: DecapsulationKey<DK_BYTES>,
}


/// Derives the public matrix seed `rho` and secret sampling seed `sigma`.
///
/// This computes:
///
/// ```text
/// G(d || k)
/// ```
///
/// where `d` is a 32-byte seed and `k` is the ML-KEM module rank encoded as
/// one byte.
///
/// The first 32 bytes of the SHA3-512 output are `rho`; the last 32 bytes are
/// `sigma`.
#[must_use]
pub fn derive_k_pke_keygen_seeds(
    d: &[u8; 32],
    k: u8,
) -> ([u8; 32], [u8; 32]) {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(d);
    input[32] = k;

    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];

    g(&input, &mut rho, &mut sigma);
    (rho, sigma)
}


/// Generates the internal algebraic K-PKE keypair.
///
/// This implements the algebraic part of K-PKE.KeyGen before byte encoding.
///
/// # Representation
///
/// - `t_hat` is in the NTT/Montgomery domain;
/// - `s_hat` is in the NTT/Montgomery domain;
/// - `rho` is the public matrix seed.
#[must_use]
fn kpke_keygen_internal<const K: usize, const ETA1: usize>(
    d: &[u8; 32],
) -> KpkeInternalKeypair<K> {
    let (rho, sigma) = derive_k_pke_keygen_seeds(d, K as u8);

    let a_hat = expand_a_hat::<K>(&rho);

    let mut s_hat = sample_secret_vector::<K, ETA1>(&sigma, 0);
    let mut e_hat = sample_error_vector::<K, ETA1>(&sigma, K as u8);

    s_hat.ntt();
    e_hat.ntt();

    let t_hat  = compute_t_hat::<K>(&a_hat, &s_hat, &e_hat);

    KpkeInternalKeypair{
        rho,
        s_hat,
        t_hat
    }
}


/// Generates a serialized K-PKE keypair.
///
/// This returns:
///
/// ```text
/// ek_pke = ByteEncode_12(t_hat) || rho
/// dk_pke = ByteEncode_12(s_hat)
/// ```
///
/// # Panics
///
/// Panics if the provided byte-size constants do not match the K-PKE sizes:
///
/// ```text
/// EK_BYTES = 384 * K + 32
/// DK_BYTES = 384 * K
/// ```
pub fn kpke_keygen<
    const K: usize,
    const EK_BYTES: usize,
    const DK_BYTES: usize,
    const ETA1: usize
> (
    d: &[u8; 32]
) -> KpkeKeypair<EK_BYTES, DK_BYTES> {
    const POLY_ENCODED_BYTES: usize = 384;

    assert_eq!(EK_BYTES, K * POLY_ENCODED_BYTES + 32);
    assert_eq!(DK_BYTES, K * POLY_ENCODED_BYTES);

    let internal_key = kpke_keygen_internal::<K, ETA1>(d);

    let t_hat = internal_key.t_hat.coeffs_from_montgomery();
    let s_hat = internal_key.s_hat.coeffs_from_montgomery();

    let mut encaps_key = [0u8; EK_BYTES];
    let mut decaps_key = [0u8; DK_BYTES];

    byte_encode_polyvec_q3329::<K, 12>(
        &t_hat,
        &mut encaps_key[.. K * POLY_ENCODED_BYTES]
    );

    encaps_key[K * POLY_ENCODED_BYTES..].copy_from_slice(&internal_key.rho);

    byte_encode_polyvec_q3329::<K, 12>(
        &s_hat,
        &mut decaps_key
    );

    let ek_pke = EncapsulationKey::from_bytes(encaps_key);
    let dk_pke = DecapsulationKey::from_bytes(decaps_key);

    KpkeKeypair{ek_pke, dk_pke}
}


/// Computes `Decompress_1(ByteDecode_1(m))`
#[must_use]
pub(crate) fn message_to_mu(m: &[u8; 32]) -> Poly<Q3329> {
    let decoded = byte_decode_poly_q3329::<1>(m);
    decompress_q3329_poly::<1>(&decoded)
}


/// Encrypts a 32-byte message using K-PKE.
///
/// This implements the deterministic K-PKE encryption algorithm used inside
/// ML-KEM.
///
/// The input `ek` is the serialized K-PKE encapsulation key:
///
/// ```text
/// ek_pke = ByteEncode_12(t_hat) || rho
/// ```
///
/// The input `message` is a 32-byte plaintext block. The input `randomness` is
/// the 32-byte encryption randomness used to sample the ephemeral secret and
/// error terms.
///
/// The returned ciphertext is:
///
/// ```text
/// c = c1 || c2
/// ```
///
/// where:
///
/// ```text
/// c1 = ByteEncode_DU(Compress_DU(u))
/// c2 = ByteEncode_DV(Compress_DV(v))
/// ```
///
/// # Representation
///
/// The decoded `t_hat` coefficients are converted into this crate's
/// NTT/Montgomery representation before NTT-domain multiplication.
fn kpke_encrypt<
    const K: usize,
    const EK_BYTES: usize,
    const CT_BYTES: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
> (
    ek: &EncapsulationKey<EK_BYTES>,
    message: &[u8; 32],
    randomness: &[u8; 32],
) -> Ciphertext<CT_BYTES> {
    const POLY_ENCODED_BYTES: usize = 384;

    assert_eq!(EK_BYTES, K * POLY_ENCODED_BYTES + 32);
    assert_eq!(CT_BYTES, 32 * (DU * K + DV));

    let mut output = [0u8; CT_BYTES];

    let ek_bytes = ek.as_bytes();

    // Decode t_hat from ek_pke = ByteEncode_12(t_hat) || rho.
    //
    // ByteDecode_12 gives ordinary representatives. Convert them back to this
    // crate's NTT/Montgomery representation before using NTT-domain products.
    let t_hat = byte_decode_polyvec_q3329::<K, 12>(
        &ek_bytes[..K * POLY_ENCODED_BYTES]
    ).coeffs_to_montgomery();


    let mut rho= [0u8; 32];
    rho.copy_from_slice(&ek_bytes[K * POLY_ENCODED_BYTES..]);

    let a_hat_transposed = expand_a_hat_transposed::<K>(&rho);

    // y is sampled in the coefficient domain, then transformed to the
    // NTT/Montgomery domain.
    let mut y_hat = sample_polyvec_from_prf::<K, ETA1>(&randomness, 0u8);
    y_hat.ntt();

    // e1 and e2 remain in the ordinary coefficient domain.
    let e1 = sample_error_vector::<K, ETA2>(&randomness, K as u8);
    let e2 = sample_poly_from_prf::<ETA2>(&randomness, (2 * K) as u8);

    let mut u = a_hat_transposed.mul_vec_ntt(&y_hat);
    u.inv_ntt();
    u.add_assign(&e1);

    let mu = message_to_mu(message);

    let mut v = t_hat.dot_ntt(&y_hat);
    v.inv_ntt();
    v.add_assign(&e2);
    v.add_assign(&mu);

    byte_encode_polyvec_q3329::<K, DU>(
        &compress_q3329_polyvec::<K, DU>(&u),
        &mut output[..(32 * DU * K)]
    );

    byte_encode_poly_q3329::<DV>(
        &compress_q3329_poly::<DV>(&v),
        &mut output[32 * DU * K..]
    );

    Ciphertext::from_bytes(output)
}



















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
    ek: &EncapsulationKey<800>,
    message: &[u8; 32],
    randomness: &[u8; 32],
) -> Ciphertext<768> {
    kpke_encrypt::<2, 800, 768, 3, 2, 10, 4>(ek, message, randomness)
}

/// Encrypts using the K-PKE parameters underlying ML-KEM-768.
#[must_use]
pub(crate) fn kpke_encrypt768(
    ek: &EncapsulationKey<1184>,
    message: &[u8; 32],
    randomness: &[u8; 32],
) -> Ciphertext<1088> {
    kpke_encrypt::<3, 1184, 1088, 2, 2, 10, 4>(ek, message, randomness)
}

/// Encrypts using the K-PKE parameters underlying ML-KEM-1024.
#[must_use]
pub(crate) fn kpke_encrypt1024(
    ek: &EncapsulationKey<1568>,
    message: &[u8; 32],
    randomness: &[u8; 32],
) -> Ciphertext<1568> {
    kpke_encrypt::<4, 1568, 1568, 2, 2, 11, 5>(ek, message, randomness)
}



// -----------------------------------------------------
// Tests
// -----------------------------------------------------


#[cfg(test)]
mod tests {
    use super::*;

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
}