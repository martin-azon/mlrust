//! ML-KEM K-PKE algorithms.
//!
//! This module implements the deterministic public-key encryption component
//! used internally by ML-KEM.
//!
//! These routines are crate-internal. The public ML-KEM API is implemented
//! separately in the KEM layer.

use mlrust_core::encode::ml_kem::{
    byte_decode_poly_q3329, byte_decode_polyvec_q3329, byte_encode_poly_q3329,
    byte_encode_polyvec_q3329, compress_q3329_poly, compress_q3329_polyvec, decompress_q3329_poly,
    decompress_q3329_polyvec,
};
use mlrust_core::params::Q3329;
use mlrust_core::poly::Poly;
use mlrust_core::symmetric::ml_kem::g;

use crate::kpke::internal::{
    compute_t_hat, expand_a_hat, expand_a_hat_transposed, sample_error_vector,
    sample_poly_from_prf, sample_polyvec_from_prf, sample_secret_vector,
};

use crate::keys::{
    Ciphertext, KpkeDecryptionKey, KpkeEncryptionKey, KpkeInternalKeypair, KpkeKeypair,
};

// -----------------------------------------------------
// KeyGen - Encryption - Decryption
// -----------------------------------------------------

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
pub(crate) fn derive_k_pke_keygen_seeds(d: &[u8; 32], k: u8) -> ([u8; 32], [u8; 32]) {
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
pub(crate) fn kpke_keygen_internal<const K: usize, const ETA1: usize>(
    d: &[u8; 32],
) -> KpkeInternalKeypair<K> {
    let (rho, sigma) = derive_k_pke_keygen_seeds(d, K as u8);

    let a_hat = expand_a_hat::<K>(&rho);

    let mut s_hat = sample_secret_vector::<K, ETA1>(&sigma, 0);
    let mut e_hat = sample_error_vector::<K, ETA1>(&sigma, K as u8);

    s_hat.ntt();
    e_hat.ntt();

    let t_hat = compute_t_hat::<K>(&a_hat, &s_hat, &e_hat);

    KpkeInternalKeypair { rho, s_hat, t_hat }
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
/// EK_PKE_BYTES = 384 * K + 32
/// DK_PKE_BYTES = 384 * K
/// ```
pub(crate) fn kpke_keygen<
    const K: usize,
    const EK_PKE_BYTES: usize,
    const DK_PKE_BYTES: usize,
    const ETA1: usize,
>(
    d: &[u8; 32],
) -> KpkeKeypair<EK_PKE_BYTES, DK_PKE_BYTES> {
    const POLY_ENCODED_BYTES: usize = 384;

    assert_eq!(EK_PKE_BYTES, K * POLY_ENCODED_BYTES + 32);
    assert_eq!(DK_PKE_BYTES, K * POLY_ENCODED_BYTES);

    let internal_key = kpke_keygen_internal::<K, ETA1>(d);

    let t_hat = internal_key.t_hat.coeffs_from_montgomery();
    let s_hat = internal_key.s_hat.coeffs_from_montgomery();

    let mut encaps_key = [0u8; EK_PKE_BYTES];
    let mut decaps_key = [0u8; DK_PKE_BYTES];

    byte_encode_polyvec_q3329::<K, 12>(&t_hat, &mut encaps_key[..K * POLY_ENCODED_BYTES]);

    encaps_key[K * POLY_ENCODED_BYTES..].copy_from_slice(&internal_key.rho);

    byte_encode_polyvec_q3329::<K, 12>(&s_hat, &mut decaps_key);

    let ek_pke = KpkeEncryptionKey::from_bytes(encaps_key);
    let dk_pke = KpkeDecryptionKey::from_bytes(decaps_key);

    KpkeKeypair { ek_pke, dk_pke }
}

/// Computes `Decompress_1(ByteDecode_1(m))`
#[must_use]
pub(crate) fn message_to_mu(m: &[u8; 32]) -> Poly<Q3329> {
    decompress_q3329_poly::<1>(&byte_decode_poly_q3329::<1>(m))
}

/// Computes `ByteEncode_1(Compress_1(m))`
#[must_use]
pub(crate) fn mu_to_message(mu: &Poly<Q3329>) -> [u8; 32] {
    let mut out = [0u8; 32];
    byte_encode_poly_q3329::<1>(&compress_q3329_poly::<1>(mu), &mut out);
    out
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
pub(crate) fn kpke_encrypt<
    const K: usize,
    const EK_PKE_BYTES: usize,
    const CT_BYTES: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    ek: &KpkeEncryptionKey<EK_PKE_BYTES>,
    message: &[u8; 32],
    randomness: &[u8; 32],
) -> Ciphertext<CT_BYTES> {
    const POLY_ENCODED_BYTES: usize = 384;

    assert_eq!(EK_PKE_BYTES, K * POLY_ENCODED_BYTES + 32);
    assert_eq!(CT_BYTES, 32 * (DU * K + DV));

    let mut output = [0u8; CT_BYTES];

    let ek_bytes = ek.as_bytes();

    // Decode t_hat from ek_pke = ByteEncode_12(t_hat) || rho.
    //
    // ByteDecode_12 gives ordinary representatives. Convert them back to this
    // crate's NTT/Montgomery representation before using NTT-domain products.
    let t_hat = byte_decode_polyvec_q3329::<K, 12>(&ek_bytes[..K * POLY_ENCODED_BYTES])
        .coeffs_to_montgomery();

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek_bytes[K * POLY_ENCODED_BYTES..]);

    let a_hat_transposed = expand_a_hat_transposed::<K>(&rho);

    // y is sampled in the coefficient domain, then transformed to the
    // NTT/Montgomery domain.
    let mut y_hat = sample_polyvec_from_prf::<K, ETA1>(randomness, 0u8);
    y_hat.ntt();

    // e1 and e2 remain in the ordinary coefficient domain.
    let e1 = sample_error_vector::<K, ETA2>(randomness, K as u8);
    let e2 = sample_poly_from_prf::<ETA2>(randomness, (2 * K) as u8);

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
        &mut output[..(32 * DU * K)],
    );

    byte_encode_poly_q3329::<DV>(&compress_q3329_poly::<DV>(&v), &mut output[32 * DU * K..]);

    Ciphertext::from_bytes(output)
}

/// Decrypts a K-PKE ciphertext.
///
/// This implements the K-PKE decryption step:
///
/// ```text
/// u' = Decompress_DU(ByteDecode_DU(c1))
/// v' = Decompress_DV(ByteDecode_DV(c2))
/// w  = v' - NTT^{-1}(s_hat · NTT(u'))
/// m  = ByteEncode_1(Compress_1(w))
/// ```
///
/// where:
///
/// ```text
/// c = c1 || c2
/// dk_pke = ByteEncode_12(s_hat)
/// ```
///
/// # Representation
///
/// The decoded secret vector `s_hat` is converted from ordinary representatives
/// into this crate's Montgomery representation before NTT-domain multiplication.
///
/// The decoded/decompressed `u'` is in the ordinary coefficient domain and is
/// transformed with the forward NTT before multiplication.
///
/// # Panics
///
/// Panics if the provided byte-size constants do not match the K-PKE sizes:
///
/// ```text
/// DK_PKE_BYTES = 384 * K
/// CT_BYTES = 32 * (DU * K + DV)
/// ```
#[must_use]
pub(crate) fn kpke_decrypt<
    const K: usize,
    const DK_PKE_BYTES: usize,
    const CT_BYTES: usize,
    const DU: usize,
    const DV: usize,
>(
    dk: &KpkeDecryptionKey<DK_PKE_BYTES>,
    ciphertext: &Ciphertext<CT_BYTES>,
) -> [u8; 32] {
    const POLY_ENCODED_BYTES: usize = 384;

    assert_eq!(DK_PKE_BYTES, K * POLY_ENCODED_BYTES);
    assert_eq!(CT_BYTES, 32 * (DU * K + DV));

    let ciphertext_bytes = ciphertext.as_bytes();
    let c1_len = 32 * DU * K;

    let mut u = decompress_q3329_polyvec::<K, DU>(&byte_decode_polyvec_q3329::<K, DU>(
        &ciphertext_bytes[..c1_len],
    ));

    let mut v =
        decompress_q3329_poly::<DV>(&byte_decode_poly_q3329::<DV>(&ciphertext_bytes[c1_len..]));

    let s_hat = byte_decode_polyvec_q3329::<K, 12>(dk.as_bytes()).coeffs_to_montgomery();

    u.ntt();

    let mut scalar_prod = s_hat.dot_ntt(&u);
    scalar_prod.inv_ntt();

    v.sub_assign(&scalar_prod);

    mu_to_message(&v)
}
