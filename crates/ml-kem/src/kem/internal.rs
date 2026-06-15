//! Deterministic algorithms for ML-KEM key generation,
//! encapsulation, and decapsulation.
//!
//! All such algorithms are implemented on top of the internal
//! K-PKE routines.


use crate::kpke::{kpke_decrypt, kpke_encrypt, kpke_keygen};
use crate::keys::{
    Ciphertext,
    DecapsulationKey,
    EncapsulationKey,
    KpkeDecryptionKey,
    KpkeEncryptionKey,
    MlKemKeypair,
    SharedSecret,
};

use mlrust_core::ct::{ct_eq, ct_select_bytes};
use mlrust_core::symmetric::ml_kem::{g, h, j_concat};



/// Deterministically generates an ML-KEM keypair from two 32-byte seeds.
///
/// This implements the internal deterministic form of ML-KEM key generation.
/// The final decapsulation key has layout:
///
/// ```text
/// dk = dk_pke || ek || H(ek) || z
/// ```
///
/// where:
///
/// - `dk_pke` is the K-PKE decryption key;
/// - `ek` is the ML-KEM encapsulation key;
/// - `H(ek)` is cached for decapsulation;
/// - `z` is the fallback secret used if ciphertext validation fails.
#[must_use]
pub(crate) fn ml_kem_keygen_internal<
    const K: usize,
    const EK_BYTES: usize,
    const EK_PKE_BYTES: usize,
    const DK_BYTES: usize,
    const DK_PKE_BYTES: usize,
    const ETA1: usize
> (
    randomness_d: &[u8; 32],
    randomness_z: &[u8; 32]
) -> MlKemKeypair<EK_BYTES, DK_BYTES> {
    assert_eq!(EK_BYTES, 384 * K + 32);
    assert_eq!(DK_BYTES, 768 * K + 96);
    assert_eq!(EK_PKE_BYTES, 384 * K + 32);
    assert_eq!(DK_PKE_BYTES, 384 * K);

    let kpke_keypair =
        kpke_keygen::<K, EK_PKE_BYTES, DK_PKE_BYTES, ETA1>(randomness_d);

    let mut ek_bytes = [0u8; EK_BYTES];
    ek_bytes.copy_from_slice(kpke_keypair.ek_pke.as_bytes());

    let mut dk_bytes = [0u8; DK_BYTES];

    let mut hash = [0u8; 32];
    h(&ek_bytes, &mut hash);

    dk_bytes[..DK_PKE_BYTES].copy_from_slice(kpke_keypair.dk_pke.as_bytes());
    dk_bytes[DK_PKE_BYTES..(DK_PKE_BYTES + EK_BYTES)].copy_from_slice(&ek_bytes);
    dk_bytes[(DK_PKE_BYTES + EK_BYTES)..(DK_PKE_BYTES + EK_BYTES + 32)]
        .copy_from_slice(&hash);
    dk_bytes[(DK_PKE_BYTES + EK_BYTES + 32)..].copy_from_slice(randomness_z);

    MlKemKeypair::from_parts(
        EncapsulationKey::<EK_BYTES>::from_bytes(ek_bytes),
        DecapsulationKey::<DK_BYTES>::from_bytes(dk_bytes)
    )
}


/// Deterministically encapsulates to an ML-KEM encapsulation key.
///
/// The caller supplies the 32-byte message/randomness `m`. Public randomized
/// APIs should generate this value with a cryptographically secure RNG.
///
/// Returns the shared secret and ciphertext.
#[must_use]
pub(crate) fn ml_kem_encaps_internal<
    const K: usize,
    const EK_BYTES: usize,
    const CT_BYTES: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
> (
    ek: &EncapsulationKey<EK_BYTES>,
    randomness_m: &[u8; 32]
) -> (SharedSecret, Ciphertext<CT_BYTES>) {
    const POLY_ENCODED_BYTES: usize = 384;

    assert_eq!(EK_BYTES, K * POLY_ENCODED_BYTES + 32);
    assert_eq!(CT_BYTES, 32 * (DU * K + DV));

    let mut input_to_g = [0u8; 64];

    let mut hash = [0u8; 32];
    h(ek.as_bytes() , &mut hash);

    input_to_g[..32].copy_from_slice(randomness_m);
    input_to_g[32..].copy_from_slice(&hash);

    let mut shared_key_bytes = [0u8; 32];
    let mut randomness_r = [0u8; 32];

    g(&input_to_g, &mut shared_key_bytes, &mut randomness_r);

    let encr_key =
        KpkeEncryptionKey::<EK_BYTES>::from_bytes(*ek.as_bytes());

    let ciphertext =
        kpke_encrypt::<K, EK_BYTES, CT_BYTES, ETA1, ETA2, DU, DV>(
            &encr_key, randomness_m, &randomness_r
        );

    (SharedSecret::from_bytes(shared_key_bytes), ciphertext)
}


/// Decapsulates an ML-KEM ciphertext.
///
/// This decrypts the ciphertext using the embedded K-PKE decryption key,
/// recomputes the expected ciphertext, and returns either the derived shared
/// secret or the fallback value `J(z || c)` using a constant-time selection.
#[must_use]
pub(crate) fn ml_kem_decaps_internal<
    const K: usize,
    const DK_BYTES: usize,
    const EK_PKE_BYTES: usize,
    const DK_PKE_BYTES: usize,
    const CT_BYTES: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
> (
    dk: &DecapsulationKey<DK_BYTES>,
    ciphertext: &Ciphertext<CT_BYTES>
) -> SharedSecret {
    assert_eq!(EK_PKE_BYTES, 384 * K + 32);
    assert_eq!(DK_PKE_BYTES, 384 * K);
    assert_eq!(DK_BYTES, DK_PKE_BYTES + EK_PKE_BYTES + 64);
    assert_eq!(CT_BYTES, 32 * (DU * K + DV));

    let dk_bytes = dk.as_bytes();

    let mut dk_pke_bytes = [0u8; DK_PKE_BYTES];
    let mut ek_pke_bytes = [0u8; EK_PKE_BYTES];
    let mut hash = [0u8; 32];
    let mut randomness_z = [0u8; 32];

    dk_pke_bytes.copy_from_slice(&dk_bytes[..DK_PKE_BYTES]);

    ek_pke_bytes.copy_from_slice(
        &dk_bytes[DK_PKE_BYTES..(DK_PKE_BYTES + EK_PKE_BYTES)]
    );

    hash.copy_from_slice(
        &dk_bytes[
            (DK_PKE_BYTES + EK_PKE_BYTES)..(DK_PKE_BYTES + EK_PKE_BYTES + 32)
            ]
    );

    randomness_z.copy_from_slice(
        &dk_bytes[(DK_PKE_BYTES + EK_PKE_BYTES + 32)..]
    );

    let dk_pke = KpkeDecryptionKey::<DK_PKE_BYTES>::from_bytes(dk_pke_bytes);


    let randomness_m = kpke_decrypt::<K, DK_PKE_BYTES, CT_BYTES, DU, DV>(&dk_pke, &ciphertext);


    let mut input_to_g = [0u8; 64];
    input_to_g[..32].copy_from_slice(&randomness_m);
    input_to_g[32..].copy_from_slice(&hash);

    let mut k = [0u8; 32];
    let mut randomness_r = [0u8; 32];

    g(&input_to_g, &mut k, &mut randomness_r);


    let mut k_bar = [0u8; 32];

    j_concat(&randomness_z, ciphertext.as_bytes(), &mut k_bar);

    let encr_key =
        KpkeEncryptionKey::<EK_PKE_BYTES>::from_bytes(ek_pke_bytes);

    let alternative_ciphertext =
        kpke_encrypt::<K, EK_PKE_BYTES, CT_BYTES, ETA1, ETA2, DU, DV>(
            &encr_key, &randomness_m, &randomness_r
        );

    let ciph_bytes = ciphertext.as_bytes();
    let alt_ciph_bytes = alternative_ciphertext.as_bytes();
    // ciphertexts_differ equals:
    // Choice::from(1) if ciph_bytes != alt_ciph_bytes,
    // Choice::from(0) if ciph_bytes == alt_ciph_bytes,
    let ciphertexts_differ = !ct_eq(ciph_bytes, alt_ciph_bytes);

    let mut output_bytes = [0u8; 32];
    // Stores in output_bytes:
    // the slice k_bar if ciphertexts_differ = Choice::from(1) (ie ciph_bytes != alt_ciph_bytes),
    // the slice k if ciphertexts_differ = Choice::from(0) (ie ciph_bytes == alt_ciph_bytes).
    ct_select_bytes(&mut output_bytes, &k, &k_bar, ciphertexts_differ);

    SharedSecret::from_bytes(output_bytes)
}