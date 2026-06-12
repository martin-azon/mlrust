//! ML-KEM key generation, encapsulation, and decapsulation.
//!
//! This module implements the final ML-KEM layer on top of the internal
//! K-PKE routines. The functions in this module assemble the final serialized
//! ML-KEM decapsulation key, derive shared secrets, and perform the
//! Fujisaki-Okamoto-style re-encryption check used during decapsulation.



use crate::k_pke::{kpke_decrypt, kpke_encrypt, kpke_keygen};
use crate::error::MlKemError;
use crate::keys::{
    Ciphertext,
    DecapsulationKey,
    EncapsulationKey,
    KpkeDecryptionKey,
    KpkeEncryptionKey,
    MlKem512Ciphertext,
    MlKem512DecapsulationKey,
    MlKem512EncapsulationKey,
    MlKem512Keypair,
    MlKem768Ciphertext,
    MlKem768DecapsulationKey,
    MlKem768EncapsulationKey,
    MlKem768Keypair,
    MlKem1024Ciphertext,
    MlKem1024DecapsulationKey,
    MlKem1024EncapsulationKey,
    MlKem1024Keypair,
    MlKemKeypair,
    SharedSecret,
};
use crate::params::{
    MlKem512,
    MlKem768,
    MlKem1024,

    ML_KEM_512_ENCAPS_KEY_BYTES,
    ML_KEM_512_DECAPS_KEY_BYTES,
    ML_KEM_512_CIPHERTEXT_BYTES,
    KPKE_512_ENCRYPT_KEY_BYTES,
    KPKE_512_DECRYPT_KEY_BYTES,

    ML_KEM_768_ENCAPS_KEY_BYTES,
    ML_KEM_768_DECAPS_KEY_BYTES,
    ML_KEM_768_CIPHERTEXT_BYTES,
    KPKE_768_ENCRYPT_KEY_BYTES,
    KPKE_768_DECRYPT_KEY_BYTES,

    ML_KEM_1024_ENCAPS_KEY_BYTES,
    ML_KEM_1024_DECAPS_KEY_BYTES,
    ML_KEM_1024_CIPHERTEXT_BYTES,
    KPKE_1024_ENCRYPT_KEY_BYTES,
    KPKE_1024_DECRYPT_KEY_BYTES,
};

use mlrust_core::symmetric::ml_kem::{g, h, j_concat};
use mlrust_core::ct::{ct_select_bytes, ct_eq};


// --------------------------------------------------------------------
// Internal ML-KEM functions
// --------------------------------------------------------------------


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




// --------------------------------------------------------------------
// Defining generic MlKemParams trait
// --------------------------------------------------------------------


/// Public ML-KEM parameter-set trait.
///
/// This trait provides a stable, concise API over the three ML-KEM parameter
/// sets without relying on associated constants in const-generic type
/// positions in public generic function signatures.
pub trait MlKemParams: Sized {
    const K: usize;
    const ETA1: usize;
    const ETA2: usize;
    const DU: usize;
    const DV: usize;

    const ENCAPS_KEY_BYTES: usize;
    const DECAPS_KEY_BYTES: usize;
    const CIPHERTEXT_BYTES: usize;
    const EK_PKE_BYTES: usize;
    const DK_PKE_BYTES: usize;

    type EncapsulationKey;
    type DecapsulationKey;
    type Ciphertext;
    type Keypair;

    fn keygen_from_seed(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Self::Keypair;

    fn encaps_from_seed(
        ek: &Self::EncapsulationKey,
        m: &[u8; 32],
    ) -> (SharedSecret, Self::Ciphertext);

    fn decaps(
        dk: &Self::DecapsulationKey,
        ciphertext: &Self::Ciphertext,
    ) -> SharedSecret;
}



// --------------------------------------------------------------------
// Implementing the trait MlKemParams for each instantiation of ML-KEM
// --------------------------------------------------------------------

impl MlKemParams for MlKem512 {
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;

    const ENCAPS_KEY_BYTES: usize = ML_KEM_512_ENCAPS_KEY_BYTES;
    const DECAPS_KEY_BYTES: usize = ML_KEM_512_DECAPS_KEY_BYTES;
    const CIPHERTEXT_BYTES: usize = ML_KEM_512_CIPHERTEXT_BYTES;
    const EK_PKE_BYTES: usize = KPKE_512_ENCRYPT_KEY_BYTES;
    const DK_PKE_BYTES: usize = KPKE_512_DECRYPT_KEY_BYTES;

    type EncapsulationKey = MlKem512EncapsulationKey;
    type DecapsulationKey = MlKem512DecapsulationKey;
    type Ciphertext = MlKem512Ciphertext;
    type Keypair = MlKem512Keypair;

    fn keygen_from_seed(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Self::Keypair {
        ml_kem_keygen_internal::<
            2,
            ML_KEM_512_ENCAPS_KEY_BYTES,
            KPKE_512_ENCRYPT_KEY_BYTES,
            ML_KEM_512_DECAPS_KEY_BYTES,
            KPKE_512_DECRYPT_KEY_BYTES,
            3,
        >(d, z)
    }

    fn encaps_from_seed(
        ek: &Self::EncapsulationKey,
        m: &[u8; 32],
    ) -> (SharedSecret, Self::Ciphertext) {
        ml_kem_encaps_internal::<
            2,
            ML_KEM_512_ENCAPS_KEY_BYTES,
            ML_KEM_512_CIPHERTEXT_BYTES,
            3,
            2,
            10,
            4,
        >(ek, m)
    }

    fn decaps(
        dk: &Self::DecapsulationKey,
        ciphertext: &Self::Ciphertext,
    ) -> SharedSecret {
        ml_kem_decaps_internal::<
            2,
            ML_KEM_512_DECAPS_KEY_BYTES,
            KPKE_512_ENCRYPT_KEY_BYTES,
            KPKE_512_DECRYPT_KEY_BYTES,
            ML_KEM_512_CIPHERTEXT_BYTES,
            3,
            2,
            10,
            4,
        >(dk, ciphertext)
    }
}

impl MlKemParams for MlKem768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;

    const ENCAPS_KEY_BYTES: usize = ML_KEM_768_ENCAPS_KEY_BYTES;
    const DECAPS_KEY_BYTES: usize = ML_KEM_768_DECAPS_KEY_BYTES;
    const CIPHERTEXT_BYTES: usize = ML_KEM_768_CIPHERTEXT_BYTES;
    const EK_PKE_BYTES: usize = KPKE_768_ENCRYPT_KEY_BYTES;
    const DK_PKE_BYTES: usize = KPKE_768_DECRYPT_KEY_BYTES;

    type EncapsulationKey = MlKem768EncapsulationKey;
    type DecapsulationKey = MlKem768DecapsulationKey;
    type Ciphertext = MlKem768Ciphertext;
    type Keypair = MlKem768Keypair;

    fn keygen_from_seed(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Self::Keypair {
        ml_kem_keygen_internal::<
            3,
            ML_KEM_768_ENCAPS_KEY_BYTES,
            KPKE_768_ENCRYPT_KEY_BYTES,
            ML_KEM_768_DECAPS_KEY_BYTES,
            KPKE_768_DECRYPT_KEY_BYTES,
            2,
        >(d, z)
    }

    fn encaps_from_seed(
        ek: &Self::EncapsulationKey,
        m: &[u8; 32],
    ) -> (SharedSecret, Self::Ciphertext) {
        ml_kem_encaps_internal::<
            3,
            ML_KEM_768_ENCAPS_KEY_BYTES,
            ML_KEM_768_CIPHERTEXT_BYTES,
            2,
            2,
            10,
            4,
        >(ek, m)
    }

    fn decaps(
        dk: &Self::DecapsulationKey,
        ciphertext: &Self::Ciphertext,
    ) -> SharedSecret {
        ml_kem_decaps_internal::<
            3,
            ML_KEM_768_DECAPS_KEY_BYTES,
            KPKE_768_ENCRYPT_KEY_BYTES,
            KPKE_768_DECRYPT_KEY_BYTES,
            ML_KEM_768_CIPHERTEXT_BYTES,
            2,
            2,
            10,
            4,
        >(dk, ciphertext)
    }
}

impl MlKemParams for MlKem1024 {
    const K: usize = 4;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;

    const ENCAPS_KEY_BYTES: usize = ML_KEM_1024_ENCAPS_KEY_BYTES;
    const DECAPS_KEY_BYTES: usize = ML_KEM_1024_DECAPS_KEY_BYTES;
    const CIPHERTEXT_BYTES: usize = ML_KEM_1024_CIPHERTEXT_BYTES;
    const EK_PKE_BYTES: usize = KPKE_1024_ENCRYPT_KEY_BYTES;
    const DK_PKE_BYTES: usize = KPKE_1024_DECRYPT_KEY_BYTES;

    type EncapsulationKey = MlKem1024EncapsulationKey;
    type DecapsulationKey = MlKem1024DecapsulationKey;
    type Ciphertext = MlKem1024Ciphertext;
    type Keypair = MlKem1024Keypair;

    fn keygen_from_seed(
        d: &[u8; 32],
        z: &[u8; 32],
    ) -> Self::Keypair {
        ml_kem_keygen_internal::<
            4,
            ML_KEM_1024_ENCAPS_KEY_BYTES,
            KPKE_1024_ENCRYPT_KEY_BYTES,
            ML_KEM_1024_DECAPS_KEY_BYTES,
            KPKE_1024_DECRYPT_KEY_BYTES,
            2,
        >(d, z)
    }

    fn encaps_from_seed(
        ek: &Self::EncapsulationKey,
        m: &[u8; 32],
    ) -> (SharedSecret, Self::Ciphertext) {
        ml_kem_encaps_internal::<
            4,
            ML_KEM_1024_ENCAPS_KEY_BYTES,
            ML_KEM_1024_CIPHERTEXT_BYTES,
            2,
            2,
            11,
            5,
        >(ek, m)
    }

    fn decaps(
        dk: &Self::DecapsulationKey,
        ciphertext: &Self::Ciphertext,
    ) -> SharedSecret {
        ml_kem_decaps_internal::<
            4,
            ML_KEM_1024_DECAPS_KEY_BYTES,
            KPKE_1024_ENCRYPT_KEY_BYTES,
            KPKE_1024_DECRYPT_KEY_BYTES,
            ML_KEM_1024_CIPHERTEXT_BYTES,
            2,
            2,
            11,
            5,
        >(dk, ciphertext)
    }
}



// --------------------------------------------------------------------
// Final ML-KEM functions
// --------------------------------------------------------------------

fn fill_random(bytes: &mut [u8]) -> Result<(), MlKemError> {
    getrandom::fill(bytes)
        .map_err(|_| MlKemError::RandomnessGenerationFailed)
}

fn random_32() -> Result<[u8; 32], MlKemError> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

pub fn ml_kem_keygen<P: MlKemParams>() -> Result<P::Keypair, MlKemError> {
    let d = random_32()?;
    let z = random_32()?;

    Ok(P::keygen_from_seed(&d, &z))
}

pub fn ml_kem_encaps<P: MlKemParams>(
    ek: &P::EncapsulationKey,
) -> Result<(SharedSecret, P::Ciphertext), MlKemError> {
    let m = random_32()?;

    Ok(P::encaps_from_seed(ek, &m))
}

#[must_use]
pub fn ml_kem_decaps<P: MlKemParams>(
    dk: &P::DecapsulationKey,
    ciphertext: &P::Ciphertext,
) -> SharedSecret {
    P::decaps(dk, ciphertext)
}



// --------------------------------------------------------------------
// Wrappers for each instantiation of ML-KEM
// --------------------------------------------------------------------


pub fn ml_kem_keygen512() -> Result<MlKem512Keypair, MlKemError> {
    ml_kem_keygen::<MlKem512>()
}

pub fn ml_kem_encaps512(
    ek: &MlKem512EncapsulationKey,
) -> Result<(SharedSecret, MlKem512Ciphertext), MlKemError> {
    ml_kem_encaps::<MlKem512>(ek)
}

#[must_use]
pub fn ml_kem_decaps512(
    dk: &MlKem512DecapsulationKey,
    ciphertext: &MlKem512Ciphertext,
) -> SharedSecret {
    ml_kem_decaps::<MlKem512>(dk, ciphertext)
}

pub fn ml_kem_keygen768() -> Result<MlKem768Keypair, MlKemError> {
    ml_kem_keygen::<MlKem768>()
}

pub fn ml_kem_encaps768(
    ek: &MlKem768EncapsulationKey,
) -> Result<(SharedSecret, MlKem768Ciphertext), MlKemError> {
    ml_kem_encaps::<MlKem768>(ek)
}

#[must_use]
pub fn ml_kem_decaps768(
    dk: &MlKem768DecapsulationKey,
    ciphertext: &MlKem768Ciphertext,
) -> SharedSecret {
    ml_kem_decaps::<MlKem768>(dk, ciphertext)
}

pub fn ml_kem_keygen1024() -> Result<MlKem1024Keypair, MlKemError> {
    ml_kem_keygen::<MlKem1024>()
}

pub fn ml_kem_encaps1024(
    ek: &MlKem1024EncapsulationKey,
) -> Result<(SharedSecret, MlKem1024Ciphertext), MlKemError> {
    ml_kem_encaps::<MlKem1024>(ek)
}

#[must_use]
pub fn ml_kem_decaps1024(
    dk: &MlKem1024DecapsulationKey,
    ciphertext: &MlKem1024Ciphertext,
) -> SharedSecret {
    ml_kem_decaps::<MlKem1024>(dk, ciphertext)
}


// --------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------


#[cfg(test)]
mod tests {
    use super::*;

    use crate::internal::{
        compute_t_hat,
        expand_a_hat,
        sample_error_vector,
        sample_secret_vector,
    };
    use crate::keys::KpkeKeypair;
    use std::vec::Vec;
    use mlrust_core::encode::ml_kem::byte_encode_polyvec_q3329;

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

        let kp = ml_kem_keygen_internal::<
            K,
            EK_BYTES,
            EK_PKE_BYTES,
            DK_BYTES,
            DK_PKE_BYTES,
            ETA1,
        >(&d, &z);

        assert_eq!(kp.ek.as_bytes().len(), EK_BYTES);
        assert_eq!(kp.dk.as_bytes().len(), DK_BYTES);

        let ek = kp.ek.as_bytes();
        let dk = kp.dk.as_bytes();

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

        let kp = ml_kem_keygen_internal::<
            K,
            EK_BYTES,
            EK_PKE_BYTES,
            DK_BYTES,
            DK_PKE_BYTES,
            ETA1,
        >(&d, &z);

        let (ss_enc, ciphertext) = ml_kem_encaps_internal::<
            K,
            EK_BYTES,
            CT_BYTES,
            ETA1,
            ETA2,
            DU,
            DV,
        >(&kp.ek, &m);

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
        >(&kp.dk.clone(), &ciphertext.clone());

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

        let kp = ml_kem_keygen_internal::<
            K,
            EK_BYTES,
            EK_PKE_BYTES,
            DK_BYTES,
            DK_PKE_BYTES,
            ETA1,
        >(&d, &z);

        let (_ss_enc, ciphertext) = ml_kem_encaps_internal::<
            K,
            EK_BYTES,
            CT_BYTES,
            ETA1,
            ETA2,
            DU,
            DV,
        >(&kp.ek, &m);

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
        >(&kp.dk, &tampered_ciphertext);

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

    // ---------------------------------------------------------------
    // CCTV helpers
    // ---------------------------------------------------------------

    fn try_hex_field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
        for line in text.lines() {
            let line = line.trim();

            let Some((lhs, rhs)) = line.split_once('=') else {
                continue;
            };

            if lhs.trim() == name {
                return Some(
                    rhs.trim()
                        .rsplit(" = ")
                        .next()
                        .expect("field has a value")
                        .trim(),
                );
            }
        }

        None
    }

    fn hex_field<'a>(text: &'a str, name: &str) -> &'a str {
        try_hex_field(text, name).unwrap_or_else(|| {
            panic!("missing CCTV field: {name}");
        })
    }

    fn hex_field_any<'a>(text: &'a str, names: &[&str]) -> &'a str {
        for name in names {
            if let Some(value) = try_hex_field(text, name) {
                return value;
            }
        }

        panic!("missing CCTV field among: {names:?}");
    }

    fn hex_field_nth<'a>(text: &'a str, name: &str, n: usize) -> &'a str {
        let mut count = 0usize;

        for line in text.lines() {
            let line = line.trim();

            let Some((lhs, rhs)) = line.split_once('=') else {
                continue;
            };

            if lhs.trim() == name {
                if count == n {
                    return rhs
                        .trim()
                        .rsplit(" = ")
                        .next()
                        .expect("field has a value")
                        .trim();
                }

                count += 1;
            }
        }

        panic!("missing CCTV field occurrence {n}: {name}");
    }

    fn hex_array<const N: usize>(hex_str: &str) -> [u8; N] {
        let bytes = hex::decode(hex_str).expect("valid hex");

        bytes.try_into().unwrap_or_else(|bytes: Vec<u8>| {
            panic!("wrong length: expected {N} bytes, got {}", bytes.len())
        })
    }

    /// CCTV intermediate vectors use legacy K-PKE seed derivation `G(d)`.
    ///
    /// This is intentionally test-only. Production ML-KEM keeps `G(d || k)`.
    #[must_use]
    fn derive_kpke_keygen_seeds_cctv_legacy(
        d: &[u8; 32],
    ) -> ([u8; 32], [u8; 32]) {
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

        byte_encode_polyvec_q3329::<K, 12>(
            &t_hat,
            &mut ek_bytes[..K * POLY_ENCODED_BYTES],
        );

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
        dk_bytes[(DK_PKE_BYTES + EK_BYTES)..(DK_PKE_BYTES + EK_BYTES + 32)]
            .copy_from_slice(&h_ek);
        dk_bytes[(DK_PKE_BYTES + EK_BYTES + 32)..].copy_from_slice(z);

        MlKemKeypair::from_parts(
            EncapsulationKey::<EK_BYTES>::from_bytes(ek_bytes),
            DecapsulationKey::<DK_BYTES>::from_bytes(dk_bytes)
        )

    }

    fn assert_cctv_kem_keygen<
        const K: usize,
        const EK_BYTES: usize,
        const DK_BYTES: usize,
        const DK_PKE_BYTES: usize,
        const ETA1: usize,
    >(vector: &str) {
        let d = hex_array::<32>(hex_field(vector, "d"));
        let z = hex_array::<32>(hex_field(vector, "z"));

        let expected_ek = hex_array::<EK_BYTES>(hex_field(vector, "ek"));
        let expected_dk = hex_array::<DK_BYTES>(hex_field(vector, "dk"));

        let kp = ml_kem_keygen_internal_cctv_legacy::<
            K,
            EK_BYTES,
            DK_BYTES,
            DK_PKE_BYTES,
            ETA1,
        >(&d, &z);

        assert_eq!(kp.ek.as_bytes(), &expected_ek);
        assert_eq!(kp.dk.as_bytes(), &expected_dk);
    }

    fn assert_cctv_kem_encaps<
        const K: usize,
        const EK_BYTES: usize,
        const CT_BYTES: usize,
        const ETA1: usize,
        const ETA2: usize,
        const DU: usize,
        const DV: usize,
    >(vector: &str) {
        let ek = hex_array::<EK_BYTES>(hex_field(vector, "ek"));
        let m = hex_array::<32>(hex_field(vector, "m"));

        let expected_shared_secret =
            hex_array::<32>(hex_field_any(vector, &["K", "ss", "shared_secret"]));

        let expected_ciphertext = hex_array::<CT_BYTES>(hex_field(vector, "c"));

        let ek = EncapsulationKey::<EK_BYTES>::from_bytes(ek);

        let (shared_secret, ciphertext) = ml_kem_encaps_internal::<
            K,
            EK_BYTES,
            CT_BYTES,
            ETA1,
            ETA2,
            DU,
            DV,
        >(&ek, &m);

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
    >(vector: &str) {
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
        const V: &str =
            include_str!("../tests/vectors/cctv/intermediate/ML-KEM-512.txt");

        assert_cctv_kem_keygen::<2, 800, 1632, 768, 3>(V);
    }

    #[test]
    fn cctv_ml_kem768_keygen_matches_intermediate_vector() {
        const V: &str =
            include_str!("../tests/vectors/cctv/intermediate/ML-KEM-768.txt");

        assert_cctv_kem_keygen::<3, 1184, 2400, 1152, 2>(V);
    }

    #[test]
    fn cctv_ml_kem1024_keygen_matches_intermediate_vector() {
        const V: &str =
            include_str!("../tests/vectors/cctv/intermediate/ML-KEM-1024.txt");

        assert_cctv_kem_keygen::<4, 1568, 3168, 1536, 2>(V);
    }

    #[test]
    fn cctv_ml_kem512_encaps_matches_intermediate_vector() {
        const V: &str =
            include_str!("../tests/vectors/cctv/intermediate/ML-KEM-512.txt");

        assert_cctv_kem_encaps::<2, 800, 768, 3, 2, 10, 4>(V);
    }

    #[test]
    fn cctv_ml_kem768_encaps_matches_intermediate_vector() {
        const V: &str =
            include_str!("../tests/vectors/cctv/intermediate/ML-KEM-768.txt");

        assert_cctv_kem_encaps::<3, 1184, 1088, 2, 2, 10, 4>(V);
    }

    #[test]
    fn cctv_ml_kem1024_encaps_matches_intermediate_vector() {
        const V: &str =
            include_str!("../tests/vectors/cctv/intermediate/ML-KEM-1024.txt");

        assert_cctv_kem_encaps::<4, 1568, 1568, 2, 2, 11, 5>(V);
    }

    #[test]
    fn cctv_ml_kem512_decaps_matches_intermediate_vector() {
        const V: &str =
            include_str!("../tests/vectors/cctv/intermediate/ML-KEM-512.txt");

        assert_cctv_kem_decaps::<2, 1632, 800, 768, 768, 3, 2, 10, 4>(V);
    }

    #[test]
    fn cctv_ml_kem768_decaps_matches_intermediate_vector() {
        const V: &str =
            include_str!("../tests/vectors/cctv/intermediate/ML-KEM-768.txt");

        assert_cctv_kem_decaps::<3, 2400, 1184, 1152, 1088, 2, 2, 10, 4>(V);
    }

    #[test]
    fn cctv_ml_kem1024_decaps_matches_intermediate_vector() {
        const V: &str =
            include_str!("../tests/vectors/cctv/intermediate/ML-KEM-1024.txt");

        assert_cctv_kem_decaps::<4, 3168, 1568, 1536, 1568, 2, 2, 11, 5>(V);
    }
}