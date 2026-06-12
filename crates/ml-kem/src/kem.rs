//! ML-KEM routines




use crate::k_pke::kpke_keygen;
use crate::keys::{DecapsulationKey, EncapsulationKey, MlKemKeypair};

use mlrust_core::symmetric::ml_kem::h;

pub fn ml_kem_keygen_internal<
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
    let mut dk_bytes = [0u8; DK_BYTES];

    let mut hash = [0u8; 32];
    h(&ek_bytes, &mut hash);

    ek_bytes.copy_from_slice(kpke_keypair.ek_pke.as_bytes());
    dk_bytes[..DK_PKE_BYTES].copy_from_slice(kpke_keypair.dk_pke.as_bytes());
    dk_bytes[DK_PKE_BYTES..(DK_PKE_BYTES + EK_BYTES)].copy_from_slice(&ek_bytes);
    dk_bytes[(DK_PKE_BYTES + EK_BYTES)..(DK_PKE_BYTES + EK_BYTES + 32)]
        .copy_from_slice(&hash);
    dk_bytes[(DK_PKE_BYTES + EK_BYTES + 32)..].copy_from_slice(randomness_z);

    let ek = EncapsulationKey::<EK_BYTES>::from_bytes(ek_bytes);
    let dk = DecapsulationKey::<DK_BYTES>::from_bytes(dk_bytes);

    MlKemKeypair{ ek, dk}
}