//! ML-DSA signature encoding and decoding.


use mlrust_core::encode::bits::bitlen_u32;
use mlrust_core::encode::ml_dsa::{bit_pack_signed_q8380417, bit_unpack_q8380417};
use mlrust_core::encode::ml_dsa::hint::{HintVec, hint_bit_pack, hint_bit_unpack};
use mlrust_core::params::Q8380417;
use mlrust_core::poly::{Poly, PolyVec};
use crate::error::MlDsaError;
use crate::keys::Signature;




pub(crate) struct DecodedSignature<
    const K: usize,
    const L: usize,
    const LAMBDA_OVER_4: usize,
> {
    pub(crate) c_tilde: [u8; LAMBDA_OVER_4],
    pub(crate) z: PolyVec<Q8380417, L>,
    pub(crate) hint: HintVec<K>,
}


/// FIPS 204 `sigEncode`.
///
/// Encodes the challenge bytes, response vector `z`, and sparse hint vector
/// into an ML-DSA signature.
///
/// # Panics
///
/// Panics if `SIG_BYTES` does not match the parameter-set signature length, or
/// if `z` or `hint` contains values outside their encoding ranges.
pub(crate) fn sig_encode<
    const K: usize,
    const L: usize,
    const LAMBDA_OVER_4: usize,
    const GAMMA1: usize,
    const BITLEN_2GAMMA1_MINUS_ONE: usize,
    const OMEGA: usize,
    const SIG_BYTES: usize,
> (
    dec_sig: &DecodedSignature<K, L, LAMBDA_OVER_4>
) -> Signature<SIG_BYTES> {
    assert_eq!(
        SIG_BYTES,
        LAMBDA_OVER_4 + L * 32 * BITLEN_2GAMMA1_MINUS_ONE + OMEGA + K
    );
    assert_eq!(
        BITLEN_2GAMMA1_MINUS_ONE,
        1 + bitlen_u32((GAMMA1 - 1) as u32)
    );


    let mut sig_bytes = [0u8; SIG_BYTES];
    sig_bytes[0..LAMBDA_OVER_4].copy_from_slice(&dec_sig.c_tilde);

    let z_polys = dec_sig.z.polys();

    let mut start = LAMBDA_OVER_4;
    let z_poly_len = 32 * BITLEN_2GAMMA1_MINUS_ONE;

    for poly in z_polys {
        bit_pack_signed_q8380417::<BITLEN_2GAMMA1_MINUS_ONE>(
            poly.coeffs(),
            (GAMMA1 - 1) as i32,
            GAMMA1 as i32,
            &mut sig_bytes[start..start + z_poly_len],
        );

        start += z_poly_len;
    }

    hint_bit_pack::<K, OMEGA>(&dec_sig.hint, &mut sig_bytes[start..]);

    Signature::from_bytes(sig_bytes)
}



/// FIPS 204 `sigDecode`.
///
/// Decodes an ML-DSA signature into its internal algebraic representation.
///
/// This function rejects malformed or non-canonical hint encodings.
///
/// # Errors
///
/// Returns [`MlDsaError::InvalidSignature`] if the parameter-set byte length is
/// inconsistent with the expected signature layout, or if the hint encoding is
/// malformed or non-canonical.
pub(crate) fn sig_decode<
    const K: usize,
    const L: usize,
    const LAMBDA_OVER_4: usize,
    const GAMMA1: usize,
    const BITLEN_2GAMMA1_MINUS_ONE: usize,
    const OMEGA: usize,
    const SIG_BYTES: usize,
> (
    enc_sig: &Signature<SIG_BYTES>
) -> Result<DecodedSignature<K, L, LAMBDA_OVER_4>, MlDsaError> {
    if SIG_BYTES
        != LAMBDA_OVER_4 + L * 32 * (1 + bitlen_u32((GAMMA1 - 1) as u32)) + OMEGA + K {
        return Err(MlDsaError::InvalidSignature);
    }
    if BITLEN_2GAMMA1_MINUS_ONE != 1 + bitlen_u32((GAMMA1 - 1) as u32) {
        return Err(MlDsaError::InvalidSignature);
    }

    let sig_bytes = enc_sig.as_bytes();

    let mut c_tilde = [0u8; LAMBDA_OVER_4];
    let mut z_polys = [Poly::<Q8380417>::zero(); L];

    c_tilde.copy_from_slice(&sig_bytes[0..LAMBDA_OVER_4]);

    let mut start = LAMBDA_OVER_4;
    let z_poly_len = 32 * BITLEN_2GAMMA1_MINUS_ONE;

    for poly in &mut z_polys {
        *poly = bit_unpack_q8380417::<BITLEN_2GAMMA1_MINUS_ONE>(
            &sig_bytes[start..start + z_poly_len],
            (GAMMA1 - 1) as i32,
            GAMMA1 as i32
        );

        start += z_poly_len;
    }

    let hint = hint_bit_unpack::<K, OMEGA>(&sig_bytes[start..])
        .map_err(|_| MlDsaError::InvalidSignature)?;

    Ok(DecodedSignature{
        c_tilde,
        z: PolyVec::from_polys(z_polys),
        hint
    })
}



#[cfg(test)]
mod tests {
    use super::*;
    use mlrust_core::params::N;

    fn poly_from_fn<F>(mut f: F) -> Poly<Q8380417>
    where
        F: FnMut(usize) -> i32,
    {
        let mut coeffs = [0i32; N];

        for (i, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = f(i);
        }

        Poly::from_coeffs(coeffs)
    }

    #[test]
    fn sig_encode_decode_roundtrip() {
        const K: usize = 2;
        const L: usize = 2;
        const LAMBDA_OVER_4: usize = 8;
        const GAMMA1: usize = 4;
        const BITLEN_2GAMMA1_MINUS_ONE: usize = 3;
        const OMEGA: usize = 8;
        const SIG_BYTES: usize =
            LAMBDA_OVER_4 + L * 32 * BITLEN_2GAMMA1_MINUS_ONE + OMEGA + K;

        let c_tilde = [9u8; LAMBDA_OVER_4];

        let z = PolyVec::from_polys([
            poly_from_fn(|i| match i % 8 {
                0 => -3,
                1 => -2,
                2 => -1,
                3 => 0,
                4 => 1,
                5 => 2,
                6 => 3,
                _ => 4,
            }),
            poly_from_fn(|i| match i % 8 {
                0 => 4,
                1 => 3,
                2 => 2,
                3 => 1,
                4 => 0,
                5 => -1,
                6 => -2,
                _ => -3,
            }),
        ]);

        let mut hint = HintVec::<K>::zero();
        hint.data_mut()[0][3] = 1;
        hint.data_mut()[1][255] = 1;

        let decoded = DecodedSignature { c_tilde, z, hint };

        let encoded = sig_encode::<
            K,
            L,
            LAMBDA_OVER_4,
            GAMMA1,
            BITLEN_2GAMMA1_MINUS_ONE,
            OMEGA,
            SIG_BYTES,
        >(&decoded);

        let decoded_again = sig_decode::<
            K,
            L,
            LAMBDA_OVER_4,
            GAMMA1,
            BITLEN_2GAMMA1_MINUS_ONE,
            OMEGA,
            SIG_BYTES,
        >(&encoded)
            .unwrap();

        assert_eq!(decoded_again.c_tilde, decoded.c_tilde);
        assert_eq!(decoded_again.z, decoded.z);
        assert_eq!(decoded_again.hint, decoded.hint);
    }

    #[test]
    fn sig_decode_rejects_bad_hint_without_panicking() {
        const K: usize = 2;
        const L: usize = 1;
        const LAMBDA_OVER_4: usize = 8;
        const GAMMA1: usize = 4;
        const BITLEN_2GAMMA1_MINUS_ONE: usize = 3;
        const OMEGA: usize = 4;
        const SIG_BYTES: usize =
            LAMBDA_OVER_4 + L * 32 * BITLEN_2GAMMA1_MINUS_ONE + OMEGA + K;

        let mut bytes = [0u8; SIG_BYTES];

        let hint_start = LAMBDA_OVER_4 + L * 32 * BITLEN_2GAMMA1_MINUS_ONE;

        // All delimiters are zero, so all OMEGA index bytes are unused.
        // A nonzero unused byte is non-canonical.
        bytes[hint_start] = 99;

        let sig = Signature::from_bytes(bytes);

        let result = sig_decode::<
            K,
            L,
            LAMBDA_OVER_4,
            GAMMA1,
            BITLEN_2GAMMA1_MINUS_ONE,
            OMEGA,
            SIG_BYTES,
        >(&sig);

        assert!(matches!(result, Err(MlDsaError::InvalidSignature)));
    }
}