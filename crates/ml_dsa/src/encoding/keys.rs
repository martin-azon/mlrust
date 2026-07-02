//! ML-DSA public-key and secret-key encoding.


use mlrust_core::encode::ml_dsa::{bit_pack_signed_q8380417, bit_unpack_q8380417, simple_bit_pack_q8380417, simple_bit_unpack_q8380417};
use mlrust_core::params::Q8380417;
use mlrust_core::poly::{Poly, PolyVec};
use crate::error::MlDsaError;
use crate::keys::{SecretKey, PublicKey};
use crate::constants::{BITLEN_Q_MINUS_ONE, BITLEN_Q_MINUS_ONE_MINUS_D};


/// Decoded ML-DSA secret key.
///
/// This is an internal algebraic representation used by signing.
pub(crate) struct DecodedSecretKey<const K: usize, const L: usize> {
    pub(crate) rho: [u8; 32],
    pub(crate) key: [u8; 32],
    pub(crate) tr: [u8; 64],
    pub(crate) s1: PolyVec<Q8380417, L>,
    pub(crate) s2: PolyVec<Q8380417, K>,
    pub(crate) t0: PolyVec<Q8380417, K>,
}


/// Decoded ML-DSA public key.
///
/// This is an internal algebraic representation used by verification.
pub(crate) struct DecodedPublicKey<const K: usize> {
    pub(crate) rho: [u8; 32],
    pub(crate) t1: PolyVec<Q8380417, K>,
}


#[inline]
fn coeffs_in_range(coeffs: &[i32], min: i32, max: i32) -> bool {
    coeffs.iter().all(|&c| min <= c && c <= max)
}

#[inline]
fn t0_bounds<const D: usize>() -> (i32, i32) {
    assert!(D > 0);
    assert!(D < 31);

    let two_d_minus_1 = 1i32 << (D - 1);

    (two_d_minus_1 - 1, two_d_minus_1)
}



/// FIPS 204 `pkEncode`.
///
/// Encodes the public seed `rho` and vector `t1` into an ML-DSA public key.
///
/// # Panics
///
/// Panics if `PK_BYTES` does not match the parameter-set public-key length, or
/// if any coefficient of `t1` is outside the expected packing range.
pub(crate) fn pk_encode<
    const K: usize,
    const D: usize,
    const PK_BYTES: usize,
>(dec_pk: &DecodedPublicKey<K>) -> PublicKey<PK_BYTES> {
    assert_eq!(PK_BYTES, 32 + 32 * K * (BITLEN_Q_MINUS_ONE - D));

    let mut pk_bytes = [0u8; PK_BYTES];

    let t1_polys = dec_pk.t1.polys();
    let bound = (1 << BITLEN_Q_MINUS_ONE_MINUS_D) - 1;
    let packed_len = 32 * BITLEN_Q_MINUS_ONE_MINUS_D;

    pk_bytes[0..32].copy_from_slice(&dec_pk.rho);

    let mut start = 32usize;

    for poly in t1_polys {
        simple_bit_pack_q8380417::<BITLEN_Q_MINUS_ONE_MINUS_D>(
            poly.coeffs(),
            bound,
            &mut pk_bytes[start..(start + packed_len)]
        );

        start += packed_len;
    }

    PublicKey::from_bytes(pk_bytes)
}



/// FIPS 204 `pkDecode`.
///
/// Decodes an ML-DSA public key into its internal algebraic representation.
///
/// # Errors
///
/// Returns [`MlDsaError::InvalidPublicKey`] if the parameter-set byte length is
/// inconsistent with the expected public-key layout.

pub(crate) fn pk_decode<
    const K: usize,
    const PK_BYTES: usize,
> (enc_pk: &PublicKey<PK_BYTES>) -> Result<DecodedPublicKey<K>, MlDsaError> {
    if PK_BYTES != 32 + 32 * K * BITLEN_Q_MINUS_ONE_MINUS_D {
        return Err(MlDsaError::InvalidPublicKey);
    }

    let pk_bytes = enc_pk.as_bytes();

    let mut rho = [0u8; 32];
    let mut t1_polys = [Poly::<Q8380417>::zero(); K];

    let bound = (1 << BITLEN_Q_MINUS_ONE_MINUS_D) - 1;
    let packed_len = 32 * BITLEN_Q_MINUS_ONE_MINUS_D;

    rho.copy_from_slice(&pk_bytes[0..32]);

    let mut start = 32usize;

    for poly in &mut t1_polys {
        *poly = simple_bit_unpack_q8380417::<BITLEN_Q_MINUS_ONE_MINUS_D>(
            &pk_bytes[start..(start + packed_len)],
            bound
        );

        start += packed_len;
    }

    Ok(DecodedPublicKey{
        rho,
        t1: PolyVec::from_polys(t1_polys)
    })
}



/// FIPS 204 `skEncode`.
///
/// Encodes the ML-DSA secret-key components into the standardized secret-key
/// byte representation.
///
/// # Panics
///
/// Panics if `SK_BYTES` does not match the parameter-set secret-key length, or
/// if one of the encoded polynomial coefficients is outside its required range.
pub(crate) fn sk_encode<
    const K: usize,
    const L: usize,
    const D: usize,
    const ETA: usize,
    const BITLEN_2ETA: usize,
    const SK_BYTES: usize,
> (
    dec_sk: &DecodedSecretKey<K, L>
) -> SecretKey<SK_BYTES> {
    assert_eq!(SK_BYTES, 128 + 32 * ((K + L) * BITLEN_2ETA + D * K));

    let mut sk_bytes = [0u8; SK_BYTES];

    let s1_polys = dec_sk.s1.polys();
    let s2_polys = dec_sk.s2.polys();
    let t0_polys = dec_sk.t0.polys();

    let eta = ETA as i32;
    let (t0_a, t0_b) = t0_bounds::<D>();

    let short_poly_len = 32 * BITLEN_2ETA;
    let t0_poly_len = 32 * D;

    sk_bytes[0..32].copy_from_slice(&dec_sk.rho);
    sk_bytes[32..64].copy_from_slice(&dec_sk.key);
    sk_bytes[64..128].copy_from_slice(&dec_sk.tr);

    let mut start = 128usize;

    for poly in s1_polys {
        bit_pack_signed_q8380417::<BITLEN_2ETA>(
            poly.coeffs(),
            eta,
            eta,
            &mut sk_bytes[start..start + short_poly_len],
        );

        start += short_poly_len;
    }

    for poly in s2_polys {
        bit_pack_signed_q8380417::<BITLEN_2ETA>(
            poly.coeffs(),
            eta,
            eta,
            &mut sk_bytes[start..start + short_poly_len],
        );

        start += short_poly_len;
    }

    for poly in t0_polys {
        bit_pack_signed_q8380417::<D>(
            poly.coeffs(),
            t0_a,
            t0_b,
            &mut sk_bytes[start..start + t0_poly_len],
        );

        start += t0_poly_len;
    }

    SecretKey::from_bytes(sk_bytes)
}



/// FIPS 204 `skDecode`.
///
/// Decodes an ML-DSA secret key into its internal algebraic representation.
///
/// This function rejects non-canonical `s1` and `s2` encodings that decode
/// outside `[-ETA, ETA]`.
///
/// # Errors
///
/// Returns [`MlDsaError::InvalidSecretKey`] if the parameter-set byte length is
/// inconsistent with the expected secret-key layout, or if a short secret
/// polynomial decodes to a coefficient outside `[-ETA, ETA]`.
pub(crate) fn sk_decode<
    const K: usize,
    const L: usize,
    const D: usize,
    const ETA: usize,
    const BITLEN_2ETA: usize,
    const SK_BYTES: usize,
> (enc_sk: &SecretKey<SK_BYTES>) -> Result<DecodedSecretKey<K, L>, MlDsaError> {
    if SK_BYTES != 128 + 32 * ((K + L) * BITLEN_2ETA + D * K) {
        return Err(MlDsaError::InvalidSecretKey);
    }

    let sk_bytes = enc_sk.as_bytes();

    let mut rho = [0u8; 32];
    let mut key = [0u8; 32];
    let mut tr = [0u8; 64];

    let mut s1_polys = [Poly::<Q8380417>::zero(); L];
    let mut s2_polys = [Poly::<Q8380417>::zero(); K];
    let mut t0_polys = [Poly::<Q8380417>::zero(); K];

    let eta = ETA as i32;
    let (t0_a, t0_b) = t0_bounds::<D>();

    let short_poly_len = 32 * BITLEN_2ETA;
    let t0_poly_len = 32 * D;

    rho.copy_from_slice(&sk_bytes[0..32]);
    key.copy_from_slice(&sk_bytes[32..64]);
    tr.copy_from_slice(&sk_bytes[64..128]);

    let mut start= 128usize;

    for poly in &mut s1_polys {
        *poly = bit_unpack_q8380417::<BITLEN_2ETA>(
            &sk_bytes[start..start + short_poly_len],
            eta,
            eta
        );

        if !coeffs_in_range(poly.coeffs(), -eta, eta) {
            return Err(MlDsaError::InvalidSecretKey);
        }

        start += short_poly_len;
    }

    for poly in &mut s2_polys {
        *poly = bit_unpack_q8380417::<BITLEN_2ETA>(
            &sk_bytes[start..start + short_poly_len],
            eta,
            eta
        );

        if !coeffs_in_range(poly.coeffs(), -eta, eta) {
            return Err(MlDsaError::InvalidSecretKey);
        }

        start += short_poly_len;
    }

    for poly in &mut t0_polys {
        *poly = bit_unpack_q8380417::<D>(
            &sk_bytes[start..start + t0_poly_len],
            t0_a,
            t0_b,
        );

        start += t0_poly_len;
    }

    let dec_sk = DecodedSecretKey{
        rho,
        key,
        tr,
        s1: PolyVec::from_polys(s1_polys),
        s2: PolyVec::from_polys(s2_polys),
        t0: PolyVec::from_polys(t0_polys),
    };
    Ok(dec_sk)
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
    fn pk_encode_decode_roundtrip() {
        const K: usize = 2;
        const D: usize = 13;
        const PK_BYTES: usize = 32 + 32 * K * 10;

        let rho = [7u8; 32];

        let t1 = PolyVec::from_polys([
            poly_from_fn(|i| (i as i32) % 1024),
            poly_from_fn(|i| ((3 * i) as i32) % 1024),
        ]);

        let decoded = DecodedPublicKey { rho, t1 };

        let encoded = pk_encode::<K, D, PK_BYTES>(&decoded);
        let decoded_again = pk_decode::<K, PK_BYTES>(&encoded).unwrap();

        assert_eq!(decoded_again.rho, decoded.rho);
        assert_eq!(decoded_again.t1, decoded.t1);
    }

    #[test]
    fn sk_encode_decode_roundtrip_eta2() {
        const K: usize = 2;
        const L: usize = 2;
        const D: usize = 13;
        const ETA: usize = 2;
        const BITLEN_2ETA: usize = 3;
        const SK_BYTES: usize = 128 + 32 * ((K + L) * BITLEN_2ETA + D * K);

        let rho = [1u8; 32];
        let key = [2u8; 32];
        let tr = [3u8; 64];

        let s1 = PolyVec::from_polys([
            poly_from_fn(|i| match i % 5 {
                0 => -2,
                1 => -1,
                2 => 0,
                3 => 1,
                _ => 2,
            }),
            poly_from_fn(|i| match i % 5 {
                0 => 2,
                1 => 1,
                2 => 0,
                3 => -1,
                _ => -2,
            }),
        ]);

        let s2 = PolyVec::from_polys([
            poly_from_fn(|i| match i % 3 {
                0 => -1,
                1 => 0,
                _ => 1,
            }),
            poly_from_fn(|i| match i % 3 {
                0 => 1,
                1 => 0,
                _ => -1,
            }),
        ]);

        let t0 = PolyVec::from_polys([
            poly_from_fn(|i| ((i as i32) % 8192) - 4095),
            poly_from_fn(|i| 4096 - ((i as i32) % 8192)),
        ]);

        let decoded = DecodedSecretKey {
            rho,
            key,
            tr,
            s1,
            s2,
            t0,
        };

        let encoded = sk_encode::<K, L, D, ETA, BITLEN_2ETA, SK_BYTES>(&decoded);
        let decoded_again =
            sk_decode::<K, L, D, ETA, BITLEN_2ETA, SK_BYTES>(&encoded).unwrap();

        assert_eq!(decoded_again.rho, decoded.rho);
        assert_eq!(decoded_again.key, decoded.key);
        assert_eq!(decoded_again.tr, decoded.tr);
        assert_eq!(decoded_again.s1, decoded.s1);
        assert_eq!(decoded_again.s2, decoded.s2);
        assert_eq!(decoded_again.t0, decoded.t0);
    }

    #[test]
    fn sk_decode_rejects_noncanonical_s1_eta2() {
        const K: usize = 1;
        const L: usize = 1;
        const D: usize = 13;
        const ETA: usize = 2;
        const BITLEN_2ETA: usize = 3;
        const SK_BYTES: usize = 128 + 32 * ((K + L) * BITLEN_2ETA + D * K);

        let mut bytes = [0u8; SK_BYTES];

        // First s1 coefficient is encoded as y = 7.
        // BitUnpack maps coeff = eta - y = 2 - 7 = -5,
        // which is outside [-2, 2] and must be rejected.
        bytes[128] = 0b0000_0111;

        let sk = SecretKey::from_bytes(bytes);

        let result = sk_decode::<K, L, D, ETA, BITLEN_2ETA, SK_BYTES>(&sk);

        assert!(matches!(result, Err(MlDsaError::InvalidSecretKey)));
    }
}