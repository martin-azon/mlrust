//! ML-KEM coefficient compression and decompression.
//!
//! This module implements the coefficient-level compression primitives used by
//! ML-KEM over the modulus `q = 3329`.
//!
//! These operations are lossy for `D < 12`. They are used by ML-KEM ciphertext
//! compression and by the byte encoding of compressed polynomial coefficients.

use crate::encode::bits::{bit_pack, bit_unpack};
use crate::params::{N, Q3329, RingParams};
use crate::poly::{Poly, PolyVec};

/// Division-free ML-KEM compression for `q = 3329`.
///
/// # Side-channel note
///
/// ML-KEM compression is used during decapsulation re-encryption. Its inputs
/// are therefore secret-dependent in the decapsulation path.
///
/// This function intentionally avoids division by `3329`. Secret-dependent
/// division by the public modulus is the KyberSlash class of timing leakage.
/// Instead, this uses exact reciprocal-multiplication replacements for the
/// ML-KEM compression widths used by FIPS 203.
///
/// For every canonical coefficient `0 <= x < 3329`, this computes the same
/// value as:
///
/// ```text
/// round((2^D * x) / 3329) mod 2^D
/// ```
///
/// without a data-dependent division.
///
/// Supported widths:
///
/// - `D = 1`: message-bit compression;
/// - `D = 4`: ML-KEM-512/768 `v` compression;
/// - `D = 5`: ML-KEM-1024 `v` compression;
/// - `D = 10`: ML-KEM-512/768 `u` compression;
/// - `D = 11`: ML-KEM-1024 `u` compression.
#[inline]
fn compress_q3329_coefficient<const D: usize>(x: i32) -> u16 {
    assert!(matches!(D, 1 | 4 | 5 | 10 | 11));

    let x = Q3329::freeze(x) as u32;

    let (rounding, multiplier, shift): (u64, u64, u32) = match D {
        1 | 4 => (1_665, 80_635, 28),
        5 => (1_664, 40_318, 27),
        10 => (1_665, 1_290_167, 32),
        11 => (1_664, 645_084, 31),
        _ => unreachable!("unsupported ML-KEM compression width"),
    };

    let scaled = ((x as u64) << D) + rounding;
    let rounded = (scaled * multiplier) >> shift;

    (rounded as u16) & ((1u16 << D) - 1)
}

#[inline]
fn decompress_q3329_coefficient<const D: usize>(y: u16) -> i32 {
    assert!(D > 0);
    assert!(D <= 12);

    let mask = (1u32 << D) - 1;
    let y = (y as u32) & mask;

    (((Q3329::Q as u32) * y + (1u32 << (D - 1))) >> D) as i32
}

/// Compresses one coefficient modulo `q = 3329`
///
/// ```text
/// Compress_d(x) = round((2^D * x) / 3329) mod 2^D
/// ```
///
/// This is a division-free ML-KEM compression routine. See
/// [`compress_q3329_coefficient`] for the side-channel rationale.
#[must_use]
pub fn compress_q3329<const D: usize>(x: i32) -> u16 {
    compress_q3329_coefficient::<D>(x)
}

/// Decompresses one coefficient modulo `q = 3329`.
///
/// ```text
/// Decompress_d(y) = round((q / 2^d) * y)
/// ```
///
/// This uses a shift by `D` rather than division by `2^D`.
#[must_use]
pub fn decompress_q3329<const D: usize>(y: u16) -> i32 {
    decompress_q3329_coefficient::<D>(y)
}

/// Compresses each coefficient of a polynomial modulo `q = 3329`.
///
/// # Side-channel note
///
/// This routine is used in K-PKE encryption and in ML-KEM decapsulation
/// re-encryption. It must remain division-free.
#[must_use]
pub fn compress_q3329_poly<const D: usize>(p: &Poly<Q3329>) -> Poly<Q3329> {
    assert!(matches!(D, 1 | 4 | 5 | 10 | 11));

    let mut coeffs = p.into_coeffs();

    for coeff in coeffs.iter_mut() {
        *coeff = compress_q3329_coefficient::<D>(*coeff) as i32;
    }

    Poly::from_coeffs(coeffs)
}

/// Decompresses all coefficients of a polynomial.
/// These are initially integers modulo `2^D` and turned into integers modulo `q`.
#[must_use]
pub fn decompress_q3329_poly<const D: usize>(p: &Poly<Q3329>) -> Poly<Q3329> {
    assert!(D > 0);
    assert!(D <= 12);

    let mut coeffs = p.into_coeffs();

    for coeff in coeffs.iter_mut() {
        *coeff = decompress_q3329_coefficient::<D>(*coeff as u16);
    }

    Poly::from_coeffs(coeffs)
}

/// Compresses each coefficient of a polynomial vector modulo `q = 3329`.
///
/// # Side-channel note
///
/// This routine is used in K-PKE encryption and in ML-KEM decapsulation
/// re-encryption. It must remain division-free.
#[must_use]
pub fn compress_q3329_polyvec<const K: usize, const D: usize>(
    pv: &PolyVec<Q3329, K>,
) -> PolyVec<Q3329, K> {
    let mut polys_output = [Poly::<Q3329>::zero(); K];

    for i in 0..K {
        polys_output[i] = compress_q3329_poly::<D>(&pv.polys()[i]);
    }

    PolyVec::from_polys(polys_output)
}

/// Decompresses all polynomials in a vector of polynomials.
#[must_use]
pub fn decompress_q3329_polyvec<const K: usize, const D: usize>(
    v: &PolyVec<Q3329, K>,
) -> PolyVec<Q3329, K> {
    let mut polys = [Poly::<Q3329>::zero(); K];

    for i in 0..K {
        polys[i] = decompress_q3329_poly::<D>(&v.polys()[i]);
    }

    PolyVec::from_polys(polys)
}

/// Encodes one ML-KEM polynomial using `ByteEncode_D`.
///
/// The output length must be exactly `32 * D` bytes.
///
/// # Representation
///
/// For `D = 12`, coefficients are interpreted modulo `q = 3329` and are
/// canonicalized before packing.
///
/// For `D < 12`, coefficients are expected to already be `D`-bit values,
/// typically produced by `Compress_D`.
///
/// # Panics
///
/// Panics if:
///
/// - `D == 0`;
/// - `D > 12`;
/// - `out.len() != 32 * D`;
/// - for `D < 12`, a coefficient is outside `[0, 2^D)`.
pub fn byte_encode_poly_q3329<const D: usize>(poly: &Poly<Q3329>, out: &mut [u8]) {
    assert!(D > 0);
    assert!(D <= 12);
    assert_eq!(out.len(), 32 * D);

    let mut values = [0i32; N];

    for (value, &coeff) in values.iter_mut().zip(poly.coeffs()) {
        if D == 12 {
            *value = Q3329::freeze(coeff);
        } else {
            assert!(0 <= coeff);
            assert!(coeff < (1i32 << D));

            *value = coeff;
        }
    }

    bit_pack::<D>(&values, out);
}

/// Decodes one ML-KEM polynomial using `ByteDecode_D`.
///
/// The input length must be exactly `32 * D` bytes.
///
/// For `D = 12`, decoded coefficients are canonicalized modulo `q = 3329`.
/// For `D < 12`, decoded coefficients are returned as `D`-bit integers.
#[must_use]
pub fn byte_decode_poly_q3329<const D: usize>(input: &[u8]) -> Poly<Q3329> {
    assert!(D > 0);
    assert!(D <= 12);
    assert_eq!(input.len(), 32 * D);

    let mut coeffs = [0i32; N];

    bit_unpack::<D>(input, &mut coeffs);

    if D == 12 {
        for coeff in coeffs.iter_mut() {
            *coeff = Q3329::freeze(*coeff);
        }
    }

    Poly::from_coeffs(coeffs)
}

/// Encodes a vector of ML-KEM polynomials using `ByteEncode_D`.
///
/// The output layout is the concatenation of the encodings of the individual
/// polynomials:
///
/// ```text
/// ByteEncode_D(vec[0]) || ByteEncode_D(vec[1]) || ... || ByteEncode_D(vec[K-1])
/// ```
///
/// Each polynomial occupies `32 * D` bytes, so `out.len()` must be
/// `K * 32 * D`.
pub fn byte_encode_polyvec_q3329<const K: usize, const D: usize>(
    vec: &PolyVec<Q3329, K>,
    out: &mut [u8],
) {
    assert!(D > 0);
    assert!(D <= 12);

    let poly_bytes = 32 * D;

    assert_eq!(out.len(), K * poly_bytes);

    for i in 0..K {
        let start = i * poly_bytes;
        let end = start + poly_bytes;

        byte_encode_poly_q3329::<D>(&vec.polys()[i], &mut out[start..end]);
    }
}

/// Decodes a vector of ML-KEM polynomials using `ByteDecode_D`.
///
/// The input layout is the concatenation of `K` polynomial encodings, each of
/// length `32 * D` bytes.
#[must_use]
pub fn byte_decode_polyvec_q3329<const K: usize, const D: usize>(
    input: &[u8],
) -> PolyVec<Q3329, K> {
    assert!(D > 0);
    assert!(D <= 12);

    let poly_bytes = 32 * D;

    assert_eq!(input.len(), K * poly_bytes);

    let mut polys = [Poly::<Q3329>::zero(); K];

    for i in 0..K {
        let start = i * poly_bytes;
        let end = start + poly_bytes;

        polys[i] = byte_decode_poly_q3329::<D>(&input[start..end]);
    }

    PolyVec::from_polys(polys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_bits_d1() {
        let values = [0i32, 1, 1, 0, 1, 0, 0, 1];
        let mut bytes = [0u8; 1];
        let mut recovered = [0i32; 8];

        bit_pack::<1>(&values, &mut bytes);
        bit_unpack::<1>(&bytes, &mut recovered);

        assert_eq!(recovered, values);
    }

    #[test]
    fn pack_unpack_bits_d4() {
        let values = [0i32, 1, 2, 3, 4, 5, 14, 15];
        let mut bytes = [0u8; 4];
        let mut recovered = [0i32; 8];

        bit_pack::<4>(&values, &mut bytes);
        bit_unpack::<4>(&bytes, &mut recovered);

        assert_eq!(recovered, values);
    }

    #[test]
    fn pack_unpack_bits_d10() {
        let values = [0i32, 1, 2, 511, 512, 777, 1022, 1023];
        let mut bytes = [0u8; 10];
        let mut recovered = [0i32; 8];

        bit_pack::<10>(&values, &mut bytes);
        bit_unpack::<10>(&bytes, &mut recovered);

        assert_eq!(recovered, values);
    }

    #[test]
    fn pack_bits_d4_known_output() {
        let values = [0x1i32, 0x2, 0x3, 0x4];
        let mut bytes = [0u8; 2];

        bit_pack::<4>(&values, &mut bytes);

        // Low nibble is first value, high nibble is second value.
        assert_eq!(bytes, [0x21, 0x43]);
    }

    #[test]
    fn compress_q3329_outputs_fit_in_d_bits() {
        for d in [1usize, 4, 5, 10, 11] {
            for x in 0..Q3329::Q {
                let c = match d {
                    1 => compress_q3329::<1>(x),
                    4 => compress_q3329::<4>(x),
                    5 => compress_q3329::<5>(x),
                    10 => compress_q3329::<10>(x),
                    11 => compress_q3329::<11>(x),
                    _ => unreachable!(),
                };

                assert!(c < (1u16 << d), "d = {d}, x = {x}, c = {c}");
            }
        }
    }

    #[test]
    fn decompress_q3329_outputs_in_range() {
        for y in 0..(1u16 << 12) {
            let x = decompress_q3329::<12>(y);
            assert!((0..=Q3329::Q).contains(&x));
        }
    }

    #[test]
    fn compress_decompress_are_reasonable_q3329() {
        for d in [1usize, 4, 5, 10, 11] {
            let max = 1u16 << d;

            for y in 0..max {
                let x = match d {
                    1 => decompress_q3329::<1>(y),
                    4 => decompress_q3329::<4>(y),
                    5 => decompress_q3329::<5>(y),
                    10 => decompress_q3329::<10>(y),
                    11 => decompress_q3329::<11>(y),
                    _ => unreachable!(),
                };

                let y2 = match d {
                    1 => compress_q3329::<1>(x),
                    4 => compress_q3329::<4>(x),
                    5 => compress_q3329::<5>(x),
                    10 => compress_q3329::<10>(x),
                    11 => compress_q3329::<11>(x),
                    _ => unreachable!(),
                };

                assert_eq!(y2, y, "d = {d}, y = {y}, x = {x}");
            }
        }
    }

    #[test]
    fn byte_encode_decode_poly_q3329_d12_roundtrip_canonical() {
        let mut coeffs = [0i32; 256];

        for (i, c) in coeffs.iter_mut().enumerate() {
            *c = ((17 * i as i32 + 123) % Q3329::Q) - 100;
        }

        let poly = Poly::<Q3329>::from_coeffs(coeffs);

        let mut bytes = [0u8; 384];
        byte_encode_poly_q3329::<12>(&poly, &mut bytes);

        let decoded = byte_decode_poly_q3329::<12>(&bytes);

        for (i, coeff) in coeffs.iter().enumerate() {
            assert_eq!(
                decoded.coeffs()[i],
                Q3329::freeze(*coeff),
                "coefficient mismatch at {i}"
            );
        }
    }

    #[test]
    fn byte_encode_decode_polyvec_q3329_d12_roundtrip() {
        const K: usize = 3;

        let mut polys = [Poly::<Q3329>::zero(); K];

        for k in 0..K {
            let mut coeffs = [0i32; 256];

            for (i, c) in coeffs.iter_mut().enumerate() {
                *c = ((k as i32 + 1) * 19 * i as i32 + 7) % Q3329::Q;
            }

            polys[k] = Poly::<Q3329>::from_coeffs(coeffs);
        }

        let vec = PolyVec::<Q3329, K>::from_polys(polys);

        let mut bytes = [0u8; K * 384];
        byte_encode_polyvec_q3329::<K, 12>(&vec, &mut bytes);

        let decoded = byte_decode_polyvec_q3329::<K, 12>(&bytes);

        assert_eq!(decoded, vec);
    }

    #[test]
    fn byte_encode_polyvec_q3329_concatenates_polynomials() {
        const K: usize = 2;
        const D: usize = 12;

        let mut coeffs0 = [0i32; 256];
        let mut coeffs1 = [0i32; 256];

        for i in 0..256 {
            coeffs0[i] = i as i32;
            coeffs1[i] = (255 - i) as i32;
        }

        let p0 = Poly::<Q3329>::from_coeffs(coeffs0);
        let p1 = Poly::<Q3329>::from_coeffs(coeffs1);
        let vec = PolyVec::<Q3329, K>::from_polys([p0, p1]);

        let mut encoded_vec = [0u8; K * 384];
        byte_encode_polyvec_q3329::<K, D>(&vec, &mut encoded_vec);

        let mut encoded_p0 = [0u8; 384];
        let mut encoded_p1 = [0u8; 384];

        byte_encode_poly_q3329::<D>(&p0, &mut encoded_p0);
        byte_encode_poly_q3329::<D>(&p1, &mut encoded_p1);

        assert_eq!(&encoded_vec[..384], &encoded_p0);
        assert_eq!(&encoded_vec[384..], &encoded_p1);
    }

    #[test]
    fn compress_q3329_matches_reference_division_for_all_ml_kem_widths() {
        fn check<const D: usize>() {
            for x in 0..Q3329::Q {
                let expected = ((((x as u32) << D) + (Q3329::Q as u32 / 2)) / (Q3329::Q as u32))
                    & ((1u32 << D) - 1);

                assert_eq!(compress_q3329::<D>(x) as u32, expected, "D={D}, x={x}",);
            }
        }

        check::<1>();
        check::<4>();
        check::<5>();
        check::<10>();
        check::<11>();
    }
}
