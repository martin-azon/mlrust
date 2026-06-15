//! ML-KEM coefficient compression and decompression.
//!
//! This module implements the coefficient-level compression primitives used by
//! ML-KEM over the modulus `q = 3329`.
//!
//! These operations are lossy for `D < 12`. They are used by ML-KEM ciphertext
//! compression and by the byte encoding of compressed polynomial coefficients.

use crate::params::{N, Q3329, RingParams};
use crate::poly::{Poly, PolyVec};

fn round_div_u64(num: u64, den: u64) -> u64 {
    assert_ne!(den, 0);

    (num + den / 2) / den
}

/// Helper function that compresses an integer modulo `q` into an integer modulo `2^D`.
fn compress_q<const D: usize, P: RingParams>(x: i32) -> u16 {
    assert!(D > 0);
    assert!(D <= 16);

    let q = P::Q as u64;
    let x = P::freeze(x) as u64;
    let scale = 1u64 << D;

    let rounded = round_div_u64(scale * x, q);

    (rounded & (scale - 1)) as u16
}

/// Helper function that decompresses an integer modulo `2^D` into an integer modulo `q`.
fn decompress_q<const D: usize, P: RingParams>(y: u16) -> i32 {
    assert!(D > 0);
    assert!(D <= 16);

    let q = P::Q as u64;
    let scale = 1u64 << D;
    let y = (y as u64) & (scale - 1);

    round_div_u64(q * y, scale) as i32
}

/// Helper function that compresses all coefficients of a polynomial.
/// These are initially integers modulo `q` and turned into integers modulo `2^D`.
fn compress_q_poly<const D: usize, P: RingParams>(p: &Poly<P>) -> Poly<P> {
    assert!(D > 0);
    assert!(D <= 16);

    let mut coeffs = p.into_coeffs();

    for coeff in coeffs.iter_mut() {
        *coeff = compress_q::<D, P>(*coeff) as i32;
    }

    Poly::from_coeffs(coeffs)
}

/// Helper function that decompresses all coefficients of a polynomial.
/// These are initially integers modulo `2^D` and turned into integers modulo `q`.
fn decompress_q_poly<const D: usize, P: RingParams>(p: &Poly<P>) -> Poly<P> {
    assert!(D > 0);
    assert!(D <= 16);

    let mut coeffs = p.into_coeffs();

    for coeff in coeffs.iter_mut() {
        *coeff = decompress_q::<D, P>(*coeff as u16);
    }

    Poly::from_coeffs(coeffs)
}

/// Compresses an integer mod `q = 3329` into an integer mod `2^D`.
///
/// ```text
/// Compress_d(x) = round((2^d / q) * x) mod 2^d
/// ```
#[must_use]
pub fn compress_q3329<const D: usize>(x: i32) -> u16 {
    compress_q::<D, Q3329>(x)
}

/// Decompresses an integer mod `2^D` into an integer mod `q = 3329`.
///
/// ```text
/// Decompress_d(y) = round((q / 2^d) * y)
/// ```
#[must_use]
pub fn decompress_q3329<const D: usize>(y: u16) -> i32 {
    decompress_q::<D, Q3329>(y)
}

/// Compresses all coefficients of a polynomial.
/// These are initially integers modulo `q` and turned into integers modulo `2^D`.
#[must_use]
pub fn compress_q3329_poly<const D: usize>(p: &Poly<Q3329>) -> Poly<Q3329> {
    compress_q_poly::<D, Q3329>(p)
}

/// Decompresses all coefficients of a polynomial.
/// These are initially integers modulo `2^D` and turned into integers modulo `q`.
#[must_use]
pub fn decompress_q3329_poly<const D: usize>(p: &Poly<Q3329>) -> Poly<Q3329> {
    decompress_q_poly::<D, Q3329>(p)
}

/// Compresses all polynomials in a vector of polynomials.
#[must_use]
pub fn compress_q3329_polyvec<const K: usize, const D: usize>(
    v: &PolyVec<Q3329, K>,
) -> PolyVec<Q3329, K> {
    let mut polys = [Poly::<Q3329>::zero(); K];

    for     i in 0..K {
        polys[i] = compress_q3329_poly::<D>(&v.polys()[i]);
    }

    PolyVec::from_polys(polys)
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

/// Packs fixed-width unsigned integers into a byte slice.
///
/// This corresponds to the function ByteEncode_d from FIPS 203
///
/// # Panics
///
/// Panics if:
///
/// - `D == 0`;
/// - `D > 12`;
/// - `int_values.len() * D != output_bytes.len() * 8`.
pub fn pack_bits<const D: usize>(int_values: &[i32], output_bytes: &mut [u8]) {
    assert!(D > 0);
    assert!(D <= 12);
    assert_eq!(int_values.len() * D, output_bytes.len() * 8);

    output_bytes.fill(0);
    let mut bit_pos = 0usize;

    for &value in int_values {
        assert!(value < (1i32 << D));
        assert!(0 <= value);

        for j in 0..D {
            let bit = (value >> j) & 1;
            let byte_index = bit_pos / 8;
            let bit_index = bit_pos % 8;

            output_bytes[byte_index] |= (bit as u8) << bit_index;
            bit_pos += 1;
        }
    }
}

/// Unpacks fixed-width unsigned values from a byte slice.
///
/// This corresponds to the function ByteDecode_d from FIPS 203
pub fn unpack_bits<const D: usize>(byt_values: &[u8], output_ints: &mut [i32]) {
    assert!(D > 0);
    assert!(D <= 12);
    assert_eq!(byt_values.len() * 8, output_ints.len() * D);

    let mut bit_pos = 0usize;

    for intg in output_ints.iter_mut() {
        let mut acc = 0i32;

        for k in 0..D {
            let byte_index = bit_pos / 8;
            let bit_index = bit_pos % 8;

            let bit = (byt_values[byte_index] >> bit_index) & 1;
            acc |= (bit as i32) << k;

            bit_pos += 1;
        }

        *intg = acc;
    }
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

    for (value, &coeff) in values.iter_mut().zip(poly.coeffs().iter()) {
        if D == 12 {
            *value = Q3329::freeze(coeff);
        } else {
            assert!(0 <= coeff);
            assert!(coeff < (1i32 << D));

            *value = coeff;
        }
    }

    pack_bits::<D>(&values, out);
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

    unpack_bits::<D>(input, &mut coeffs);

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

        pack_bits::<1>(&values, &mut bytes);
        unpack_bits::<1>(&bytes, &mut recovered);

        assert_eq!(recovered, values);
    }

    #[test]
    fn pack_unpack_bits_d4() {
        let values = [0i32, 1, 2, 3, 4, 5, 14, 15];
        let mut bytes = [0u8; 4];
        let mut recovered = [0i32; 8];

        pack_bits::<4>(&values, &mut bytes);
        unpack_bits::<4>(&bytes, &mut recovered);

        assert_eq!(recovered, values);
    }

    #[test]
    fn pack_unpack_bits_d10() {
        let values = [0i32, 1, 2, 511, 512, 777, 1022, 1023];
        let mut bytes = [0u8; 10];
        let mut recovered = [0i32; 8];

        pack_bits::<10>(&values, &mut bytes);
        unpack_bits::<10>(&bytes, &mut recovered);

        assert_eq!(recovered, values);
    }

    #[test]
    fn pack_bits_d4_known_output() {
        let values = [0x1i32, 0x2, 0x3, 0x4];
        let mut bytes = [0u8; 2];

        pack_bits::<4>(&values, &mut bytes);

        // Low nibble is first value, high nibble is second value.
        assert_eq!(bytes, [0x21, 0x43]);
    }

    #[test]
    fn compress_q3329_outputs_fit_in_d_bits() {
        for d in [1usize, 4, 5, 10, 11, 12] {
            for x in 0..Q3329::Q {
                let c = match d {
                    1 => compress_q3329::<1>(x),
                    4 => compress_q3329::<4>(x),
                    5 => compress_q3329::<5>(x),
                    10 => compress_q3329::<10>(x),
                    11 => compress_q3329::<11>(x),
                    12 => compress_q3329::<12>(x),
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
}
