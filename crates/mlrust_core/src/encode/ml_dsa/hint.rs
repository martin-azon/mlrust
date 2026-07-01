//! ML-DSA hint-vector encoding and decoding.
//!
//! This module implements the FIPS 204 `HintBitPack` and `HintBitUnpack`
//! routines.
//!
//! ML-DSA hints are sparse binary vectors of polynomials. They are not ring
//! elements over `q`; they are binary masks indicating which coefficient
//! positions require a hint during verification. Therefore this module uses a
//! dedicated [`HintVec`] representation rather than `Poly<Q8380417>` or
//! `PolyVec<Q8380417, K>`.


use crate::params::N;
use crate::error::PqcCoreError;



/// Binary ML-DSA hint vector.
///
/// A hint vector contains `K` binary polynomials, each with `N = 256`
/// coefficients. Each coefficient must be either `0` or `1`.
///
/// This type is intentionally separate from `Poly<Q8380417>` because hints are
/// not arithmetic ring elements; they are sparse binary masks used in ML-DSA
/// signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HintVec<const K: usize> {
    polys: [[u8; N]; K]
}


impl<const K: usize> HintVec<K> {
    /// Creates a hint vector from binary coefficient arrays.
    ///
    /// This constructor does not check that the coefficients are binary.
    /// Encoding routines such as [`hint_bit_pack`] validate that every
    /// coefficient is either `0` or `1`.
    pub const fn from_polys(polys: [[u8; N]; K]) -> Self {
        Self { polys }
    }

    /// Creates the all-zero hint vector.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            polys: [[0u8; N]; K],
        }
    }

    /// Returns the underlying binary polynomial array.
    #[must_use]
    pub fn polys(&self) -> &[[u8; N]; K] {
        &self.polys
    }

    /// Returns a mutable reference to the underlying binary polynomial array.
    #[must_use]
    pub fn polys_mut(&mut self) -> &mut [[u8; N]; K] {
        &mut self.polys
    }
}



/// FIPS 204 `HintBitPack`.
///
/// Encodes a sparse binary hint vector into its canonical byte representation.
///
/// The first `OMEGA` bytes contain the sorted coefficient indices where the
/// hint vector has value `1`. The final `K` bytes contain cumulative endpoint
/// delimiters for each polynomial.
///
/// The unused index bytes after the final used position are set to zero.
///
/// # Panics
///
/// Panics if:
///
/// - `out.len() != OMEGA + K`;
/// - `OMEGA > 255`;
/// - a hint coefficient is not `0` or `1`;
/// - the total number of set hint bits exceeds `OMEGA`.
pub fn hint_bit_pack<const K: usize, const OMEGA: usize>(
    h: &HintVec<K>,
    out: &mut [u8]
) {
    assert_eq!(out.len(), K + OMEGA);

    out.fill(0);

    let mut index = 0usize;
    let polys = h.polys();

    for i in 0..K {
        for j in 0..N {
            let bit = polys[i][j];

            assert!(bit == 0 || bit == 1);

            if bit == 1 {
                assert!(index < OMEGA);

                out[index] = j as u8;
                index += 1;
            }
        }
        out[OMEGA + i] = index as u8;
    }
}


/// FIPS 204 `HintBitUnpack`.
///
/// Decodes a sparse binary hint vector from its canonical byte representation.
///
/// The input must have length `OMEGA + K`. The first `OMEGA` bytes contain
/// coefficient indices. The final `K` bytes contain cumulative endpoint
/// delimiters.
///
/// This function rejects malformed or non-canonical encodings.
///
/// # Errors
///
/// Returns:
///
/// - [`PqcCoreError::InvalidLength`] if `input.len() != OMEGA + K`;
/// - [`PqcCoreError::InvalidEncoding`] if a delimiter is out of range or
///   decreases;
/// - [`PqcCoreError::NonCanonicalEncoding`] if indices inside one polynomial
///   are not strictly increasing, or if unused index bytes are nonzero.
#[must_use]
pub fn hint_bit_unpack<const K: usize, const OMEGA: usize>(
    input: & [u8]
) -> Result<HintVec<K>, PqcCoreError> {
    if input.len() != K + OMEGA {
        return Err(PqcCoreError::InvalidLength);
    }

    let mut h = [[0u8; N]; K];
    let mut start = 0usize;

    for i in 0..K {
        let end = input[OMEGA + i] as usize;

        if end > OMEGA {
            return Err(PqcCoreError::InvalidEncoding);
        }

        if end < start {
            return Err(PqcCoreError::InvalidEncoding);
        }

        for pos in start..end {
            let j = input[pos] as usize;

            if j >= N {
                return Err(PqcCoreError::InvalidEncoding);
            }

            if pos > start && input[pos] <= input[pos - 1] {
                return Err(PqcCoreError::NonCanonicalEncoding);
            }

            h[i][j] = 1;
        }

        start = end;
    }
    for &unused in &input[start..OMEGA] {
        if unused != 0 {
            return Err(PqcCoreError::NonCanonicalEncoding);
        }
    }
    Ok(HintVec::from_polys(h))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hint_vec_zero_is_all_zero() {
        let h = HintVec::<4>::zero();

        for poly in h.polys() {
            for &bit in poly {
                assert_eq!(bit, 0);
            }
        }
    }

    #[test]
    fn hint_bit_pack_all_zero() {
        const K: usize = 4;
        const OMEGA: usize = 8;

        let h = HintVec::<K>::zero();
        let mut out = [0xffu8; OMEGA + K];

        hint_bit_pack::<K, OMEGA>(&h, &mut out);

        assert_eq!(out, [0u8; OMEGA + K]);
    }

    #[test]
    fn hint_bit_pack_known_sparse_vector() {
        const K: usize = 4;
        const OMEGA: usize = 8;

        let mut h = HintVec::<K>::zero();

        h.polys_mut()[0][3] = 1;
        h.polys_mut()[0][7] = 1;
        h.polys_mut()[2][1] = 1;
        h.polys_mut()[3][255] = 1;

        let mut out = [0u8; OMEGA + K];

        hint_bit_pack::<K, OMEGA>(&h, &mut out);

        // Index bytes:
        // poly 0: 3, 7
        // poly 1: none
        // poly 2: 1
        // poly 3: 255
        //
        // Delimiters:
        // after poly 0: 2
        // after poly 1: 2
        // after poly 2: 3
        // after poly 3: 4
        assert_eq!(
            out,
            [
                3, 7, 1, 255, 0, 0, 0, 0,
                2, 2, 3, 4,
            ]
        );
    }

    #[test]
    fn hint_bit_pack_unpack_roundtrip() {
        const K: usize = 4;
        const OMEGA: usize = 8;

        let mut h = HintVec::<K>::zero();

        h.polys_mut()[0][0] = 1;
        h.polys_mut()[0][10] = 1;
        h.polys_mut()[1][5] = 1;
        h.polys_mut()[3][255] = 1;

        let mut encoded = [0u8; OMEGA + K];

        hint_bit_pack::<K, OMEGA>(&h, &mut encoded);

        let decoded = hint_bit_unpack::<K, OMEGA>(&encoded).unwrap();

        assert_eq!(decoded, h);
    }

    #[test]
    fn hint_bit_unpack_known_sparse_vector() {
        const K: usize = 4;
        const OMEGA: usize = 8;

        let input = [
            3, 7, 1, 255, 0, 0, 0, 0,
            2, 2, 3, 4,
        ];

        let h = hint_bit_unpack::<K, OMEGA>(&input).unwrap();

        assert_eq!(h.polys()[0][3], 1);
        assert_eq!(h.polys()[0][7], 1);
        assert_eq!(h.polys()[1].iter().sum::<u8>(), 0);
        assert_eq!(h.polys()[2][1], 1);
        assert_eq!(h.polys()[3][255], 1);
    }

    #[test]
    fn hint_bit_unpack_rejects_wrong_length() {
        const K: usize = 4;
        const OMEGA: usize = 8;

        let input = [0u8; OMEGA + K - 1];

        let err = hint_bit_unpack::<K, OMEGA>(&input).unwrap_err();

        assert_eq!(err, PqcCoreError::InvalidLength);
    }

    #[test]
    fn hint_bit_unpack_rejects_delimiter_out_of_range() {
        const K: usize = 4;
        const OMEGA: usize = 8;

        let mut input = [0u8; OMEGA + K];
        input[OMEGA] = 9;

        let err = hint_bit_unpack::<K, OMEGA>(&input).unwrap_err();

        assert_eq!(err, PqcCoreError::InvalidEncoding);
    }

    #[test]
    fn hint_bit_unpack_rejects_decreasing_delimiter() {
        const K: usize = 4;
        const OMEGA: usize = 8;

        let mut input = [0u8; OMEGA + K];

        input[0] = 1;
        input[1] = 2;

        input[OMEGA] = 2;
        input[OMEGA + 1] = 1;

        let err = hint_bit_unpack::<K, OMEGA>(&input).unwrap_err();

        assert_eq!(err, PqcCoreError::InvalidEncoding);
    }

    #[test]
    fn hint_bit_unpack_rejects_unsorted_indices() {
        const K: usize = 4;
        const OMEGA: usize = 8;

        let mut input = [0u8; OMEGA + K];

        input[0] = 7;
        input[1] = 3;

        input[OMEGA] = 2;
        input[OMEGA + 1] = 2;
        input[OMEGA + 2] = 2;
        input[OMEGA + 3] = 2;

        let err = hint_bit_unpack::<K, OMEGA>(&input).unwrap_err();

        assert_eq!(err, PqcCoreError::NonCanonicalEncoding);
    }

    #[test]
    fn hint_bit_unpack_rejects_duplicate_indices() {
        const K: usize = 4;
        const OMEGA: usize = 8;

        let mut input = [0u8; OMEGA + K];

        input[0] = 7;
        input[1] = 7;

        input[OMEGA] = 2;
        input[OMEGA + 1] = 2;
        input[OMEGA + 2] = 2;
        input[OMEGA + 3] = 2;

        let err = hint_bit_unpack::<K, OMEGA>(&input).unwrap_err();

        assert_eq!(err, PqcCoreError::NonCanonicalEncoding);
    }

    #[test]
    fn hint_bit_unpack_rejects_nonzero_unused_bytes() {
        const K: usize = 4;
        const OMEGA: usize = 8;

        let mut input = [0u8; OMEGA + K];

        input[0] = 3;
        input[OMEGA] = 1;
        input[OMEGA + 1] = 1;
        input[OMEGA + 2] = 1;
        input[OMEGA + 3] = 1;

        // This byte is after the final used index, so it must be zero.
        input[1] = 99;

        let err = hint_bit_unpack::<K, OMEGA>(&input).unwrap_err();

        assert_eq!(err, PqcCoreError::NonCanonicalEncoding);
    }

    #[test]
    #[should_panic]
    fn hint_bit_pack_rejects_non_binary_coefficient() {
        const K: usize = 4;
        const OMEGA: usize = 8;

        let mut h = HintVec::<K>::zero();
        h.polys_mut()[0][0] = 2;

        let mut out = [0u8; OMEGA + K];

        hint_bit_pack::<K, OMEGA>(&h, &mut out);
    }

    #[test]
    #[should_panic]
    fn hint_bit_pack_rejects_too_many_hints() {
        const K: usize = 1;
        const OMEGA: usize = 2;

        let mut h = HintVec::<K>::zero();

        h.polys_mut()[0][0] = 1;
        h.polys_mut()[0][1] = 1;
        h.polys_mut()[0][2] = 1;

        let mut out = [0u8; OMEGA + K];

        hint_bit_pack::<K, OMEGA>(&h, &mut out);
    }
}