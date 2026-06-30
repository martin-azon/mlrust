//! ML-DSA byte-string-to-polynomial conversions for sparse binary polynomials.


use crate::params::{Q8380417, N};
use crate::encode::bits::{bit_pack, bit_unpack, bitlen_u32};
use crate::poly::Poly;



pub struct HintVec<const K: usize> {
    polys: [[u8; N]; K]
}


impl<const K: usize> HintVec<K> {
    /// Creates a Hint Vector from a fixed-size array of indices.
    pub const fn from_polys(polys: [[u8; N]; K]) -> Self {
        Self { polys }
    }

    /// Returns an immutable reference to the polynomial array.
    #[must_use]
    pub fn polys(&self) -> &[[u8; N]; K] {
        &self.polys
    }

    /// Returns a mutable reference to the polynomial array.
    #[must_use]
    pub fn polys_mut(&mut self) -> &mut [[u8; N]; K] {
        &mut self.polys
    }
}



/// FIPS 204 HintBitPack.
pub fn hint_bit_pack<const K: usize, const OMEGA: usize>(
    h: HintVec<K>,
    out: &mut [u8]
) {
    assert_eq!(out.len(), K + OMEGA);

    out.fill(0);

    let mut index = 0usize;
    let polys = h.polys();

    for i in 0..(K - 1) {
        for j in 0..N {
            if polys[i][j] == 1 {
                out[index] = j as u8;
                index += 1;
            }
        }
        out[OMEGA + i] = index as u8;
    }
}


#[must_use]
pub fn hint_bit_unpack<const K: usize, const OMEGA: usize>(
    bytes: & [u8]
) -> Option<HintVec<K>> {
    let mut h = HintVec{ polys: [[0u8; N]; K] };
    let mut index = 0usize;

    for i in 0..K {
        if (bytes[OMEGA + i] < (index as u8)) || (bytes[OMEGA + i] > (OMEGA as u8)) {

        }
    }


    todo!()
}