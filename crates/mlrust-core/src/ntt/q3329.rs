//! NTT implementation for the ML-KEM modulus q = 3329.


use super::q3329_tables;
use crate::params::{N, RingParams, NttParams, Q3329};


impl NttParams for Q3329 {
    const ZETAS: &'static [i32] = q3329_tables::FIPS_ZETAS_BITREV;
    const BASE_MUL_ZETAS: &'static [i32] = q3329_tables::FIPS_BASEMUL_ZETAS;
    const INV_NTT_SCALE: i32 = q3329_tables::INV_NTT_SCALE;
}


/// Base multiplication of two degree-1 polynomial fragments.
///
/// Computes:
///
/// ```text
/// (a0 + a1 x)(b0 + b1 x) mod (x^2 - zeta)
/// ```
pub fn base_mul<P: RingParams>(
    a0: i32,
    a1: i32,
    b0: i32,
    b1: i32,
    zeta: i32,
) -> (i32, i32) {
    let a0b0 = P::montgomery_reduce((a0 as i64) * (b0 as i64));
    let a1b1 = P::montgomery_reduce((a1 as i64) * (b1 as i64));
    let za1b1 = P::montgomery_reduce((zeta as i64) * (a1b1 as i64));
    let deg0 = P::barrett_reduce(a0b0 + za1b1);

    let a0b1 = P::montgomery_reduce((a0 as i64) * (b1 as i64));
    let a1b0 = P::montgomery_reduce((a1 as i64) * (b0 as i64));
    let deg1 = P::barrett_reduce(a0b1 + a1b0);

    (deg0, deg1)
}


/// Applies the forward NTT in place.
pub fn ntt_in_place<P: NttParams>(a: &mut [i32; N]) {
    let mut i = 0usize;
    let mut len = 2usize;

    while len <= 128 {
        let mut start = 0;

        while start < N {
            let zeta = P::ZETAS[i];
            i += 1;

            for j in start..(start + len) {
                let t = P::montgomery_reduce((zeta as i64) * (a[j + len] as i64));
                let u = a[j];

                a[j + len] = P::barrett_reduce(u - t);
                a[j] = P::barrett_reduce(u + t);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    for coeff in a.iter_mut() {
        *coeff = P::montgomery_reduce((*coeff as i64) * (P::INV_NTT_SCALE as i64));
    }
}


/// Applies the inverse NTT in place.
pub fn inv_ntt_in_place<P: NttParams>(a: &mut [i32; N]) {
    let mut i = 127usize;
    let mut len = 128usize;

    while len >= 2 {
        let mut start = 0;

        while start < N {
            let zeta = P::ZETAS[i];
            i -= 1;

            for j in start..(start + len) {
                let t = a[j];
                let u = a[j + len];

                a[j] = P::barrett_reduce(t + u);
                let tmp = P::barrett_reduce(u - t);
                a[j + len] = P::montgomery_reduce((zeta as i64) * (tmp as i64));
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

























