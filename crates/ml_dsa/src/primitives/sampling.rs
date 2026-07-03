//! ML-DSA sampling routines.

use mlrust_core::encode::bits::bytes_to_bits;
use mlrust_core::encode::ml_dsa::coeff_from_three_bytes;
use mlrust_core::params::{Q8380417, N};
use mlrust_core::poly::Poly;
use mlrust_core::symmetric::ml_dsa::{g_absorb, g_squeeze, h_absorb, h_squeeze};

pub(crate) fn sample_in_ball<
    const LAMBDA_OVER_4: usize,
    const TAU: usize,
>(rho: &[u8]) -> Poly<Q8380417> {
    assert_eq!(rho.len(), LAMBDA_OVER_4);

    let mut c_coeffs = [0i32; N];

    let mut s = [0u8; 8];
    let mut h_bits = [0u8; 64];
    let mut j_byte = [0u8; 1];

    let mut reader = h_absorb(rho);
    h_squeeze(&mut reader, &mut s);
    bytes_to_bits(&s, &mut h_bits);

    for i in (N - TAU)..N {
        h_squeeze(&mut reader, &mut j_byte);

        while j_byte[0] as usize > i {
            h_squeeze(&mut reader, &mut j_byte);
        }

        let j = j_byte[0] as usize;
        c_coeffs[i] = c_coeffs[j];
        c_coeffs[j] = 1 - 2 * ((h_bits[i + TAU - 256] & 1) as i32);
    }

    Poly::<Q8380417>::from_coeffs(c_coeffs)
}


pub(crate) fn rej_ntt_poly(rho: &[u8]) -> Poly<Q8380417> {
    assert_eq!(rho.len(), 34);

    let mut a_coeffs = [0i32; N];

    let mut j = 0usize;

    let mut reader = g_absorb(rho);

    let mut s = [0u8; 3];

    while j < 256 {
        g_squeeze(&mut reader, &mut s);

        if let Some(z) = coeff_from_three_bytes(s[0], s[1], s[2]) {
            a_coeffs[j] = z;
            j += 1;
        }
    }

    Poly::<Q8380417>::from_coeffs(a_coeffs)
}