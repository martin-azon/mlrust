//! NTT implementation for the ML-DSA modulus q = 8380417.


use super::q8380417_tables::{FIPS_ZETAS_MONT, INV_NTT_SCALE_MONT};
use crate::params::{N, RingParams, NttParams, NttOps, NttDomainMul, Q8380417};
use crate::field::{mul_montgomery, add_mod, sub_mod};


impl NttParams for Q8380417 {
    const ZETAS_MONT: &'static [i32] = &FIPS_ZETAS_MONT;
    const INV_NTT_SCALE_MONT: i32 = INV_NTT_SCALE_MONT;
}


/// Applies the forward NTT in place.
pub fn ntt_in_place_q8380417(a: &mut [i32; N]) {
    for coeff in a.iter_mut() {
        *coeff = Q8380417::to_montgomery(*coeff);
    }

    let mut m = 0usize;
    let mut len = 128usize;

    while len >= 1 {
        let mut start = 0usize;
        while start < 256 {
            m += 1;
            let zeta_mont = Q8380417::ZETAS_MONT[m];
            for j in start..(start + len) {
                let t = mul_montgomery::<Q8380417>(zeta_mont, a[j + len]);
                let u = a[j];

                a[j + len] = sub_mod::<Q8380417>(u, t);
                a[j] = add_mod::<Q8380417>(u, t);
            }
            start += 2 * len;
        }

        len >>= 1;
    }
}


/// Applies the inverse NTT in place.
pub fn inv_ntt_in_place_q8380417(a: &mut [i32; N]) {
    let mut m = 256usize;
    let mut len = 1usize;

    while len < 256 {
        let mut start = 0usize;

        while start < 256 {
            m -= 1;
            let zeta_mont = - Q8380417::ZETAS_MONT[m];

            for j in start..(start + len) {
                let t = a[j];
                let u = a[j + len];

                a[j] = add_mod::<Q8380417>(t, u);
                let tmp = sub_mod::<Q8380417>(t, u);
                a[j + len] = mul_montgomery::<Q8380417>(zeta_mont, tmp);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    for coeff in a.iter_mut() {
        *coeff = mul_montgomery::<Q8380417>(*coeff, Q8380417::INV_NTT_SCALE_MONT);
        *coeff = Q8380417::from_montgomery(*coeff);
        *coeff = Q8380417::freeze(*coeff);
    }
}


impl NttOps for Q8380417 {
    fn ntt_in_place(a: &mut [i32; N]) {
        ntt_in_place_q8380417(a)
    }

    fn inv_ntt_in_place(a: &mut [i32; N]) {
        inv_ntt_in_place_q8380417(a)
    }
}


impl NttDomainMul for Q8380417 {
    /// Multiplies two polynomials in the NTT domain.
    ///
    /// This implements the ML-DSA/FIPS 204 NTT-domain coordinate-wise multiplication.
    ///
    /// The inputs `lhs` and `rhs` are interpreted as NTT-domain polynomials.
    /// The result is written to `out`.
    fn mul_ntt(
        lhs: &[i32; N],
        rhs: &[i32; N],
        out: &mut [i32; N],
    ) {
        for i in 0..256 {
            out[i] = mul_montgomery::<Self>(lhs[i], rhs[i]);
        }

    }
}


#[cfg(test)]
mod tests {
    use crate::params::{N, Q8380417, RingParams};
    use crate::poly::Poly;

    fn canonical(mut p: Poly<Q8380417>) -> Poly<Q8380417> {
        p.freeze();
        p
    }

    fn make_pattern_poly(seed: i32) -> Poly<Q8380417> {
        let mut coeffs = [0i32; N];

        for (i, coeff) in coeffs.iter_mut().enumerate() {
            let i = i as i32;

            // Nontrivial but still bounded enough that schoolbook reference
            // multiplication remains safely inside i64.
            *coeff = ((seed + 31 * i + 17 * i * i) % 20_003) - 10_001;
        }

        Poly::from_coeffs(coeffs)
    }

    fn make_high_canonical_poly() -> Poly<Q8380417> {
        let q = Q8380417::Q;
        let mut coeffs = [0i32; N];

        coeffs[0] = q - 1;           // -1 mod q
        coeffs[1] = q - 2;           // -2 mod q
        coeffs[2] = 3;
        coeffs[17] = q - 17;         // -17 mod q
        coeffs[63] = 1_234_567;
        coeffs[64] = q - 1_234_567;
        coeffs[127] = 4_000_000;
        coeffs[128] = q - 4_000_000;
        coeffs[191] = 7_654_321;
        coeffs[255] = 7;

        Poly::from_coeffs(coeffs)
    }

    fn make_sparse_poly(terms: &[(usize, i32)]) -> Poly<Q8380417> {
        let mut coeffs = [0i32; N];

        for &(i, c) in terms {
            coeffs[i] = c;
        }

        Poly::from_coeffs(coeffs)
    }

    #[test]
    fn ntt_zero_stays_zero_q8380417() {
        let mut p = Poly::<Q8380417>::zero();

        p.ntt();

        assert!(p.coeffs().iter().all(|&c| c == 0));
    }

    #[test]
    fn montgomery_conversion_roundtrip_q8380417() {
        let test_values = [
            0,
            1,
            2,
            3,
            17,
            42,
            256,
            1_753,
            4_193_792,
            Q8380417::Q - 2,
            Q8380417::Q - 1,
        ];

        for &a in &test_values {
            let mont = Q8380417::to_montgomery(a);
            let back = Q8380417::from_montgomery(mont);

            assert_eq!(Q8380417::freeze(back), a, "a = {a}");
        }
    }

    #[test]
    fn montgomery_product_roundtrip_q8380417() {
        let test_values = [
            0,
            1,
            2,
            3,
            17,
            42,
            256,
            1_753,
            123_456,
            4_193_792,
            Q8380417::Q - 2,
            Q8380417::Q - 1,
        ];

        for &a in &test_values {
            for &b in &test_values {
                let a_mont = Q8380417::to_montgomery(a);
                let b_mont = Q8380417::to_montgomery(b);

                let prod_mont = Q8380417::montgomery_reduce(
                    (a_mont as i64) * (b_mont as i64),
                );

                let got = Q8380417::freeze(Q8380417::from_montgomery(prod_mont));
                let expected = ((a as i64) * (b as i64))
                    .rem_euclid(Q8380417::Q as i64) as i32;

                assert_eq!(got, expected, "a = {a}, b = {b}");
            }
        }
    }

    #[test]
    fn ntt_roundtrip_sparse_edges_q8380417() {
        let mut p = make_sparse_poly(&[
            (0, 1),
            (1, -2),
            (2, 3),
            (127, -17),
            (128, 42),
            (254, -99),
            (255, 123),
        ]);

        let expected = canonical(p);

        p.ntt();
        p.inv_ntt();

        assert_eq!(canonical(p), expected);
    }

    #[test]
    fn ntt_roundtrip_dense_pattern_q8380417() {
        let mut p = make_pattern_poly(91);
        let expected = canonical(p);

        p.ntt();
        p.inv_ntt();

        assert_eq!(canonical(p), expected);
    }

    #[test]
    fn ntt_roundtrip_high_canonical_q8380417() {
        let mut p = make_high_canonical_poly();
        let expected = canonical(p);

        p.ntt();
        p.inv_ntt();

        assert_eq!(canonical(p), expected);
    }

    #[test]
    fn inv_ntt_after_ntt_recovers_input_q8380417() {
        let mut coeffs = [0i32; N];

        for (i, coeff) in coeffs.iter_mut().enumerate() {
            let i = i as i32;
            *coeff = ((31 * i + 23) % Q8380417::Q) - 10_000;
        }

        let mut p = Poly::<Q8380417>::from_coeffs(coeffs);
        let expected = canonical(p);

        p.ntt();
        p.inv_ntt();

        assert_eq!(canonical(p), expected);
    }

    #[test]
    fn ntt_multiplication_matches_schoolbook_q8380417() {
        let mut a_coeffs = [0i32; N];
        let mut b_coeffs = [0i32; N];

        for i in 0..N {
            a_coeffs[i] = (i as i32 % 17) - 8;
            b_coeffs[i] = (i as i32 % 19) - 9;
        }

        let a = Poly::<Q8380417>::from_coeffs(a_coeffs);
        let b = Poly::<Q8380417>::from_coeffs(b_coeffs);

        let expected = canonical(a.schoolbook_mul_negacyclic(&b));

        let mut a_ntt = a;
        let mut b_ntt = b;

        a_ntt.ntt();
        b_ntt.ntt();

        let mut got = a_ntt.mul_ntt(&b_ntt);
        got.inv_ntt();

        assert_eq!(canonical(got), expected);
    }

    #[test]
    fn ntt_mul_by_zero_matches_schoolbook_q8380417() {
        let a = make_pattern_poly(123);
        let zero = Poly::<Q8380417>::zero();

        let expected = canonical(a.schoolbook_mul_negacyclic(&zero));

        let mut a_ntt = a;
        let mut zero_ntt = zero;

        a_ntt.ntt();
        zero_ntt.ntt();

        let mut got = a_ntt.mul_ntt(&zero_ntt);
        got.inv_ntt();

        assert_eq!(canonical(got), expected);
    }

    #[test]
    fn ntt_mul_by_one_matches_schoolbook_q8380417() {
        let a = make_pattern_poly(123);
        let one = make_sparse_poly(&[(0, 1)]);

        let expected = canonical(a.schoolbook_mul_negacyclic(&one));

        let mut a_ntt = a;
        let mut one_ntt = one;

        a_ntt.ntt();
        one_ntt.ntt();

        let mut got = a_ntt.mul_ntt(&one_ntt);
        got.inv_ntt();

        assert_eq!(canonical(got), expected);
    }

    #[test]
    fn ntt_mul_sparse_wraparound_matches_schoolbook_q8380417() {
        let a = make_sparse_poly(&[
            (0, 12),
            (1, -7),
            (127, 5),
            (200, -9),
            (255, 4),
        ]);

        let b = make_sparse_poly(&[
            (0, -3),
            (2, 8),
            (56, -6),
            (128, 7),
            (255, -5),
        ]);

        let expected = canonical(a.schoolbook_mul_negacyclic(&b));

        let mut a_ntt = a;
        let mut b_ntt = b;

        a_ntt.ntt();
        b_ntt.ntt();

        let mut got = a_ntt.mul_ntt(&b_ntt);
        got.inv_ntt();

        assert_eq!(canonical(got), expected);
    }

    #[test]
    fn ntt_mul_dense_small_matches_schoolbook_q8380417() {
        let a = make_pattern_poly(5);
        let b = make_pattern_poly(211);

        let expected = canonical(a.schoolbook_mul_negacyclic(&b));

        let mut a_ntt = a;
        let mut b_ntt = b;

        a_ntt.ntt();
        b_ntt.ntt();

        let mut got = a_ntt.mul_ntt(&b_ntt);
        got.inv_ntt();

        assert_eq!(canonical(got), expected);
    }

    #[test]
    fn ntt_mul_high_canonical_matches_schoolbook_q8380417() {
        let a = make_high_canonical_poly();

        let b = make_sparse_poly(&[
            (0, Q8380417::Q - 2),
            (1, 3),
            (64, Q8380417::Q - 5),
            (129, 11),
            (255, Q8380417::Q - 7),
        ]);

        let expected = canonical(a.schoolbook_mul_negacyclic(&b));

        let mut a_ntt = a;
        let mut b_ntt = b;

        a_ntt.ntt();
        b_ntt.ntt();

        let mut got = a_ntt.mul_ntt(&b_ntt);
        got.inv_ntt();

        assert_eq!(canonical(got), expected);
    }
}