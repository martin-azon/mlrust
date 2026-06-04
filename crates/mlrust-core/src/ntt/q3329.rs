//! NTT implementation for the ML-KEM modulus q = 3329.


use super::q3329_tables::{FIPS_ZETAS_MONT, FIPS_BASEMUL_ZETAS_MONT, INV_NTT_SCALE_MONT};
use crate::params::{N, RingParams, NttParams, NttOps, NttDomainMul, Q3329};
use crate::field::{mul_montgomery, add_mod, sub_mod};


impl NttParams for Q3329 {
    const ZETAS_MONT: &'static [i32] = &FIPS_ZETAS_MONT;
    const INV_NTT_SCALE_MONT: i32 = INV_NTT_SCALE_MONT;
}


/// Applies the forward NTT in place.
pub fn ntt_in_place_q3329(a: &mut [i32; N]) {
    for coeff in a.iter_mut() {
        *coeff = Q3329::to_montgomery(*coeff);
    }


    let mut i = 1usize;
    let mut len = 128usize;

    while len >= 2 {
        let mut start = 0;

        while start < N {
            let zeta_mont = Q3329::ZETAS_MONT[i];
            i += 1;

            for j in start..(start + len) {
                let t = mul_montgomery::<Q3329>(zeta_mont, a[j + len]);
                let u = a[j];

                a[j + len] = sub_mod::<Q3329>(u, t);
                a[j] = add_mod::<Q3329>(u, t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}


/// Applies the inverse NTT in place.
pub fn inv_ntt_in_place_q3329(a: &mut [i32; N]) {
    let mut i = 127usize;
    let mut len = 2usize;

    while len <= 128 {
        let mut start = 0usize;

        while start < N {
            let zeta_mont = Q3329::ZETAS_MONT[i];
            i -= 1;

            for j in start..(start + len) {
                let t = a[j];
                let u = a[j + len];

                a[j] = add_mod::<Q3329>(t, u);
                let tmp = sub_mod::<Q3329>(u, t);
                a[j + len] = mul_montgomery::<Q3329>(zeta_mont, tmp);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    for coeff in a.iter_mut() {
        *coeff = mul_montgomery::<Q3329>(*coeff, Q3329::INV_NTT_SCALE_MONT);
        *coeff = Q3329::from_montgomery(*coeff);
        *coeff = Q3329::freeze(*coeff);
    }
}


impl NttOps for Q3329 {
    fn ntt_in_place(a: &mut [i32; N]) {
        ntt_in_place_q3329(a)
    }

    fn inv_ntt_in_place(a: &mut [i32; N]) {
        inv_ntt_in_place_q3329(a)
    }
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
    zeta_mont: i32,
) -> (i32, i32) {
    let a0b0 = mul_montgomery::<P>(a0, b0);
    let a1b1 = mul_montgomery::<P>(a1, b1);
    let za1b1 = mul_montgomery::<P>(zeta_mont, a1b1);
    let deg0 = add_mod::<P>(a0b0, za1b1);

    let a0b1 = mul_montgomery::<P>(a0, b1);
    let a1b0 = mul_montgomery::<P>(a1, b0);
    let deg1 = add_mod::<P>(a0b1, a1b0);

    (deg0, deg1)
}


impl NttDomainMul for Q3329 {
    /// Multiplies two polynomials in the NTT domain.
    ///
    /// This implements the ML-KEM/FIPS 203 NTT-domain multiplication using
    /// degree-1 base-case multiplication blocks.
    ///
    /// The inputs `lhs` and `rhs` are interpreted as NTT-domain polynomials.
    /// The result is written to `out`.
    fn mul_ntt(
        lhs: &[i32; N],
        rhs: &[i32; N],
        out: &mut [i32; N],
    ) {
        for i in 0..N/2 {
            let zeta_mont = FIPS_BASEMUL_ZETAS_MONT[i];

            let base_prod = base_mul::<Self>(
                lhs[2*i],
                lhs[2*i+1],
                rhs[2*i],
                rhs[2*i+1],
                zeta_mont
            );
            out[2*i] = base_prod.0;
            out[2*i+1] = base_prod.1;
        }

    }
}



#[cfg(test)]
mod tests {
    use crate::params::{N, Q3329, RingParams};
    use crate::poly::Poly;

    fn freeze_poly(mut p: Poly<Q3329>) -> Poly<Q3329> {
        p.freeze();
        p
    }

    fn assert_poly_eq_canonical(
        got: Poly<Q3329>,
        expected: Poly<Q3329>,
    ) {
        let got = freeze_poly(got);
        let expected = freeze_poly(expected);

        assert_eq!(got, expected);
    }

    fn make_pattern_poly(seed: i32) -> Poly<Q3329> {
        let mut coeffs = [0i32; N];

        for (i, coeff) in coeffs.iter_mut().enumerate() {
            let i = i as i32;

            // Deliberately nontrivial but bounded pattern:
            // includes negative, positive, and repeated residues.
            *coeff = ((seed + 17 * i + 13 * i * i) % 997) - 498;
        }

        Poly::from_coeffs(coeffs)
    }

    fn make_high_canonical_poly() -> Poly<Q3329> {
        let q = Q3329::Q;
        let mut coeffs = [0i32; N];

        coeffs[0] = q - 1;       // -1 mod q
        coeffs[1] = q - 2;       // -2 mod q
        coeffs[2] = 3;
        coeffs[17] = q - 17;     // -17 mod q
        coeffs[63] = 1234;
        coeffs[127] = q - 1234;
        coeffs[128] = 2048;
        coeffs[191] = q - 2048;
        coeffs[255] = 7;

        Poly::from_coeffs(coeffs)
    }

    fn make_sparse_poly(terms: &[(usize, i32)]) -> Poly<Q3329> {
        let mut coeffs = [0i32; N];

        for &(i, c) in terms {
            coeffs[i] = c;
        }

        Poly::from_coeffs(coeffs)
    }

    #[test]
    fn montgomery_conversion_roundtrip_q3329() {
        for a in 0..Q3329::Q {
            let mont = Q3329::to_montgomery(a);
            let back = Q3329::from_montgomery(mont);

            assert_eq!(Q3329::freeze(back), a, "a = {a}");
        }
    }

    #[test]
    fn montgomery_product_roundtrip_q3329() {
        let test_values = [
            0,
            1,
            2,
            3,
            17,
            42,
            123,
            777,
            1729,
            Q3329::Q - 2,
            Q3329::Q - 1,
        ];

        for &a in &test_values {
            for &b in &test_values {
                let a_mont = Q3329::to_montgomery(a);
                let b_mont = Q3329::to_montgomery(b);

                let prod_mont = Q3329::montgomery_reduce(
                    (a_mont as i64) * (b_mont as i64),
                );

                let got = Q3329::freeze(Q3329::from_montgomery(prod_mont));
                let expected = ((a as i64) * (b as i64))
                    .rem_euclid(Q3329::Q as i64) as i32;

                assert_eq!(got, expected, "a = {a}, b = {b}");
            }
        }
    }

    #[test]
    fn ntt_roundtrip_zero_q3329() {
        let mut p = Poly::<Q3329>::zero();
        let expected = p;

        p.ntt();
        p.inv_ntt();

        assert_poly_eq_canonical(p, expected);
    }

    #[test]
    fn ntt_roundtrip_constant_q3329() {
        let mut coeffs = [0i32; N];
        coeffs[0] = 1234;

        let mut p = Poly::<Q3329>::from_coeffs(coeffs);
        let expected = p;

        p.ntt();
        p.inv_ntt();

        assert_poly_eq_canonical(p, expected);
    }

    #[test]
    fn ntt_roundtrip_sparse_edges_q3329() {
        let mut p = make_sparse_poly(&[
            (0, 1),
            (1, -2),
            (2, 3),
            (127, -17),
            (128, 42),
            (254, -99),
            (255, 123),
        ]);

        let expected = p;

        p.ntt();
        p.inv_ntt();

        assert_poly_eq_canonical(p, expected);
    }

    #[test]
    fn ntt_roundtrip_dense_pattern_q3329() {
        let mut p = make_pattern_poly(91);
        let expected = p;

        p.ntt();
        p.inv_ntt();

        assert_poly_eq_canonical(p, expected);
    }

    #[test]
    fn ntt_roundtrip_high_canonical_q3329() {
        let mut p = make_high_canonical_poly();
        let expected = p;

        p.ntt();
        p.inv_ntt();

        assert_poly_eq_canonical(p, expected);
    }

    #[test]
    fn ntt_is_additive_q3329() {
        let a = make_pattern_poly(11);
        let b = make_pattern_poly(37);

        let mut lhs = a.add(&b);
        lhs.ntt();

        let mut a_ntt = a;
        let mut b_ntt = b;

        a_ntt.ntt();
        b_ntt.ntt();

        let rhs = a_ntt.add(&b_ntt);

        assert_poly_eq_canonical(lhs, rhs);
    }

    #[test]
    fn ntt_mul_by_zero_matches_schoolbook_q3329() {
        let a = make_pattern_poly(123);
        let zero = Poly::<Q3329>::zero();

        let expected = a.schoolbook_mul_negacyclic(&zero);

        let mut a_ntt = a;
        let mut zero_ntt = zero;

        a_ntt.ntt();
        zero_ntt.ntt();

        let mut got = a_ntt.mul_ntt(&zero_ntt);
        got.inv_ntt();

        assert_poly_eq_canonical(got, expected);
    }

    #[test]
    fn ntt_mul_by_one_matches_schoolbook_q3329() {
        let a = make_pattern_poly(123);

        let one = make_sparse_poly(&[(0, 1)]);

        let expected = a.schoolbook_mul_negacyclic(&one);

        let mut a_ntt = a;
        let mut one_ntt = one;

        a_ntt.ntt();
        one_ntt.ntt();

        let mut got = a_ntt.mul_ntt(&one_ntt);
        got.inv_ntt();

        assert_poly_eq_canonical(got, expected);
    }

    #[test]
    fn ntt_mul_sparse_wraparound_matches_schoolbook_q3329() {
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

        let expected = a.schoolbook_mul_negacyclic(&b);

        let mut a_ntt = a;
        let mut b_ntt = b;

        a_ntt.ntt();
        b_ntt.ntt();

        let mut got = a_ntt.mul_ntt(&b_ntt);
        got.inv_ntt();

        assert_poly_eq_canonical(got, expected);
    }

    #[test]
    fn ntt_mul_dense_small_matches_schoolbook_q3329() {
        let a = make_pattern_poly(5);
        let b = make_pattern_poly(211);

        let expected = a.schoolbook_mul_negacyclic(&b);

        let mut a_ntt = a;
        let mut b_ntt = b;

        a_ntt.ntt();
        b_ntt.ntt();

        let mut got = a_ntt.mul_ntt(&b_ntt);
        got.inv_ntt();

        assert_poly_eq_canonical(got, expected);
    }

    #[test]
    fn ntt_mul_high_canonical_matches_schoolbook_q3329() {
        let a = make_high_canonical_poly();

        let b = make_sparse_poly(&[
            (0, Q3329::Q - 2),
            (1, 3),
            (64, Q3329::Q - 5),
            (129, 11),
            (255, Q3329::Q - 7),
        ]);

        let expected = a.schoolbook_mul_negacyclic(&b);

        let mut a_ntt = a;
        let mut b_ntt = b;

        a_ntt.ntt();
        b_ntt.ntt();

        let mut got = a_ntt.mul_ntt(&b_ntt);
        got.inv_ntt();

        assert_poly_eq_canonical(got, expected);
    }
}