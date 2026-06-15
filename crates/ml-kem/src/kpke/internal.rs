//! Internal ML-KEM building blocks.
//!
//! This module contains helper routines used by the K-PKE and ML-KEM
//! algorithms. These functions are not part of the public API.
//!
//! The helpers in this module construct algebraic objects from seeds:
//!
//! - expansion of the public matrix `A_hat` from the public seed `rho`;
//! - sampling of secret and error polynomial vectors from the secret seed
//!   `sigma`;
//! - small wrappers around the ML-KEM PRF and CBD samplers.



use mlrust_core::params::Q3329;
use mlrust_core::poly::{Poly, PolyMat, PolyVec};
use mlrust_core::sampling::ml_kem::{sample_ntt, sample_poly_cbd};
use mlrust_core::symmetric::ml_kem::prf;



/// Expands the public ML-KEM matrix `A_hat`, which is in the NTT/Montgomery domain.
///
/// For each entry `(i, j)`, this computes:
///
/// ```text
/// A_hat[i, j] = SampleNTT(rho || j || i)
/// ```
#[must_use]
pub(crate) fn expand_a_hat<const K: usize>(rho: &[u8; 32]) -> PolyMat<Q3329, K, K> {
    let mut rows = [PolyVec::<Q3329, K>::zero(); K];

    for i in 0..K {
        let mut row = [Poly::<Q3329>::zero(); K];

        for j in 0..K {
            row[j] = sample_ntt(rho, i as u8, j as u8);
        }

        rows[i] = PolyVec::from_polys(row);
    }

    PolyMat::from_rows(rows)
}


/// Expands the transpose of the public ML-KEM matrix `A_hat`, which is in the NTT/Montgomery domain.
///
/// Entry `(i, j)` of the returned matrix is
///
/// ```text
/// A_hat[j, i]
/// ```
#[must_use]
pub(crate) fn expand_a_hat_transposed<const K: usize>(rho: &[u8; 32]) -> PolyMat<Q3329, K, K> {
    let mut rows = [PolyVec::<Q3329, K>::zero(); K];

    for i in 0..K {
        let mut row = [Poly::<Q3329>::zero(); K];

        for j in 0..K {
            row[j] = sample_ntt(rho, j as u8, i as u8);
        }

        rows[i] = PolyVec::from_polys(row);
    }

    PolyMat::from_rows(rows)
}


/// Samples one CBD polynomial using `PRF_eta(sigma, nonce)`.
///
/// Supported values are:
///
/// ```text
/// ETA = 2
/// ETA = 3
/// ```
///
/// The returned polynomial is in the ordinary coefficient domain. Its
/// coefficients are small signed representatives in `[-ETA, ETA]`.
#[must_use]
pub(crate) fn sample_poly_from_prf<const ETA: usize>(
    sigma: &[u8; 32],
    nonce: u8,
) -> Poly<Q3329> {
    match ETA {
        2 => {
            let mut buf = [0u8; 128];
            prf::<2>(sigma, nonce, &mut buf);
            sample_poly_cbd::<2>(&buf)
        }
        3 => {
            let mut buf = [0u8; 192];
            prf::<3>(sigma, nonce, &mut buf);
            sample_poly_cbd::<3>(&buf)
        }
        _ => panic!("unsupported eta"),
    }
}


/// Samples a vector of `K` CBD polynomials using consecutive PRF nonces.
///
/// The first polynomial uses `nonce_start`, the second uses
/// `nonce_start + 1`, and so on.
///
/// The returned vector is in the ordinary coefficient domain.
#[must_use]
pub(crate) fn sample_polyvec_from_prf<const K: usize, const ETA: usize>(
    sigma: &[u8; 32],
    nonce_start: u8,
) -> PolyVec<Q3329, K> {
    let mut polys = [Poly::<Q3329>::zero(); K];

    for i in 0..K {
        let nonce = nonce_start.checked_add(i as u8).expect("ML-KEM nonce overflow");
        polys[i] = sample_poly_from_prf::<ETA>(sigma, nonce);
    }

    PolyVec::from_polys(polys)
}


/// Samples the K-PKE secret vector `s`.
#[must_use]
pub(crate) fn sample_secret_vector<const K: usize, const ETA1: usize>(
    sigma: &[u8; 32],
    nonce_start: u8,
) -> PolyVec<Q3329, K> {
    sample_polyvec_from_prf::<K, ETA1>(sigma, nonce_start)
}


/// Samples the K-PKE error vector `e`.
#[must_use]
pub(crate) fn sample_error_vector<const K: usize, const ETA: usize>(
    sigma: &[u8; 32],
    nonce_start: u8,
) -> PolyVec<Q3329, K> {
    sample_polyvec_from_prf::<K, ETA>(sigma, nonce_start)
}


/// Computes the public vector `t_hat`.
///
/// This computes:
///
/// ```text
/// t_hat = A_hat * s_hat + e_hat
/// ```
///
/// # Representation
///
/// All inputs must already be in the NTT/Montgomery domain. The returned
/// vector is also in the NTT/Montgomery domain.
#[must_use]
pub(crate) fn compute_t_hat<const K: usize>(
    a_hat: &PolyMat<Q3329, K, K>,
    s_hat: &PolyVec<Q3329, K>,
    e_hat: &PolyVec<Q3329, K>
) -> PolyVec<Q3329, K> {
    a_hat.mul_vec_ntt(s_hat).add(e_hat)
}




#[cfg(test)]
mod tests {
    use super::*;

    use mlrust_core::poly::PolyVec;

    fn make_seed(byte: u8) -> [u8; 32] {
        let mut seed = [0u8; 32];

        for (i, b) in seed.iter_mut().enumerate() {
            *b = byte.wrapping_add((3 * i) as u8);
        }

        seed
    }

    #[test]
    fn expand_a_hat_entries_match_sample_ntt() {
        const K: usize = 3;

        let rho = make_seed(17);
        let a_hat = expand_a_hat::<K>(&rho);

        for i in 0..K {
            for j in 0..K {
                let expected = sample_ntt(&rho, i as u8, j as u8);

                assert_eq!(
                    a_hat.get(i, j),
                    Some(&expected),
                    "mismatch at A_hat[{i}, {j}]"
                );
            }
        }
    }

    #[test]
    fn expand_a_hat_transposed_entries_match_transpose() {
        const K: usize = 3;

        let rho = make_seed(91);

        let a_hat = expand_a_hat::<K>(&rho);
        let a_hat_t = expand_a_hat_transposed::<K>(&rho);

        for i in 0..K {
            for j in 0..K {
                assert_eq!(
                    a_hat_t.get(i, j),
                    a_hat.get(j, i),
                    "mismatch at A_hat^T[{i}, {j}]"
                );
            }
        }
    }

    #[test]
    fn expand_a_hat_transposed_entries_match_sample_ntt_with_reversed_indices() {
        const K: usize = 4;

        let rho = make_seed(42);
        let a_hat_t = expand_a_hat_transposed::<K>(&rho);

        for i in 0..K {
            for j in 0..K {
                let expected = sample_ntt(&rho, j as u8, i as u8);

                assert_eq!(
                    a_hat_t.get(i, j),
                    Some(&expected),
                    "mismatch at A_hat^T[{i}, {j}]"
                );
            }
        }
    }

    #[test]
    fn sample_poly_from_prf_eta2_matches_prf_then_cbd() {
        let sigma = make_seed(5);
        let nonce = 7u8;

        let got = sample_poly_from_prf::<2>(&sigma, nonce);

        let mut buf = [0u8; 128];
        prf::<2>(&sigma, nonce, &mut buf);
        let expected = sample_poly_cbd::<2>(&buf);

        assert_eq!(got, expected);
    }

    #[test]
    fn sample_poly_from_prf_eta3_matches_prf_then_cbd() {
        let sigma = make_seed(13);
        let nonce = 255u8;

        let got = sample_poly_from_prf::<3>(&sigma, nonce);

        let mut buf = [0u8; 192];
        prf::<3>(&sigma, nonce, &mut buf);
        let expected = sample_poly_cbd::<3>(&buf);

        assert_eq!(got, expected);
    }

    #[test]
    #[should_panic]
    fn sample_poly_from_prf_rejects_unsupported_eta() {
        let sigma = [0u8; 32];

        let _ = sample_poly_from_prf::<4>(&sigma, 0);
    }

    #[test]
    fn sample_polyvec_from_prf_uses_consecutive_nonces_eta2() {
        const K: usize = 4;
        const ETA: usize = 2;

        let sigma = make_seed(21);
        let nonce_start = 9u8;

        let got = sample_polyvec_from_prf::<K, ETA>(&sigma, nonce_start);

        for i in 0..K {
            let expected = sample_poly_from_prf::<ETA>(
                &sigma,
                nonce_start + i as u8,
            );

            assert_eq!(
                got.get(i),
                Some(&expected),
                "mismatch at vector entry {i}"
            );
        }
    }

    #[test]
    fn sample_polyvec_from_prf_uses_consecutive_nonces_eta3() {
        const K: usize = 2;
        const ETA: usize = 3;

        let sigma = make_seed(37);
        let nonce_start = 3u8;

        let got = sample_polyvec_from_prf::<K, ETA>(&sigma, nonce_start);

        for i in 0..K {
            let expected = sample_poly_from_prf::<ETA>(
                &sigma,
                nonce_start + i as u8,
            );

            assert_eq!(
                got.get(i),
                Some(&expected),
                "mismatch at vector entry {i}"
            );
        }
    }

    #[test]
    fn sample_secret_vector_is_sample_polyvec_from_prf() {
        const K: usize = 3;
        const ETA1: usize = 2;

        let sigma = make_seed(123);
        let nonce_start = 0u8;

        let got = sample_secret_vector::<K, ETA1>(&sigma, nonce_start);
        let expected = sample_polyvec_from_prf::<K, ETA1>(&sigma, nonce_start);

        assert_eq!(got, expected);
    }

    #[test]
    fn sample_error_vector_is_sample_polyvec_from_prf() {
        const K: usize = 3;
        const ETA: usize = 2;

        let sigma = make_seed(201);
        let nonce_start = K as u8;

        let got = sample_error_vector::<K, ETA>(&sigma, nonce_start);
        let expected = sample_polyvec_from_prf::<K, ETA>(&sigma, nonce_start);

        assert_eq!(got, expected);
    }

    #[test]
    fn sample_polyvec_entries_are_not_all_forced_equal() {
        const K: usize = 4;
        const ETA: usize = 2;

        let sigma = make_seed(44);
        let v = sample_polyvec_from_prf::<K, ETA>(&sigma, 0);

        let first = v.get(0).expect("entry exists");

        assert!(
            (1..K).any(|i| v.get(i).expect("entry exists") != first),
            "all entries are equal; nonce incrementation may be broken"
        );
    }

    #[test]
    fn compute_t_hat_matches_manual_row_by_row_computation() {
        const K: usize = 3;

        let rho = make_seed(77);
        let sigma = make_seed(155);

        let a_hat = expand_a_hat::<K>(&rho);

        let s = sample_secret_vector::<K, 2>(&sigma, 0);
        let e = sample_error_vector::<K, 2>(&sigma, K as u8);

        let mut s_hat = s;
        s_hat.ntt();

        let mut e_hat = e;
        e_hat.ntt();

        let got = compute_t_hat(&a_hat, &s_hat, &e_hat);

        let mut expected_polys = [Poly::<Q3329>::zero(); K];

        for i in 0..K {
            let mut acc = Poly::<Q3329>::zero();

            for j in 0..K {
                let a_ij = a_hat.get(i, j).expect("matrix entry exists");
                let s_j = s_hat.get(j).expect("vector entry exists");

                let prod = a_ij.mul_ntt(s_j);
                acc.add_assign(&prod);
            }

            let e_i = e_hat.get(i).expect("error entry exists");
            acc.add_assign(e_i);

            expected_polys[i] = acc;
        }

        let expected = PolyVec::from_polys(expected_polys);

        assert_eq!(got, expected);
    }

    #[test]
    fn compute_t_hat_with_zero_error_is_matrix_vector_product() {
        const K: usize = 2;

        let rho = make_seed(18);
        let sigma = make_seed(29);

        let a_hat = expand_a_hat::<K>(&rho);
        let s = sample_secret_vector::<K, 3>(&sigma, 0);

        let mut s_hat = s;
        s_hat.ntt();

        let e_hat = PolyVec::<Q3329, K>::zero();

        let got = compute_t_hat(&a_hat, &s_hat, &e_hat);
        let expected = a_hat.mul_vec_ntt(&s_hat);

        assert_eq!(got, expected);
    }

    #[test]
    fn polyvec_ntt_keeps_length_and_changes_nonzero_polys() {
        const K: usize = 2;

        let sigma = make_seed(88);
        let s = sample_secret_vector::<K, 2>(&sigma, 0);

        let mut s_hat = s;
        s_hat.ntt();

        assert_eq!(s_hat.polys().len(), K);

        assert_ne!(s_hat, s);
    }

    #[test]
    fn sampled_vectors_have_coefficients_in_expected_eta2_range() {
        const K: usize = 3;

        let sigma = make_seed(66);
        let v = sample_polyvec_from_prf::<K, 2>(&sigma, 0);

        for poly in v.polys() {
            for &coeff in poly.coeffs() {
                assert!(
                    (-2..=2).contains(&coeff),
                    "eta=2 coefficient out of range: {coeff}"
                );
            }
        }
    }

    #[test]
    fn sampled_vectors_have_coefficients_in_expected_eta3_range() {
        const K: usize = 2;

        let sigma = make_seed(99);
        let v = sample_polyvec_from_prf::<K, 3>(&sigma, 0);

        for poly in v.polys() {
            for &coeff in poly.coeffs() {
                assert!(
                    (-3..=3).contains(&coeff),
                    "eta=3 coefficient out of range: {coeff}"
                );
            }
        }
    }
}