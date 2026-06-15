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
pub(crate) fn sample_poly_from_prf<const ETA: usize>(sigma: &[u8; 32], nonce: u8) -> Poly<Q3329> {
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
        let nonce = nonce_start
            .checked_add(i as u8)
            .expect("ML-KEM nonce overflow");
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
    e_hat: &PolyVec<Q3329, K>,
) -> PolyVec<Q3329, K> {
    a_hat.mul_vec_ntt(s_hat).add(e_hat)
}
