//! Polynomial-matrix storage and accessors.
//!
//! This module defines [`PolyMat`], a fixed-size matrix whose entries are
//! polynomials.
//!
//! A polynomial matrix is stored row-wise as an array of [`PolyVec`] rows.
//! The number of rows and columns are encoded at the type level using const
//! generics.

use super::{Poly, PolyVec};
use crate::params::NttDomainMul;
use crate::params::RingParams;

/// Fixed-size matrix of polynomials.
///
/// The matrix has `ROWS` rows and `COLS` columns. Each row is stored as a
/// [`PolyVec<P, COLS>`].
///
/// The parameter type `P` determines the coefficient modulus and reduction
/// routines for the polynomial entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyMat<P: RingParams, const ROWS: usize, const COLS: usize> {
    rows: [PolyVec<P, COLS>; ROWS],
}

impl<P: RingParams, const ROWS: usize, const COLS: usize> PolyMat<P, ROWS, COLS> {
    /// Returns the zero polynomial matrix.
    ///
    /// Every row is initialized to [`PolyVec::zero`], so every entry is the
    /// zero polynomial.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            rows: [PolyVec::<P, COLS>::zero(); ROWS],
        }
    }

    /// Creates a polynomial matrix from an array of rows.
    ///
    /// This function does not reduce or canonicalize any coefficient. The
    /// caller is responsible for ensuring that the input rows are in the
    /// expected representation, or for calling reduction/canonicalization
    /// routines afterwards.
    #[must_use]
    pub const fn from_rows(rows: [PolyVec<P, COLS>; ROWS]) -> Self {
        Self { rows }
    }

    /// Returns an immutable reference to the row array.
    ///
    /// Each row is represented as a [`PolyVec<P, COLS>`].
    #[must_use]
    pub fn rows(&self) -> &[PolyVec<P, COLS>; ROWS] {
        &self.rows
    }

    /// Returns a mutable reference to the row array.
    ///
    /// The caller is responsible for preserving any representation invariants
    /// required by later operations.
    #[must_use]
    pub fn rows_mut(&mut self) -> &mut [PolyVec<P, COLS>; ROWS] {
        &mut self.rows
    }

    /// Consumes the matrix and returns its underlying row array.
    #[must_use]
    pub fn into_rows(self) -> [PolyVec<P, COLS>; ROWS] {
        self.rows
    }

    /// Returns an immutable reference to a row.
    ///
    /// Returns `None` if `row` is out of bounds.
    #[must_use]
    pub fn row(&self, row: usize) -> Option<&PolyVec<P, COLS>> {
        self.rows.get(row)
    }

    /// Returns a mutable reference to a row.
    ///
    /// Returns `None` if `row` is out of bounds.
    #[must_use]
    pub fn row_mut(&mut self, row: usize) -> Option<&mut PolyVec<P, COLS>> {
        self.rows.get_mut(row)
    }

    /// Returns an immutable reference to a single polynomial entry.
    ///
    /// The entry is addressed by `(row, col)`.
    ///
    /// Returns `None` if either index is out of bounds.
    #[must_use]
    pub fn get(&self, row: usize, col: usize) -> Option<&Poly<P>> {
        self.rows.get(row)?.polys().get(col)
    }

    /// Returns a mutable reference to a single polynomial entry.
    ///
    /// The entry is addressed by `(row, col)`.
    ///
    /// Returns `None` if either index is out of bounds.
    #[must_use]
    pub fn get_mut(&mut self, row: usize, col: usize) -> Option<&mut Poly<P>> {
        self.rows.get_mut(row)?.polys_mut().get_mut(col)
    }

    /// Reduces every coefficient of every polynomial entry.
    ///
    /// This applies [`PolyVec::reduce`] to each row. The result is reduced
    /// modulo `q`, but coefficients are not necessarily canonical
    /// representatives in `[0, q)`.
    pub fn reduce(&mut self) {
        for row in &mut self.rows {
            row.reduce();
        }
    }

    /// Canonicalizes every coefficient of every polynomial entry into `[0, q)`.
    pub fn freeze(&mut self) {
        for row in &mut self.rows {
            row.freeze();
        }
    }

    /// Adds another polynomial matrix to this matrix in place.
    ///
    /// For each entry `(i, j)`, this computes:
    ///
    /// ```text
    /// self[i, j] = self[i, j] + rhs[i, j] mod q
    /// ```
    ///
    /// The result is reduced using the row-level addition routine, but
    /// coefficients are not necessarily canonicalized into `[0, q)`.
    pub fn add_assign(&mut self, rhs: &Self) {
        for (row_a, row_b) in self.rows.iter_mut().zip(rhs.rows.iter()) {
            row_a.add_assign(row_b);
        }
    }

    /// Subtracts another polynomial matrix from this matrix in place.
    ///
    /// For each entry `(i, j)`, this computes:
    ///
    /// ```text
    /// self[i, j] = self[i, j] - rhs[i, j] mod q
    /// ```
    ///
    /// The result is reduced using the row-level subtraction routine, but
    /// coefficients are not necessarily canonicalized into `[0, q)`.
    pub fn sub_assign(&mut self, rhs: &Self) {
        for (row_a, row_b) in self.rows.iter_mut().zip(rhs.rows.iter()) {
            row_a.sub_assign(row_b);
        }
    }

    /// Returns the componentwise sum of two polynomial matrices.
    ///
    /// This does not modify either input matrix.
    ///
    /// Internally, this copies `self`, applies [`PolyMat::add_assign`], and
    /// returns the result.
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        let mut out = *self;
        out.add_assign(rhs);
        out
    }

    /// Returns the componentwise difference of two polynomial matrices.
    ///
    /// This does not modify either input matrix.
    ///
    /// Internally, this copies `self`, applies [`PolyMat::sub_assign`], and
    /// returns the result.
    #[must_use]
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut out = *self;
        out.sub_assign(rhs);
        out
    }
}

impl<P: NttDomainMul, const ROWS: usize, const COLS: usize> PolyMat<P, ROWS, COLS> {
    /// Multiplies this polynomial matrix by a polynomial vector in the
    /// NTT/Montgomery domain.
    ///
    /// This computes:
    ///
    /// ```text
    /// out[i] = sum_j self[i, j] * vec[j]
    /// ```
    ///
    /// where all products are NTT-domain products.
    ///
    /// # Representation
    ///
    /// The matrix entries and vector entries must already be in the
    /// NTT/Montgomery domain. The returned vector is also in the
    /// NTT/Montgomery domain.
    #[must_use]
    pub fn mul_vec_ntt(&self, vec: &PolyVec<P, COLS>) -> PolyVec<P, ROWS> {
        let mut polys = [Poly::<P>::zero(); ROWS];

        for i in 0..ROWS {
            polys[i] = self.rows[i].dot_ntt(vec);
        }

        PolyVec::from_polys(polys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{N, Q3329, Q8380417, RingParams};

    fn make_poly_q3329(offset: i32, step: i32) -> Poly<Q3329> {
        let mut coeffs = [0i32; N];

        for (i, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = offset + step * (i as i32);
        }

        Poly::from_coeffs(coeffs)
    }

    fn make_poly_q8380417(offset: i32, step: i32) -> Poly<Q8380417> {
        let mut coeffs = [0i32; N];

        for (i, coeff) in coeffs.iter_mut().enumerate() {
            *coeff = offset + step * (i as i32);
        }

        Poly::from_coeffs(coeffs)
    }

    fn make_row_q3329<const K: usize>(base: i32) -> PolyVec<Q3329, K> {
        let mut polys = [Poly::<Q3329>::zero(); K];

        for (j, poly) in polys.iter_mut().enumerate() {
            *poly = make_poly_q3329(base + 100 * (j as i32), (j as i32) + 1);
        }

        PolyVec::from_polys(polys)
    }

    fn make_row_q8380417<const K: usize>(base: i32) -> PolyVec<Q8380417, K> {
        let mut polys = [Poly::<Q8380417>::zero(); K];

        for (j, poly) in polys.iter_mut().enumerate() {
            *poly = make_poly_q8380417(base + 10_000 * (j as i32), (j as i32) + 17);
        }

        PolyVec::from_polys(polys)
    }

    #[test]
    fn zero_has_all_zero_entries_q3329() {
        let mat = PolyMat::<Q3329, 3, 4>::zero();

        for row in mat.rows() {
            for poly in row.polys() {
                for &coeff in poly.coeffs() {
                    assert_eq!(coeff, 0);
                }
            }
        }
    }

    #[test]
    fn from_rows_into_rows_roundtrip_q3329() {
        let rows = [make_row_q3329::<3>(-100), make_row_q3329::<3>(500)];

        let mat = PolyMat::<Q3329, 2, 3>::from_rows(rows);

        assert_eq!(mat.into_rows(), rows);
    }

    #[test]
    fn rows_accessor_returns_expected_rows_q3329() {
        let rows = [
            make_row_q3329::<3>(-100),
            make_row_q3329::<3>(500),
            make_row_q3329::<3>(900),
        ];

        let mat = PolyMat::<Q3329, 3, 3>::from_rows(rows);

        assert_eq!(mat.rows(), &rows);
    }

    #[test]
    fn rows_mut_can_modify_rows_q3329() {
        let rows = [make_row_q3329::<2>(-100), make_row_q3329::<2>(500)];

        let replacement = make_row_q3329::<2>(1234);

        let mut mat = PolyMat::<Q3329, 2, 2>::from_rows(rows);

        mat.rows_mut()[1] = replacement;

        assert_eq!(mat.rows()[0], rows[0]);
        assert_eq!(mat.rows()[1], replacement);
    }

    #[test]
    fn row_access_returns_expected_rows_q3329() {
        let rows = [
            make_row_q3329::<3>(-100),
            make_row_q3329::<3>(500),
            make_row_q3329::<3>(900),
        ];

        let mat = PolyMat::<Q3329, 3, 3>::from_rows(rows);

        assert_eq!(mat.row(0), Some(&rows[0]));
        assert_eq!(mat.row(1), Some(&rows[1]));
        assert_eq!(mat.row(2), Some(&rows[2]));
        assert!(mat.row(3).is_none());
    }

    #[test]
    fn row_mut_can_modify_a_row_q3329() {
        let rows = [make_row_q3329::<2>(-100), make_row_q3329::<2>(500)];

        let replacement = make_row_q3329::<2>(1234);

        let mut mat = PolyMat::<Q3329, 2, 2>::from_rows(rows);

        *mat.row_mut(1).expect("row exists") = replacement;

        assert_eq!(mat.row(0), Some(&rows[0]));
        assert_eq!(mat.row(1), Some(&replacement));
        assert!(mat.row_mut(2).is_none());
    }

    #[test]
    fn get_returns_expected_entries_q3329() {
        let rows = [make_row_q3329::<3>(10), make_row_q3329::<3>(1000)];

        let mat = PolyMat::<Q3329, 2, 3>::from_rows(rows);

        assert_eq!(mat.get(0, 0), Some(&rows[0].polys()[0]));
        assert_eq!(mat.get(0, 2), Some(&rows[0].polys()[2]));
        assert_eq!(mat.get(1, 1), Some(&rows[1].polys()[1]));

        assert!(mat.get(2, 0).is_none());
        assert!(mat.get(0, 3).is_none());
        assert!(mat.get(2, 3).is_none());
    }

    #[test]
    fn get_mut_can_modify_single_entry_q3329() {
        let rows = [make_row_q3329::<3>(10), make_row_q3329::<3>(1000)];

        let replacement = make_poly_q3329(-777, 5);

        let mut mat = PolyMat::<Q3329, 2, 3>::from_rows(rows);

        *mat.get_mut(1, 2).expect("entry exists") = replacement;

        assert_eq!(mat.get(1, 2), Some(&replacement));
        assert_eq!(mat.get(0, 0), Some(&rows[0].polys()[0]));

        assert!(mat.get_mut(2, 0).is_none());
        assert!(mat.get_mut(0, 3).is_none());
    }

    #[test]
    fn reduce_matches_rowwise_reduce_q3329() {
        let rows = [make_row_q3329::<3>(-5_000), make_row_q3329::<3>(8_000)];

        let mut mat = PolyMat::<Q3329, 2, 3>::from_rows(rows);
        let mut expected_rows = rows;

        mat.reduce();

        for row in &mut expected_rows {
            row.reduce();
        }

        assert_eq!(mat.rows(), &expected_rows);
    }

    #[test]
    fn freeze_canonicalizes_all_entries_q3329() {
        let rows = [make_row_q3329::<3>(-5_000), make_row_q3329::<3>(8_000)];

        let mut mat = PolyMat::<Q3329, 2, 3>::from_rows(rows);

        mat.freeze();

        for row in mat.rows() {
            for poly in row.polys() {
                for &coeff in poly.coeffs() {
                    assert!((0..Q3329::Q).contains(&coeff));
                }
            }
        }
    }

    #[test]
    fn freeze_canonicalizes_all_entries_q8380417() {
        let rows = [
            make_row_q8380417::<4>(-9_000_000),
            make_row_q8380417::<4>(12_000_000),
            make_row_q8380417::<4>(-123_456),
        ];

        let mut mat = PolyMat::<Q8380417, 3, 4>::from_rows(rows);

        mat.freeze();

        for row in mat.rows() {
            for poly in row.polys() {
                for &coeff in poly.coeffs() {
                    assert!((0..Q8380417::Q).contains(&coeff));
                }
            }
        }
    }

    #[test]
    fn dimensions_are_encoded_in_the_type() {
        let mat_2_by_3 = PolyMat::<Q3329, 2, 3>::zero();
        let mat_3_by_2 = PolyMat::<Q3329, 3, 2>::zero();

        assert_eq!(mat_2_by_3.rows().len(), 2);
        assert_eq!(mat_2_by_3.rows()[0].polys().len(), 3);

        assert_eq!(mat_3_by_2.rows().len(), 3);
        assert_eq!(mat_3_by_2.rows()[0].polys().len(), 2);
    }
}
