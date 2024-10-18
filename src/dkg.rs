use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar, RistrettoPoint};
use itertools::Itertools;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
    polynomial::{get_lagrange_coefficient_w_target, Polynomial},
    util::i32_to_scalar,
    zkp::DLPZKP,
    P2POpaqueError,
};

struct RandomnessExtractor {
    himatrix: Vec<Vec<Scalar>>,
}

impl RandomnessExtractor {
    fn new(rows: usize, cols: usize) -> Self {
        if rows == 0 || cols == 0 {
            panic!("Hyper-invertible matrix size must be greater than 0");
        }

        let mut omega_values = Vec::with_capacity(rows);
        let mut used_values = std::collections::HashSet::new();

        while omega_values.len() < rows {
            let scalar = Scalar::random(&mut OsRng);
            if scalar != Scalar::ZERO && !used_values.contains(&scalar) {
                used_values.insert(scalar);
                omega_values.push(scalar);
            }
        }

        let mut himatrix = vec![vec![Scalar::ZERO; cols]; rows];

        for i in 0..rows {
            for j in 0..cols {
                if j == 0 {
                    himatrix[i][j] = Scalar::ONE;
                } else if j == 1 {
                    himatrix[i][j] = omega_values[i];
                } else {
                    himatrix[i][j] = omega_values[i] * himatrix[i][j - 1];
                }
            }
        }

        RandomnessExtractor { himatrix }
    }

    #[cfg(test)]
    fn verify_hyper_invertible(&self) -> bool {
        if self.himatrix.len() == 0 || self.himatrix[0].len() == 0 {
            return false;
        }
        let n = std::cmp::min(self.himatrix.len(), self.himatrix[0].len());

        fn determinant(matrix: &[Vec<Scalar>]) -> Scalar {
            let n = matrix.len();
            if n == 1 {
                return matrix[0][0];
            }
            if n == 2 {
                return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
            }

            let mut det = Scalar::ZERO;
            let mut sign = Scalar::ONE;

            for j in 0..n {
                let mut submatrix = Vec::with_capacity(n - 1);
                for i in 1..n {
                    let mut row = Vec::with_capacity(n - 1);
                    for k in 0..n {
                        if k != j {
                            row.push(matrix[i][k]);
                        }
                    }
                    submatrix.push(row);
                }
                det += sign * matrix[0][j] * determinant(&submatrix);
                sign = -sign;
            }
            det
        }

        for size in 1..=n {
            for rows in (0..n).combinations(size) {
                for cols in (0..n).combinations(size) {
                    let mut submatrix = vec![vec![Scalar::ZERO; size]; size];
                    for (i, &row) in rows.iter().enumerate() {
                        for (j, &col) in cols.iter().enumerate() {
                            submatrix[i][j] = self.himatrix[row][col];
                        }
                    }
                    if determinant(&submatrix) == Scalar::ZERO {
                        return false;
                    }
                }
            }
        }

        true
    }

    fn multiply_vector(&self, vec: Vec<Scalar>) -> Vec<Scalar> {
        if self.himatrix.len() == 0 || vec.len() != self.himatrix[0].len() {
            panic!("Vector is the wrong size to multiply with the matrix");
        }

        let mut result = vec![Scalar::ZERO; self.himatrix.len()];
        for i in 0..self.himatrix.len() {
            for j in 0..self.himatrix[0].len() {
                result[i] += self.himatrix[i][j] * vec[j];
            }
        }

        result
    }
}

#[cfg(test)]
mod dkg_tests {
    use super::*;

    #[test]
    fn test_hi_matrix() {
        let re = RandomnessExtractor::new(5, 5); // anything above 8 works in theory but takes ages to run
        assert!(re.verify_hyper_invertible());
    }
}
