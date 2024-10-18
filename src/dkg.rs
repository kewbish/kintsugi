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

struct DKG {}

struct DKGAgreements {
    fhalf_shares: Vec<Scalar>,
    fhalf_hat_shares: Vec<Scalar>,
    shalf_shares: Vec<Scalar>,
    shalf_hat_shares: Vec<Scalar>,
    fhalf_commitments: Vec<RistrettoPoint>,
    shalf_commitments: Vec<RistrettoPoint>,
}

#[derive(Serialize, Deserialize, Clone)]
struct DKGKeyDerivation {
    g_z_i: RistrettoPoint,
    h_z_hat_i: RistrettoPoint,
    zkp: DLPZKP,
    zkp_hat: DLPZKP,
}

impl DKG {
    fn share() -> (Scalar, Scalar) {
        (Scalar::random(&mut OsRng), Scalar::random(&mut OsRng))
    }
    fn agreement_vec(
        consensus: HashSet<Scalar>,
        a: Polynomial,
        a_hat: Polynomial,
        b: Polynomial,
        b_hat: Polynomial,
        h_point: RistrettoPoint,
        max_nodes: usize,
    ) -> DKGAgreements {
        let mut a_shares = Vec::new();
        let mut a_hat_shares = Vec::new();
        let mut b_shares = Vec::new();
        let mut b_hat_shares = Vec::new();
        let mut u_commitments = Vec::new();
        let mut v_commitments = Vec::new();

        for i in 1..max_nodes + 1 {
            if consensus.contains(&i32_to_scalar(i as i32)) {
                a_shares.push(a.at(i));
                a_hat_shares.push(a_hat.at(i));
                b_shares.push(b.at(i));
                b_hat_shares.push(b_hat.at(i));
                u_commitments
                    .push(a.at(i) * RISTRETTO_BASEPOINT_POINT + a_hat.at(i) * h_point.clone());
                v_commitments
                    .push(b.at(i) * RISTRETTO_BASEPOINT_POINT + b_hat.at(i) * h_point.clone());
            } else {
            }
        }

        DKGAgreements {
            fhalf_shares: a_shares,
            fhalf_hat_shares: a_hat_shares,
            shalf_shares: b_shares,
            shalf_hat_shares: b_hat_shares,
            fhalf_commitments: u_commitments,
            shalf_commitments: v_commitments,
        }
    }

    fn randomness_extraction(
        num_sshares: usize,
        threshold: usize,
        node_agreements: DKGAgreements,
    ) -> (Vec<Scalar>, Vec<Scalar>) {
        let re = RandomnessExtractor::new(threshold / 2, num_sshares);
        let z_fhalf_shares = re.multiply_vector(node_agreements.fhalf_shares);
        let z_fhalf_hat_shares = re.multiply_vector(node_agreements.fhalf_hat_shares);
        let z_shalf_shares = re.multiply_vector(node_agreements.shalf_shares);
        let z_shalf_hat_shares = re.multiply_vector(node_agreements.shalf_hat_shares);
        let mut z_shares = z_fhalf_shares.clone();
        z_shares.append(&mut z_shalf_shares.clone());
        let z_poly_share = Polynomial {
            coeffs: z_shares.clone(),
        };
        let executions: Vec<Scalar> = (0..z_shares.len()).map(|x| z_poly_share.at(x)).collect();

        let mut z_hat_shares = z_fhalf_hat_shares.clone();
        z_hat_shares.append(&mut z_shalf_hat_shares.clone());
        let z_hat_poly_share = Polynomial {
            coeffs: z_hat_shares.clone(),
        };
        let executions_hat: Vec<Scalar> = (0..z_hat_shares.len())
            .map(|x| z_hat_poly_share.at(x))
            .collect();

        (executions, executions_hat)
    }

    fn pre_key_derivation(
        index: usize,
        execution_result: HashMap<Scalar, Scalar>,
        execution_hat_result: HashMap<Scalar, Scalar>,
    ) -> (Scalar, Scalar) {
        let all_indices: HashSet<Scalar> = execution_result.keys().copied().collect();
        let mut z_i = Scalar::ZERO;
        for (other_index, z_i_share) in execution_result.iter() {
            z_i += get_lagrange_coefficient_w_target(
                i32_to_scalar(index as i32),
                other_index.clone(),
                all_indices.clone(),
            ) * z_i_share;
        }

        let mut z_hat_i = Scalar::ZERO;
        for (other_index, z_hat_i_share) in execution_hat_result.iter() {
            z_hat_i += get_lagrange_coefficient_w_target(
                i32_to_scalar(index as i32),
                other_index.clone(),
                all_indices.clone(),
            ) * z_hat_i_share;
        }

        (z_i, z_hat_i)
    }

    fn pre_key_derivation_public(
        z_i: Scalar,
        z_hat_i: Scalar,
        h_point: RistrettoPoint,
    ) -> DKGKeyDerivation {
        DKGKeyDerivation {
            g_z_i: RISTRETTO_BASEPOINT_POINT * z_i,
            h_z_hat_i: h_point * z_hat_i,
            zkp: DLPZKP::new(z_i, RISTRETTO_BASEPOINT_POINT * z_i),
            zkp_hat: DLPZKP::new(z_hat_i, h_point * z_hat_i),
        }
    }

    fn key_derivation(
        total_size: usize,
        key_deriv: HashMap<Scalar, DKGKeyDerivation>,
    ) -> Result<HashMap<Scalar, RistrettoPoint>, P2POpaqueError> {
        for (_, derivation) in key_deriv.clone().iter() {
            if !derivation.zkp.verify(derivation.g_z_i)
                || !derivation.zkp_hat.verify(derivation.h_z_hat_i)
            {
                return Err(P2POpaqueError::CryptoError(
                    "ZKP could not be verified".to_string(),
                ));
            }
        }

        let all_indices: HashSet<Scalar> = key_deriv.keys().copied().collect();
        let mut result = HashMap::new();
        for i in 0..total_size + 1 {
            let mut point = Scalar::ZERO * RISTRETTO_BASEPOINT_POINT;
            for (other_index, other_share) in key_deriv.clone().iter() {
                point += get_lagrange_coefficient_w_target(
                    i32_to_scalar(i as i32),
                    other_index.clone(),
                    all_indices.clone(),
                ) * other_share.g_z_i;
            }
            result.insert(i32_to_scalar(i as i32), point);
        }

        Ok(result)
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
