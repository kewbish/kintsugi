use std::collections::{HashMap, HashSet};

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};

use crate::{
    kintsugi_lib::error::KintsugiError,
    kintsugi_lib::polynomial::{
        get_lagrange_coefficient_w_target, BivariatePolynomial, Polynomial,
    },
};

pub struct DPSS {}

impl DPSS {
    #[allow(dead_code)]
    fn reshare_old(
        s_i_d: Scalar,
        s_hat_i_d: Scalar,
        new_degree: usize,
    ) -> (Polynomial, Polynomial) {
        (
            Polynomial::new_w_secret(new_degree, s_i_d),
            Polynomial::new_w_secret(new_degree, s_hat_i_d),
        )
    }

    #[allow(dead_code)]
    fn reshare(
        index: Scalar,
        polynomials: HashMap<Scalar, Polynomial>,
        polynomials_hats: HashMap<Scalar, Polynomial>,
        commitments: HashMap<Scalar, RistrettoPoint>,
    ) -> Result<(Scalar, Scalar, HashMap<Scalar, RistrettoPoint>), KintsugiError> {
        let polynomials_keys: HashSet<Scalar> = polynomials.keys().copied().collect();
        let polynomials_hats_keys: HashSet<Scalar> = polynomials_hats.keys().copied().collect();
        let commitments_keys: HashSet<Scalar> = commitments.keys().copied().collect();
        if !(polynomials_keys == polynomials_hats_keys && polynomials_hats_keys == commitments_keys)
        {
            return Err(KintsugiError::CryptoError(
                "Missing shares, blinding factors, or commitments for some nodes".to_string(),
            ));
        }

        let bivariate_polynomial = BivariatePolynomial { polynomials };
        let bivariate_hat_polynomial = BivariatePolynomial {
            polynomials: polynomials_hats,
        };
        let s_i_d_prime = bivariate_polynomial.interpolate_0_j(index);
        let s_hat_i_d_prime = bivariate_hat_polynomial.interpolate_0_j(index);

        let mut new_commitments = HashMap::new();
        for (i, _) in commitments.iter() {
            let mut new_commitment = Scalar::ZERO * RISTRETTO_BASEPOINT_POINT;
            for (other_index, other_old_commitment) in commitments.iter() {
                new_commitment += get_lagrange_coefficient_w_target(
                    i.clone(),
                    other_index.clone(),
                    commitments_keys.clone(),
                ) * other_old_commitment;
            }
            new_commitments.insert(i.clone(), new_commitment);
        }

        Ok((s_i_d_prime, s_hat_i_d_prime, new_commitments))
    }

    pub fn reshare_w_evals(
        evaluations: HashMap<Scalar, Scalar>,
        evaluations_hats: HashMap<Scalar, Scalar>,
    ) -> Result<(Scalar, Scalar), KintsugiError> {
        let evals_keys: HashSet<Scalar> = evaluations.keys().copied().collect();
        let evals_hats_keys: HashSet<Scalar> = evaluations_hats.keys().copied().collect();
        if !(evals_keys == evals_hats_keys) {
            return Err(KintsugiError::CryptoError(
                "Missing shares or blinding factors for some nodes".to_string(),
            ));
        }

        let s_i_d_prime = BivariatePolynomial::interpolate_0(evaluations);
        let s_hat_i_d_prime = BivariatePolynomial::interpolate_0(evaluations_hats);

        Ok((s_i_d_prime, s_hat_i_d_prime))
    }

    pub fn get_commitment_at_index(
        index: Scalar,
        commitments: HashMap<Scalar, RistrettoPoint>,
    ) -> RistrettoPoint {
        let commitments_keys: HashSet<Scalar> = commitments.keys().copied().collect();
        let mut new_commitment = Scalar::ZERO * RISTRETTO_BASEPOINT_POINT;
        for (other_index, other_old_commitment) in commitments.iter() {
            new_commitment += get_lagrange_coefficient_w_target(
                index.clone(),
                other_index.clone(),
                commitments_keys.clone(),
            ) * other_old_commitment;
        }
        new_commitment
    }
}

#[cfg(test)]
#[path = "dpss_tests.rs"]
mod dpss_test;
