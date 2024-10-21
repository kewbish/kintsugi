use std::collections::{HashMap, HashSet};

use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};

use crate::{
    opaque::P2POpaqueError,
    polynomial::{get_lagrange_coefficient_w_target, BivariatePolynomial, Polynomial},
};

struct DPSS {}

impl DPSS {
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

    fn reshare(
        index: Scalar,
        polynomials: HashMap<Scalar, Polynomial>,
        polynomials_hats: HashMap<Scalar, Polynomial>,
        commitments: HashMap<Scalar, RistrettoPoint>,
        h_point: RistrettoPoint,
    ) -> Result<(Scalar, Scalar, HashMap<Scalar, RistrettoPoint>), P2POpaqueError> {
        let polynomials_keys: HashSet<Scalar> = polynomials.keys().copied().collect();
        let polynomials_hats_keys: HashSet<Scalar> = polynomials_hats.keys().copied().collect();
        let commitments_keys: HashSet<Scalar> = commitments.keys().copied().collect();
        if !(polynomials_keys == polynomials_hats_keys && polynomials_hats_keys == commitments_keys)
        {
            return Err(P2POpaqueError::CryptoError(
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

        /*Ok((
            s_i_d_prime,
            s_hat_i_d_prime,
            s_i_d_prime * RISTRETTO_BASEPOINT_POINT + s_hat_i_d_prime * h_point,
        ))*/
        Ok((s_i_d_prime, s_hat_i_d_prime, new_commitments))
    }
}

#[cfg(test)]
#[path = "dpss_tests.rs"]
mod dpss_test;
