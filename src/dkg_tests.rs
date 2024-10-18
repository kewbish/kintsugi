#[cfg(test)]
mod dkg_tests {
    use std::collections::{HashMap, HashSet};

    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, Scalar};
    use rand::rngs::OsRng;

    use crate::{
        dkg::{RandomnessExtractor, DKG},
        polynomial::Polynomial,
        util::i32_to_scalar,
    };

    #[test]
    fn test_hi_matrix() {
        let re = RandomnessExtractor::new(5, 5); // anything above 8 works in theory but takes ages to run
        assert!(re.verify_hyper_invertible());
    }

    #[test]
    fn test_dkg() {
        // do a 2/3 scheme
        let h_point = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;

        let (node_1_share_a, node_1_share_b) = DKG::share();
        let (node_1_share_a_hat, node_1_share_b_hat) = DKG::share(); // just to get random scalars
        let poly_a_1 = Polynomial::new_w_secret(1, node_1_share_a);
        let poly_a_hat_1 = Polynomial::new_w_secret(1, node_1_share_a_hat);
        let poly_b_1 = Polynomial::new_w_secret(1, node_1_share_b);
        let poly_b_hat_1 = Polynomial::new_w_secret(1, node_1_share_b_hat);

        let (node_2_share_a, node_2_share_b) = DKG::share();
        let (node_2_share_a_hat, node_2_share_b_hat) = DKG::share(); // just to get random scalars
        let poly_a_2 = Polynomial::new_w_secret(1, node_2_share_a);
        let poly_a_hat_2 = Polynomial::new_w_secret(1, node_2_share_a_hat);
        let poly_b_2 = Polynomial::new_w_secret(1, node_2_share_b);
        let poly_b_hat_2 = Polynomial::new_w_secret(1, node_2_share_b_hat);

        let (node_3_share_a, node_3_share_b) = DKG::share();
        let (node_3_share_a_hat, node_3_share_b_hat) = DKG::share(); // just to get random scalars
        let poly_a_3 = Polynomial::new_w_secret(1, node_3_share_a);
        let poly_a_hat_3 = Polynomial::new_w_secret(1, node_3_share_a_hat);
        let poly_b_3 = Polynomial::new_w_secret(1, node_3_share_b);
        let poly_b_hat_3 = Polynomial::new_w_secret(1, node_3_share_b_hat);

        let consensus = HashSet::from([i32_to_scalar(1), i32_to_scalar(2), i32_to_scalar(3)]);

        let node_1_agreements = DKG::agreement_vec(
            consensus.clone(),
            poly_a_1,
            poly_a_hat_1,
            poly_b_1,
            poly_b_hat_1,
            h_point,
            3,
        );
        let node_2_agreements = DKG::agreement_vec(
            consensus.clone(),
            poly_a_2,
            poly_a_hat_2,
            poly_b_2,
            poly_b_hat_2,
            h_point,
            3,
        );
        let node_3_agreements = DKG::agreement_vec(
            consensus.clone(),
            poly_a_3,
            poly_a_hat_3,
            poly_b_3,
            poly_b_hat_3,
            h_point,
            3,
        );

        let (node_1_executions, node_1_executions_hat) =
            DKG::randomness_extraction(2, node_1_agreements, 3);
        let (node_2_executions, node_2_executions_hat) =
            DKG::randomness_extraction(2, node_2_agreements, 3);
        let (node_3_executions, node_3_executions_hat) =
            DKG::randomness_extraction(2, node_3_agreements, 3);

        let node_1_results = HashMap::from([
            (i32_to_scalar(1), node_1_executions[1]),
            (i32_to_scalar(2), node_2_executions[1]),
            (i32_to_scalar(3), node_3_executions[1]),
        ]);
        let node_2_results = HashMap::from([
            (i32_to_scalar(1), node_1_executions[2]),
            (i32_to_scalar(2), node_2_executions[2]),
            (i32_to_scalar(3), node_3_executions[2]),
        ]);
        let node_3_results = HashMap::from([
            (i32_to_scalar(1), node_1_executions[3]),
            (i32_to_scalar(2), node_2_executions[3]),
            (i32_to_scalar(3), node_3_executions[3]),
        ]);
        let node_1_results_hat = HashMap::from([
            (i32_to_scalar(1), node_1_executions_hat[1]),
            (i32_to_scalar(2), node_2_executions_hat[1]),
            (i32_to_scalar(3), node_3_executions_hat[1]),
        ]);
        let node_2_results_hat = HashMap::from([
            (i32_to_scalar(1), node_1_executions_hat[2]),
            (i32_to_scalar(2), node_2_executions_hat[2]),
            (i32_to_scalar(3), node_3_executions_hat[2]),
        ]);
        let node_3_results_hat = HashMap::from([
            (i32_to_scalar(1), node_1_executions_hat[3]),
            (i32_to_scalar(2), node_2_executions_hat[3]),
            (i32_to_scalar(3), node_3_executions_hat[3]),
        ]);

        let (node_1_z_i, node_1_z_hat_i) =
            DKG::pre_key_derivation(1, node_1_results, node_1_results_hat);
        let (node_2_z_i, node_2_z_hat_i) =
            DKG::pre_key_derivation(2, node_2_results, node_2_results_hat);
        let (node_3_z_i, node_3_z_hat_i) =
            DKG::pre_key_derivation(3, node_3_results, node_3_results_hat);

        let node_1_derivation = DKG::pre_key_derivation_public(node_1_z_i, node_1_z_hat_i, h_point);
        let node_2_derivation = DKG::pre_key_derivation_public(node_2_z_i, node_2_z_hat_i, h_point);
        let node_3_derivation = DKG::pre_key_derivation_public(node_3_z_i, node_3_z_hat_i, h_point);

        let key_deriv = HashMap::from([
            (i32_to_scalar(1), node_1_derivation),
            (i32_to_scalar(2), node_2_derivation),
            (i32_to_scalar(3), node_3_derivation),
        ]);

        let derivation_points = DKG::key_derivation(3, key_deriv);
        assert!(derivation_points.is_ok());
    }
}
