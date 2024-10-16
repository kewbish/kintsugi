#[cfg(test)]
mod oprf_test {
    use std::collections::HashSet;

    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, Scalar};
    use rand::rngs::OsRng;

    use crate::{
        oprf::{OPRFClient, OPRFServer},
        polynomial::Polynomial,
    };

    #[test]
    fn test_oprf_blind_unblind() {
        let point = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        let (blinded_result, oprf_client) = OPRFClient::blind(point);

        assert_eq!(oprf_client.unblind(blinded_result).unwrap(), point);
    }

    #[test]
    fn test_incremental_blind_eval() {
        let secret = Scalar::random(&mut OsRng);
        let polynomial = Polynomial::new_w_secret(2, secret);
        let share_1 = polynomial.at_scalar(Scalar::ONE);
        let scalar_two = Scalar::ONE + Scalar::ONE;
        let share_2 = polynomial.at_scalar(scalar_two);
        let scalar_three = Scalar::ONE + Scalar::ONE + Scalar::ONE;
        let share_3 = polynomial.at_scalar(scalar_three);

        let point = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        let other_indices = HashSet::from([Scalar::ONE, scalar_two, scalar_three]);

        let blind_eval_1 =
            OPRFServer::blind_evaluate(point, share_1, Scalar::ONE, other_indices.clone());
        let blind_eval_2 =
            OPRFServer::blind_evaluate(point, share_2, scalar_two, other_indices.clone());
        let blind_eval_3 =
            OPRFServer::blind_evaluate(point, share_3, scalar_three, other_indices.clone());
        assert_eq!(blind_eval_1 + blind_eval_2 + blind_eval_3, secret * point);
    }

    #[test]
    fn test_full_flow() {
        let point = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        let (blinded_result, oprf_client) = OPRFClient::blind(point);

        let secret = Scalar::random(&mut OsRng);
        let polynomial = Polynomial::new_w_secret(2, secret);
        let share_1 = polynomial.at_scalar(Scalar::ONE);
        let scalar_two = Scalar::ONE + Scalar::ONE;
        let share_2 = polynomial.at_scalar(scalar_two);
        let scalar_three = Scalar::ONE + Scalar::ONE + Scalar::ONE;
        let share_3 = polynomial.at_scalar(scalar_three);

        let other_indices = HashSet::from([Scalar::ONE, scalar_two, scalar_three]);

        let blind_eval_1 =
            OPRFServer::blind_evaluate(blinded_result, share_1, Scalar::ONE, other_indices.clone());
        let blind_eval_2 =
            OPRFServer::blind_evaluate(blinded_result, share_2, scalar_two, other_indices.clone());
        let blind_eval_3 = OPRFServer::blind_evaluate(
            blinded_result,
            share_3,
            scalar_three,
            other_indices.clone(),
        );

        assert_eq!(
            blind_eval_1 + blind_eval_2 + blind_eval_3,
            oprf_client.current_blinding_scalar.unwrap() * secret * point
        );

        let unblind_result = oprf_client.unblind(blind_eval_1 + blind_eval_2 + blind_eval_3);
        assert!(unblind_result.is_ok());
        assert_eq!(unblind_result.unwrap(), secret * point);
    }
}
