#[cfg(test)]
mod dpss_test {
    use std::collections::{HashMap, HashSet};

    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
    use rand::rngs::OsRng;
    use sha3::Sha3_512;

    use crate::{
        dpss::DPSS,
        polynomial::{get_lagrange_coefficient, BivariatePolynomial, Polynomial},
        util::i32_to_scalar,
    };

    #[test]
    fn test_dpss_reshare_old() {
        let s_i_d = Scalar::random(&mut OsRng);
        let s_hat_i_d = Scalar::random(&mut OsRng);
        let new_degree = 3;

        let (poly, poly_hat) = DPSS::reshare_old(s_i_d, s_hat_i_d, new_degree);
        assert_eq!(poly.coeffs.len(), new_degree + 1);
        assert_eq!(poly.at(0), s_i_d);
        assert_eq!(poly_hat.coeffs.len(), new_degree + 1);
        assert_eq!(poly_hat.at(0), s_hat_i_d);
    }

    #[test]
    fn test_dpss_reshare() {
        let secret = Scalar::random(&mut OsRng);
        let h_point = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        let polynomial = Polynomial::new_w_secret(2, secret);
        let s_hat = Scalar::random(&mut OsRng);
        let poly_hat = Polynomial::new_w_secret(2, s_hat);

        let share_1 = polynomial.at_scalar(Scalar::ONE);
        let share_hat_1 = poly_hat.at_scalar(Scalar::ONE);
        let (poly_1, poly_hat_1) = DPSS::reshare_old(share_1, share_hat_1, 1);
        let c_1 = share_1 * RISTRETTO_BASEPOINT_POINT + share_hat_1 * h_point;

        let scalar_two = Scalar::ONE + Scalar::ONE;
        let share_2 = polynomial.at_scalar(scalar_two);
        let share_hat_2 = poly_hat.at_scalar(scalar_two);
        let (poly_2, poly_hat_2) = DPSS::reshare_old(share_2, share_hat_2, 1);
        let c_2 = share_2 * RISTRETTO_BASEPOINT_POINT + share_hat_2 * h_point;

        let scalar_three = Scalar::ONE + Scalar::ONE + Scalar::ONE;
        let share_3 = polynomial.at_scalar(scalar_three);
        let share_hat_3 = poly_hat.at_scalar(scalar_three);
        let (poly_3, poly_hat_3) = DPSS::reshare_old(share_3, share_hat_3, 1);
        let c_3 = share_3 * RISTRETTO_BASEPOINT_POINT + share_hat_3 * h_point;

        let polynomials = HashMap::from([
            (Scalar::ONE, poly_1),
            (scalar_two, poly_2),
            (scalar_three, poly_3),
        ]);
        let polynomials_hats = HashMap::from([
            (Scalar::ONE, poly_hat_1),
            (scalar_two, poly_hat_2),
            (scalar_three, poly_hat_3),
        ]);
        let commitments =
            HashMap::from([(Scalar::ONE, c_1), (scalar_two, c_2), (scalar_three, c_3)]);

        let (new_share_1, new_share_hat_1, commitment_1) = DPSS::reshare(
            Scalar::ONE,
            polynomials.clone(),
            polynomials_hats.clone(),
            commitments.clone(),
        )
        .unwrap();
        assert_eq!(c_1, commitment_1.get(&Scalar::ONE).unwrap().clone());

        let (new_share_2, new_share_hat_2, commitment_2) =
            DPSS::reshare(scalar_two, polynomials, polynomials_hats, commitments).unwrap();
        assert_eq!(c_2, commitment_2.get(&scalar_two).unwrap().clone());

        assert_eq!(commitment_1, commitment_2);

        let all_indices = HashSet::from([Scalar::ONE, scalar_two]);
        assert_eq!(
            get_lagrange_coefficient(Scalar::ONE, all_indices.clone()) * new_share_1
                + get_lagrange_coefficient(scalar_two, all_indices.clone()) * new_share_2,
            secret
        );
        assert_eq!(
            get_lagrange_coefficient(Scalar::ONE, all_indices.clone()) * new_share_hat_1
                + get_lagrange_coefficient(scalar_two, all_indices.clone()) * new_share_hat_2,
            s_hat
        );
    }

    #[test]
    fn test_dpss_reshare_w_evals() {
        let secret = Scalar::random(&mut OsRng);
        let h_point = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        let polynomial = Polynomial::new_w_secret(2, secret);
        let s_hat = Scalar::random(&mut OsRng);
        let poly_hat = Polynomial::new_w_secret(2, s_hat);

        let share_1 = polynomial.at_scalar(Scalar::ONE);
        let share_hat_1 = poly_hat.at_scalar(Scalar::ONE);
        let (poly_1, poly_hat_1) = DPSS::reshare_old(share_1, share_hat_1, 1);
        let c_1 = share_1 * RISTRETTO_BASEPOINT_POINT + share_hat_1 * h_point;

        let scalar_two = Scalar::ONE + Scalar::ONE;
        let share_2 = polynomial.at_scalar(scalar_two);
        let share_hat_2 = poly_hat.at_scalar(scalar_two);
        let (poly_2, poly_hat_2) = DPSS::reshare_old(share_2, share_hat_2, 1);
        let c_2 = share_2 * RISTRETTO_BASEPOINT_POINT + share_hat_2 * h_point;

        let scalar_three = Scalar::ONE + Scalar::ONE + Scalar::ONE;
        let share_3 = polynomial.at_scalar(scalar_three);
        let share_hat_3 = poly_hat.at_scalar(scalar_three);
        let (poly_3, poly_hat_3) = DPSS::reshare_old(share_3, share_hat_3, 1);
        let c_3 = share_3 * RISTRETTO_BASEPOINT_POINT + share_hat_3 * h_point;

        let polynomials_evals_1 = HashMap::from([
            (Scalar::ONE, poly_1.at(1)),
            (scalar_two, poly_2.at(1)),
            (scalar_three, poly_3.at(1)),
        ]);
        let polynomials_hats_1 = HashMap::from([
            (Scalar::ONE, poly_hat_1.at(1)),
            (scalar_two, poly_hat_2.at(1)),
            (scalar_three, poly_hat_3.at(1)),
        ]);
        let polynomials_evals_2 = HashMap::from([
            (Scalar::ONE, poly_1.at(2)),
            (scalar_two, poly_2.at(2)),
            (scalar_three, poly_3.at(2)),
        ]);
        let polynomials_hats_2 = HashMap::from([
            (Scalar::ONE, poly_hat_1.at(2)),
            (scalar_two, poly_hat_2.at(2)),
            (scalar_three, poly_hat_3.at(2)),
        ]);
        let commitments =
            HashMap::from([(Scalar::ONE, c_1), (scalar_two, c_2), (scalar_three, c_3)]);

        let (new_share_1, new_share_hat_1, _) = DPSS::reshare_w_evals(
            polynomials_evals_1.clone(),
            polynomials_hats_1.clone(),
            commitments.clone(),
        )
        .unwrap();

        let (new_share_2, new_share_hat_2, _) =
            DPSS::reshare_w_evals(polynomials_evals_2, polynomials_hats_2, commitments).unwrap();

        assert_eq!(
            BivariatePolynomial::interpolate_0(HashMap::from([
                (Scalar::ONE, new_share_1),
                (scalar_two, new_share_2)
            ])),
            secret
        );
        assert_eq!(
            BivariatePolynomial::interpolate_0(HashMap::from([
                (Scalar::ONE, new_share_hat_1),
                (scalar_two, new_share_hat_2)
            ])),
            s_hat
        );
    }

    #[test]
    fn test_dpss_reshare_w_eval_points() {
        let secret = Scalar::random(&mut OsRng);
        let password_point = RistrettoPoint::hash_from_bytes::<Sha3_512>("pass".as_bytes());

        let rwd = secret * password_point;

        let h_point = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        let polynomial = Polynomial::new_w_secret(2, secret);
        let s_hat = Scalar::random(&mut OsRng);
        let poly_hat = Polynomial::new_w_secret(2, s_hat);

        let share_1 = polynomial.at_scalar(Scalar::ONE);
        let share_hat_1 = poly_hat.at_scalar(Scalar::ONE);
        let (poly_1, poly_hat_1) = DPSS::reshare_old(share_1, share_hat_1, 1);
        let c_1 = share_1 * RISTRETTO_BASEPOINT_POINT + share_hat_1 * h_point;

        let scalar_two = Scalar::ONE + Scalar::ONE;
        let share_2 = polynomial.at_scalar(scalar_two);
        let share_hat_2 = poly_hat.at_scalar(scalar_two);
        let (poly_2, poly_hat_2) = DPSS::reshare_old(share_2, share_hat_2, 1);
        let c_2 = share_2 * RISTRETTO_BASEPOINT_POINT + share_hat_2 * h_point;

        let scalar_three = Scalar::ONE + Scalar::ONE + Scalar::ONE;
        let share_3 = polynomial.at_scalar(scalar_three);
        let share_hat_3 = poly_hat.at_scalar(scalar_three);
        let (poly_3, poly_hat_3) = DPSS::reshare_old(share_3, share_hat_3, 1);
        let c_3 = share_3 * RISTRETTO_BASEPOINT_POINT + share_hat_3 * h_point;

        let polynomials_evals_1 = HashMap::from([
            (Scalar::ONE, poly_1.at(1)),
            (scalar_two, poly_2.at(1)),
            (scalar_three, poly_3.at(1)),
        ]);
        let polynomials_hats_1 = HashMap::from([
            (Scalar::ONE, poly_hat_1.at(1)),
            (scalar_two, poly_hat_2.at(1)),
            (scalar_three, poly_hat_3.at(1)),
        ]);
        let polynomials_evals_2 = HashMap::from([
            (Scalar::ONE, poly_1.at(2)),
            (scalar_two, poly_2.at(2)),
            (scalar_three, poly_3.at(2)),
        ]);
        let polynomials_hats_2 = HashMap::from([
            (Scalar::ONE, poly_hat_1.at(2)),
            (scalar_two, poly_hat_2.at(2)),
            (scalar_three, poly_hat_3.at(2)),
        ]);
        let commitments =
            HashMap::from([(Scalar::ONE, c_1), (scalar_two, c_2), (scalar_three, c_3)]);

        let (new_share_1, _, _) = DPSS::reshare_w_evals(
            polynomials_evals_1.clone(),
            polynomials_hats_1.clone(),
            commitments.clone(),
        )
        .unwrap();

        let (new_share_2, _, _) =
            DPSS::reshare_w_evals(polynomials_evals_2, polynomials_hats_2, commitments).unwrap();

        let new_rwd_share_1 = new_share_1 * password_point;
        let new_rwd_share_2 = new_share_2 * password_point;

        let mut all_indices = HashSet::from([i32_to_scalar(1), i32_to_scalar(2), i32_to_scalar(3)]);
        let combined_rwd = get_lagrange_coefficient(i32_to_scalar(1), all_indices.clone())
            * share_1
            * password_point
            + get_lagrange_coefficient(i32_to_scalar(2), all_indices.clone())
                * share_2
                * password_point
            + get_lagrange_coefficient(i32_to_scalar(3), all_indices.clone())
                * share_3
                * password_point;
        all_indices.remove(&i32_to_scalar(3));
        let new_combined_rwd = get_lagrange_coefficient(i32_to_scalar(1), all_indices.clone())
            * new_rwd_share_1
            + get_lagrange_coefficient(i32_to_scalar(2), all_indices) * new_rwd_share_2;

        assert_eq!(combined_rwd, rwd);
        assert_eq!(new_combined_rwd, rwd);
    }
}
