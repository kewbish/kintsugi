#[cfg(test)]
mod dpss_test {
    use std::collections::{HashMap, HashSet};

    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, Scalar};
    use rand::rngs::OsRng;

    use crate::{
        dpss::DPSS,
        polynomial::{get_lagrange_coefficient, Polynomial},
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
            h_point,
        )
        .unwrap();
        assert_eq!(c_1, commitment_1.get(&Scalar::ONE).unwrap().clone());

        let (new_share_2, new_share_hat_2, commitment_2) = DPSS::reshare(
            scalar_two,
            polynomials,
            polynomials_hats,
            commitments,
            h_point,
        )
        .unwrap();
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
}
