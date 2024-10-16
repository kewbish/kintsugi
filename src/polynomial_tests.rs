#[cfg(test)]
mod polynomial_test {
    use std::collections::{HashMap, HashSet};

    use curve25519_dalek::Scalar;
    use rand::rngs::OsRng;

    use crate::polynomial::{
        get_lagrange_coefficient, get_lagrange_coefficient_w_target, BivariatePolynomial,
        Polynomial,
    };

    fn i32_to_scalar(i: i32) -> Scalar {
        let mut acc = Scalar::ZERO;
        for _ in 0..i.abs() {
            if i > 0 {
                acc += Scalar::ONE;
            } else {
                acc -= Scalar::ONE;
            }
        }
        acc
    }

    #[test]
    fn test_new_w_secret() {
        let secret = Scalar::random(&mut OsRng);
        let polynomial = Polynomial::new_w_secret(3, secret);

        assert_eq!(polynomial.coeffs[0], secret);
        assert_eq!(polynomial.at(0), secret);
        assert_eq!(polynomial.at_scalar(Scalar::ZERO), secret);
    }

    #[test]
    fn test_serde() {
        let polynomial = Polynomial::new(5);
        let polynomial_bytes = polynomial.clone().to_bytes().unwrap();
        let deser_polynomial = Polynomial::from_bytes(polynomial_bytes).unwrap();
        assert_eq!(polynomial, deser_polynomial);
    }

    #[test]
    fn test_bivariate_poly_interp() {
        let secret = Scalar::random(&mut OsRng);
        let polynomial = Polynomial::new_w_secret(2, secret);
        let share_1 = polynomial.at(1);
        let share_2 = polynomial.at(2);
        let polynomial_1 = Polynomial::new_w_secret(2, share_1);
        let polynomial_2 = Polynomial::new_w_secret(2, share_2);
        let scalar_two = Scalar::ONE + Scalar::ONE;
        let polynomials = HashMap::from([(Scalar::ONE, polynomial_1), (scalar_two, polynomial_2)]);

        let bivariate_polynomial = BivariatePolynomial { polynomials };
        let new_share_1 = bivariate_polynomial.interpolate_0_j(Scalar::ONE);
        assert!(share_1 != new_share_1);
        let new_share_2 = bivariate_polynomial.interpolate_0_j(scalar_two);
        assert!(share_2 != new_share_2);
    }

    #[test]
    fn test_lagrange_coeffs() {
        // precomputed for x = 1,2,3
        let all_indices = HashSet::from([Scalar::ONE, i32_to_scalar(2), i32_to_scalar(3)]);
        assert_eq!(
            get_lagrange_coefficient(Scalar::ONE, all_indices.clone()),
            i32_to_scalar(3)
        );
        assert_eq!(
            get_lagrange_coefficient(i32_to_scalar(2), all_indices.clone()),
            i32_to_scalar(-3)
        );
        assert_eq!(
            get_lagrange_coefficient(i32_to_scalar(3), all_indices.clone()),
            i32_to_scalar(1)
        );
        assert_eq!(
            get_lagrange_coefficient_w_target(i32_to_scalar(2), Scalar::ONE, all_indices.clone()),
            Scalar::ZERO
        );
        assert_eq!(
            get_lagrange_coefficient_w_target(
                i32_to_scalar(3),
                i32_to_scalar(2),
                all_indices.clone()
            ),
            Scalar::ZERO
        );
        assert_eq!(
            get_lagrange_coefficient_w_target(i32_to_scalar(3), Scalar::ONE, all_indices.clone()),
            Scalar::ZERO
        );
        assert_eq!(
            get_lagrange_coefficient_w_target(Scalar::ONE, Scalar::ONE, all_indices.clone()),
            Scalar::ONE
        );
        assert_eq!(
            get_lagrange_coefficient_w_target(
                i32_to_scalar(2),
                i32_to_scalar(2),
                all_indices.clone()
            ),
            Scalar::ONE
        );
        assert_eq!(
            get_lagrange_coefficient_w_target(
                i32_to_scalar(3),
                i32_to_scalar(3),
                all_indices.clone()
            ),
            Scalar::ONE
        );
    }

    #[test]
    fn test_lagrange_interp_to_zero() {
        let secret = Scalar::random(&mut OsRng);
        let polynomial = Polynomial::new_w_secret(2, secret);
        assert_eq!(polynomial.at(0), secret);
        let share_1 = polynomial.at(1);
        let share_2 = polynomial.at(2);
        let share_3 = polynomial.at(3);

        let all_indices = HashSet::from([Scalar::ONE, i32_to_scalar(2), i32_to_scalar(3)]);

        assert_eq!(
            get_lagrange_coefficient(Scalar::ONE, all_indices.clone()) * share_1
                + get_lagrange_coefficient(i32_to_scalar(2), all_indices.clone()) * share_2
                + get_lagrange_coefficient(i32_to_scalar(3), all_indices.clone()) * share_3,
            secret
        );
    }
}
