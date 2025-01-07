mod acss_test {
    use std::collections::HashMap;

    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, Scalar};
    use rand::rngs::OsRng;

    use crate::{
        acss::ACSS, keypair::Keypair, polynomial::BivariatePolynomial, util::i32_to_scalar,
    };

    #[test]
    fn test_dealer_share() {
        let h_point = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        let degree = 2;
        let keypair_1 = Keypair::new();
        let keypair_2 = Keypair::new();
        let peer_public_keys = HashMap::from([
            ("Alice".to_string(), keypair_1.public_key),
            ("Bob".to_string(), keypair_2.public_key),
        ]);
        let peer_indexes = HashMap::from([("Alice".to_string(), 1), ("Bob".to_string(), 2)]);

        let secret = Scalar::random(&mut OsRng);
        let dealer_keypair = Keypair::new();

        let result = ACSS::share_dealer(
            h_point,
            secret,
            degree,
            dealer_keypair.private_key,
            peer_public_keys,
            peer_indexes,
        );
        assert!(result.is_ok());
        let (shares, _, _) = result.unwrap();
        assert!(shares.contains_key("Alice"));
        assert!(shares.contains_key("Bob"));

        let alice_share = shares.get("Alice").unwrap();
        let bob_share = shares.get("Bob").unwrap();
        for share in [alice_share, bob_share] {
            assert!(share.proof.verify(h_point, share.c_i));
        }
    }

    #[test]
    fn test_node_share() {
        let h_point = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        let degree = 2;
        let keypair_1 = Keypair::new();
        let keypair_2 = Keypair::new();
        let keypair_3 = Keypair::new();
        let peer_public_keys = HashMap::from([
            ("Alice".to_string(), keypair_1.public_key),
            ("Bob".to_string(), keypair_2.public_key),
            ("Charlie".to_string(), keypair_3.public_key),
        ]);
        let peer_indexes = HashMap::from([
            ("Alice".to_string(), 1),
            ("Bob".to_string(), 2),
            ("Charlie".to_string(), 3),
        ]);

        let secret = Scalar::random(&mut OsRng);
        let dealer_keypair = Keypair::new();
        let (shares, _, _) = ACSS::share_dealer(
            h_point.clone(),
            secret,
            degree,
            dealer_keypair.private_key,
            peer_public_keys,
            peer_indexes,
        )
        .unwrap();

        let alice_share = shares.get("Alice").unwrap();
        let node_share = ACSS::share(
            h_point.clone(),
            alice_share.clone(),
            keypair_1,
            dealer_keypair.public_key,
        );
        assert!(node_share.is_ok());
        let node_share = node_share.unwrap();

        assert_eq!(
            node_share.c_i,
            node_share.s_i_d * RISTRETTO_BASEPOINT_POINT + node_share.s_hat_i_d * h_point.clone()
        );

        let bad_keypair_share = ACSS::share(
            h_point.clone(),
            alice_share.clone(),
            keypair_2.clone(),
            dealer_keypair.public_key,
        );
        assert!(bad_keypair_share.is_err());

        let bob_share = shares.get("Bob").unwrap();
        let node_share_2 = ACSS::share(
            h_point.clone(),
            bob_share.clone(),
            keypair_2,
            dealer_keypair.public_key,
        )
        .unwrap();

        let charlie_share = shares.get("Charlie").unwrap();
        let node_share_3 = ACSS::share(
            h_point.clone(),
            charlie_share.clone(),
            keypair_3,
            dealer_keypair.public_key,
        )
        .unwrap();

        let evaluations = HashMap::from([
            (i32_to_scalar(alice_share.index as i32), node_share.s_i_d),
            (i32_to_scalar(bob_share.index as i32), node_share_2.s_i_d),
            (
                i32_to_scalar(charlie_share.index as i32),
                node_share_3.s_i_d,
            ),
        ]);
        assert_eq!(BivariatePolynomial::interpolate_0(evaluations), secret);
    }
}
