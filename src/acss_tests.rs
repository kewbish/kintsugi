mod acss_test {
    use std::collections::HashMap;

    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, Scalar};
    use rand::rngs::OsRng;

    use crate::{
        acss::{ACSSInputs, ACSS},
        keypair::Keypair,
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

        let inputs = ACSSInputs {
            h_point,
            degree,
            peer_public_keys,
        };

        let secret = Scalar::random(&mut OsRng);
        let dealer_keypair = Keypair::new();

        let result = ACSS::share_dealer(inputs, secret, degree, dealer_keypair.private_key);
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
        let peer_public_keys = HashMap::from([
            ("Alice".to_string(), keypair_1.public_key),
            ("Bob".to_string(), keypair_2.public_key),
        ]);

        let inputs = ACSSInputs {
            h_point,
            degree,
            peer_public_keys,
        };

        let secret = Scalar::random(&mut OsRng);
        let dealer_keypair = Keypair::new();
        let (shares, _, _) =
            ACSS::share_dealer(inputs.clone(), secret, degree, dealer_keypair.private_key).unwrap();

        let alice_share = shares.get("Alice").unwrap();
        let node_share = ACSS::share(
            inputs.clone(),
            alice_share.clone(),
            keypair_1,
            dealer_keypair.public_key,
        );
        assert!(node_share.is_ok());
        let node_share = node_share.unwrap();

        assert_eq!(
            node_share.c_i,
            node_share.s_i_d * RISTRETTO_BASEPOINT_POINT + node_share.s_hat_i_d * inputs.h_point
        );

        let bad_keypair_share = ACSS::share(
            inputs.clone(),
            alice_share.clone(),
            keypair_2,
            dealer_keypair.public_key,
        );
        assert!(bad_keypair_share.is_err());
    }
}
