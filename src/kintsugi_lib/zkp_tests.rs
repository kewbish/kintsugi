#[cfg(test)]
mod zkp_test {
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, Scalar};
    use rand::rngs::OsRng;

    use crate::kintsugi_lib::zkp::{DLPZKP, ZKP};

    #[test]
    fn test_zkp_verify() {
        let phi_i = Scalar::random(&mut OsRng);
        let phi_hat_i = Scalar::random(&mut OsRng);
        let h_point = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        let commitment = phi_i * RISTRETTO_BASEPOINT_POINT + phi_hat_i * h_point;
        let zkp = ZKP::new(phi_i, phi_hat_i, h_point, commitment);

        assert!(zkp.verify(h_point, commitment));

        let fake_commitment = phi_i * RISTRETTO_BASEPOINT_POINT + phi_i * h_point;
        assert!(!zkp.verify(h_point, fake_commitment));

        let fake_h_point = h_point + h_point;
        assert!(!zkp.verify(fake_h_point, commitment));
    }

    #[test]
    fn test_dlpzkp_verify() {
        let x = Scalar::random(&mut OsRng);
        let public_point = x * RISTRETTO_BASEPOINT_POINT;
        let zkp = DLPZKP::new(x, RISTRETTO_BASEPOINT_POINT, public_point);

        assert!(zkp.verify(RISTRETTO_BASEPOINT_POINT, public_point));

        let fake_commitment = x * RISTRETTO_BASEPOINT_POINT + public_point;
        assert!(!zkp.verify(RISTRETTO_BASEPOINT_POINT, fake_commitment));
        assert!(!zkp.verify(fake_commitment, public_point));

        let h_point = public_point;
        let x = Scalar::random(&mut OsRng);
        let public_point = x * h_point;
        let zkp = DLPZKP::new(x, h_point, public_point);

        assert!(zkp.verify(h_point, public_point));
    }
}
