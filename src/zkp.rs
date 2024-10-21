use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar, RistrettoPoint};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

#[derive(Clone)]
pub struct ZKP {
    // does not prove knowledge under encryption but verifies commitment
    pub(crate) A: RistrettoPoint,
    pub(crate) z_1: Scalar,
    pub(crate) z_2: Scalar,
}

impl ZKP {
    pub fn new(
        phi_i: Scalar,
        phi_hat_i: Scalar,
        h_point: RistrettoPoint,
        commitment: RistrettoPoint,
    ) -> Self {
        let r_1 = Scalar::random(&mut OsRng);
        let r_2 = Scalar::random(&mut OsRng);
        let A = r_1 * RISTRETTO_BASEPOINT_POINT + r_2 * h_point;

        let mut hasher = Sha3_256::new();
        hasher.update(A.compress().to_bytes());
        hasher.update(h_point.compress().to_bytes());
        hasher.update(commitment.compress().to_bytes());
        let challenge_hash = hasher.finalize();
        let challenge = Scalar::from_bytes_mod_order(challenge_hash.into());

        let z_1 = r_1 + challenge * phi_i;
        let z_2 = r_2 + challenge * phi_hat_i;
        ZKP { A, z_1, z_2 }
    }

    pub fn verify(&self, h_point: RistrettoPoint, commitment: RistrettoPoint) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(self.A.compress().to_bytes());
        hasher.update(h_point.compress().to_bytes());
        hasher.update(commitment.compress().to_bytes());
        let challenge_hash = hasher.finalize();
        let challenge = Scalar::from_bytes_mod_order(challenge_hash.into());

        return self.z_1 * RISTRETTO_BASEPOINT_POINT + self.z_2 * h_point
            == self.A + challenge * commitment;
    }
}

#[cfg(test)]
#[path = "zkp_tests.rs"]
mod zkp_test;

#[derive(Serialize, Deserialize, Clone)]
pub struct DLPZKP {
    u: RistrettoPoint,
    c: Scalar,
    z: Scalar,
}

impl DLPZKP {
    pub fn new(secret: Scalar, base_point: RistrettoPoint, public_point: RistrettoPoint) -> Self {
        let r = Scalar::random(&mut OsRng);
        let u = r * base_point;
        let mut hasher = Sha3_256::new();
        hasher.update(base_point.compress().to_bytes());
        hasher.update(public_point.compress().to_bytes());
        hasher.update(u.compress().to_bytes());
        let challenge_hash = hasher.finalize();
        let challenge = Scalar::from_bytes_mod_order(challenge_hash.into());
        let z = r + challenge * secret;

        DLPZKP { u, c: challenge, z }
    }

    pub fn verify(&self, base_point: RistrettoPoint, public_point: RistrettoPoint) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(base_point.compress().to_bytes());
        hasher.update(public_point.compress().to_bytes());
        hasher.update(self.u.compress().to_bytes());
        let challenge_hash = hasher.finalize();
        let challenge = Scalar::from_bytes_mod_order(challenge_hash.into());

        return self.z * base_point == self.u + challenge * public_point;
    }
}
