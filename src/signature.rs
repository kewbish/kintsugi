use crate::keypair::{Keypair, PublicKey};
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
#[allow(unused_imports)]
use rand::RngCore;
use sha3::{Digest, Sha3_256};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Signature {
    pub(crate) r_point: RistrettoPoint,
    pub(crate) signature: Scalar,
}

impl Signature {
    pub fn new_with_keypair(message: &[u8], keypair: Keypair) -> Self {
        let nonce = Scalar::random(&mut OsRng);
        let r_point = &constants::RISTRETTO_BASEPOINT_POINT * nonce;
        let mut hasher = Sha3_256::new();
        hasher.update(r_point.compress().as_bytes());
        hasher.update(keypair.public_key.as_slice());
        hasher.update(message);
        let hash = hasher.finalize();
        let hash_scalar = Scalar::from_bytes_mod_order(hash.as_slice().try_into().unwrap());
        let private_key = Scalar::from_canonical_bytes(keypair.private_key)
            .expect("Could not deserialize private key in signature generation");
        Signature {
            r_point,
            signature: nonce + (private_key * hash_scalar),
        }
    }

    pub fn verify(self, message: &[u8], public_key: PublicKey) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(self.r_point.compress().as_bytes());
        hasher.update(public_key.as_slice());
        hasher.update(message);
        let hash = hasher.finalize();
        let hash_scalar = Scalar::from_bytes_mod_order(hash.as_slice().try_into().unwrap());
        let public_key_point = CompressedRistretto::from_slice(&public_key)
            .expect("Could not deserialize public key in signature verification")
            .decompress()
            .expect("Could not deserialize public key in signature verification");
        let r_prime =
            &constants::RISTRETTO_BASEPOINT_POINT * self.signature - hash_scalar * public_key_point;
        r_prime == self.r_point
    }
}
