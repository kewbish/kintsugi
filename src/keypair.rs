use curve25519_dalek::constants;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
#[allow(unused_imports)]
use rand::RngCore;

pub type PublicKey = [u8; 32];
pub type PrivateKey = [u8; 32];

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct Keypair {
    pub(crate) private_key: PrivateKey,
    pub(crate) public_key: PublicKey,
}

impl Keypair {
    pub fn new() -> Self {
        let private_key = Scalar::random(&mut OsRng);
        let public_key = &constants::RISTRETTO_BASEPOINT_POINT * private_key;
        Keypair {
            private_key: private_key.to_bytes(),
            public_key: public_key.compress().to_bytes(),
        }
    }
}
