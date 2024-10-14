use std::collections::{HashMap, HashSet};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar, RistrettoPoint};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::{keypair::PublicKey, P2POpaqueError};

struct ZKP {
    // does not prove knowledge under encryption but verifies commitment
    A: RistrettoPoint,
    z_1: Scalar,
    z_2: Scalar,
}

impl ZKP {
    fn new(
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
    fn verify(proof: ZKP, h_point: RistrettoPoint, commitment: RistrettoPoint) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(proof.A.compress().to_bytes());
        hasher.update(h_point.compress().to_bytes());
        hasher.update(commitment.compress().to_bytes());
        let challenge_hash = hasher.finalize();
        let challenge = Scalar::from_bytes_mod_order(challenge_hash.into());

        return proof.z_1 * RISTRETTO_BASEPOINT_POINT + proof.z_2 * h_point
            == proof.A + challenge * commitment;
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Polynomial {
    coeffs: Vec<Scalar>,
}

fn usize_to_scalar(i: usize) -> Scalar {
    let mut i_bytes = [0u8; 32];
    i_bytes[..8].copy_from_slice(&i.to_le_bytes());
    Scalar::from_bytes_mod_order(i_bytes)
}

impl Polynomial {
    fn new(degree: usize) -> Self {
        let mut polynomial = Vec::with_capacity(degree + 1);
        for i in 0..(degree + 1) {
            polynomial[i] = Scalar::random(&mut OsRng)
        }
        Polynomial { coeffs: polynomial }
    }
    fn new_w_secret(degree: usize, secret: Scalar) -> Self {
        let mut polynomial = Polynomial::new(degree);
        polynomial.coeffs[0] = secret;
        polynomial
    }
    fn to_bytes(self) -> Result<Vec<u8>, P2POpaqueError> {
        let string_res = serde_json::to_string(&self);
        if let Err(e) = string_res {
            return Err(P2POpaqueError::SerializationError(
                "JSON serialization of polynomial failed: ".to_string() + &e.to_string(),
            ));
        }
        Ok(string_res.unwrap().into_bytes())
    }
    fn from_bytes(bytes: Vec<u8>) -> Result<Self, P2POpaqueError> {
        let res: Result<Self, _> = serde_json::from_slice(&bytes);
        if let Err(e) = res {
            return Err(P2POpaqueError::SerializationError(
                "JSON deserialization of polynomial failed: ".to_string() + &e.to_string(),
            ));
        }
        Ok(res.unwrap())
    }
    fn at(&self, i: usize) -> Scalar {
        let i_scalar = usize_to_scalar(i);
        let mut value = Scalar::ZERO;
        for index in 0..self.coeffs.len() {
            value = value * i_scalar + self.coeffs[index];
        }
        value
    }
}

struct ACSS {}

struct ACSSInputs {
    h_point: RistrettoPoint,
    degree: usize,
    committee: HashMap<String, RistrettoPoint>,
    peer_public_keys: HashMap<String, PublicKey>,
}

struct ACSSShare {
    index: usize,
    nonce: [u8; 12],
    v_i: Vec<u8>,
    v_hat_i: Vec<u8>,
    c_i: RistrettoPoint,
    proof: ZKP,
}

impl ACSS {
    fn share(
        inputs: ACSSInputs,
        secret: Scalar,
        degree: usize,
    ) -> Result<HashMap<String, ACSSShare>, P2POpaqueError> {
        let mut shares = HashMap::new();
        let phi = Polynomial::new_w_secret(degree, secret);
        let phi_hat = Polynomial::new(degree);

        let phi_bytes = phi.clone().to_bytes();
        if let Err(e) = phi_bytes {
            return Err(e);
        }
        let phi_bytes = phi_bytes.unwrap();
        let phi_hat_bytes = phi_hat.clone().to_bytes();
        if let Err(e) = phi_hat_bytes {
            return Err(e);
        }
        let phi_hat_bytes = phi_hat_bytes.unwrap();

        for (i, (peer_id, public_key)) in inputs.peer_public_keys.iter().enumerate() {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(public_key));
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let v_i = cipher.encrypt(nonce, phi_bytes.as_slice());
            if let Err(e) = v_i {
                return Err(P2POpaqueError::CryptoError(
                    "Encryption failed".to_string() + &e.to_string(),
                ));
            }
            let v_i = v_i.unwrap();

            let v_hat_i = cipher.encrypt(nonce, phi_hat_bytes.as_slice());
            if let Err(e) = v_hat_i {
                return Err(P2POpaqueError::CryptoError(
                    "Encryption failed".to_string() + &e.to_string(),
                ));
            }
            let v_hat_i = v_hat_i.unwrap();

            let c_i = phi.at(i) * RISTRETTO_BASEPOINT_POINT + phi_hat.at(i) * inputs.h_point;
            let proof = ZKP::new(phi_hat.at(i), phi_hat.at(i), inputs.h_point, c_i);

            shares.insert(
                peer_id.clone(),
                ACSSShare {
                    index: i,
                    nonce: nonce_bytes,
                    v_i,
                    v_hat_i,
                    c_i,
                    proof,
                },
            );
        }

        Ok(shares)
    }
}
