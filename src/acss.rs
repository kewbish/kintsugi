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

use crate::{
    keypair::{Keypair, PublicKey},
    P2POpaqueError,
};

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

    fn verify(&self, h_point: RistrettoPoint, commitment: RistrettoPoint) -> bool {
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

struct ACSSDealerShare {
    index: usize,
    nonce: [u8; 12],
    v_i: Vec<u8>,
    v_hat_i: Vec<u8>,
    c_i: RistrettoPoint,
    proof: ZKP,
}

struct ACSSNodeShare {
    s_i_d: Scalar,
    s_hat_i_d: Scalar,
    c_i: RistrettoPoint,
}

impl ACSS {
    fn share_dealer(
        inputs: ACSSInputs,
        secret: Scalar,
        degree: usize,
    ) -> Result<HashMap<String, ACSSDealerShare>, P2POpaqueError> {
        let mut shares = HashMap::new();
        let phi = Polynomial::new_w_secret(degree, secret);
        let phi_hat = Polynomial::new(degree);

        for (i, (peer_id, public_key)) in inputs.peer_public_keys.iter().enumerate() {
            let cipher = ChaCha20Poly1305::new(Key::from_slice(public_key));
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let v_i = cipher.encrypt(nonce, phi.at(i).to_bytes().as_slice());
            if let Err(e) = v_i {
                return Err(P2POpaqueError::CryptoError(
                    "Encryption failed".to_string() + &e.to_string(),
                ));
            }
            let v_i = v_i.unwrap();

            let v_hat_i = cipher.encrypt(nonce, phi_hat.at(i).to_bytes().as_slice());
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
                ACSSDealerShare {
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

    fn share(
        inputs: ACSSInputs,
        share: ACSSDealerShare,
        keypair: Keypair,
    ) -> Result<ACSSNodeShare, P2POpaqueError> {
        if !share.proof.verify(inputs.h_point, share.c_i) {
            return Err(P2POpaqueError::CryptoError(
                "ZKP was not accepted".to_string(),
            ));
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&keypair.private_key));
        let nonce_bytes = share.nonce;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let s_i_d_bytes = cipher.decrypt(nonce, share.v_i.as_ref());
        if let Err(e) = s_i_d_bytes {
            return Err(P2POpaqueError::CryptoError(
                "Decryption failed: ".to_string() + &e.to_string(),
            ));
        }
        let s_i_d_bytes = s_i_d_bytes.unwrap();
        let s_i_d_bytes: Result<[u8; 32], _> = s_i_d_bytes.try_into();
        if let Err(_) = s_i_d_bytes {
            return Err(P2POpaqueError::SerializationError(
                "Deserialization failed: ".to_string(),
            ));
        }
        let s_i_d_bytes = s_i_d_bytes.unwrap();
        let s_i_d = Scalar::from_bytes_mod_order(s_i_d_bytes);

        let s_hat_i_d_bytes = cipher.decrypt(nonce, share.v_hat_i.as_ref());
        if let Err(e) = s_hat_i_d_bytes {
            return Err(P2POpaqueError::CryptoError(
                "Decryption failed: ".to_string() + &e.to_string(),
            ));
        }
        let s_hat_i_d_bytes = s_hat_i_d_bytes.unwrap();
        let s_hat_i_d_bytes: Result<[u8; 32], _> = s_hat_i_d_bytes.try_into();
        if let Err(_) = s_hat_i_d_bytes {
            return Err(P2POpaqueError::SerializationError(
                "Deserialization failed: ".to_string(),
            ));
        }
        let s_hat_i_d_bytes = s_hat_i_d_bytes.unwrap();
        let s_hat_i_d = Scalar::from_bytes_mod_order(s_hat_i_d_bytes);

        let c_i = s_i_d * RISTRETTO_BASEPOINT_POINT + s_hat_i_d * inputs.h_point;

        Ok(ACSSNodeShare {
            s_i_d,
            s_hat_i_d,
            c_i,
        })
    }
}
