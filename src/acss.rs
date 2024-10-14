use std::collections::{HashMap, HashSet};

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar, RistrettoPoint};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{keypair::PublicKey, P2POpaqueError};

#[derive(Serialize, Deserialize, Clone)]
struct Polynomial {
    coeffs: Vec<Scalar>,
}

fn usize_to_scalar(i: usize) -> Scalar {
    let mut i_bytes = [0u8; 32];
    i_bytes[..8].copy_from_slice(&i.to_le_bytes());
    Scalar::from_bytes_mod_order(i_bytes);
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
}

impl ACSS {
    fn share(
        inputs: ACSSInputs,
        secret: Scalar,
        degree: usize,
    ) -> Result<HashMap<String, ACSSShare>, P2POpaqueError> {
        let shares = HashMap::new();
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
            let v_hat_i = cipher.encrypt(nonce, phi_hat_bytes.as_slice());

            let c_i = phi.at(i) * RISTRETTO_BASEPOINT_POINT + phi_hat.at(i) * inputs.h_point;
        }
        Ok(shares)
    }
}
