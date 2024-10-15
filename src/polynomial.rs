use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar, RistrettoPoint};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::P2POpaqueError;

#[derive(Serialize, Deserialize, Clone)]
pub struct Polynomial {
    pub(crate) coeffs: Vec<Scalar>,
}

fn usize_to_scalar(i: usize) -> Scalar {
    let mut i_bytes = [0u8; 32];
    i_bytes[..8].copy_from_slice(&i.to_le_bytes());
    Scalar::from_bytes_mod_order(i_bytes)
}

impl Polynomial {
    pub fn new(degree: usize) -> Self {
        let mut polynomial = Vec::with_capacity(degree + 1);
        for i in 0..(degree + 1) {
            polynomial[i] = Scalar::random(&mut OsRng)
        }
        Polynomial { coeffs: polynomial }
    }
    pub fn new_w_secret(degree: usize, secret: Scalar) -> Self {
        let mut polynomial = Polynomial::new(degree);
        polynomial.coeffs[0] = secret;
        polynomial
    }
    pub fn to_bytes(self) -> Result<Vec<u8>, P2POpaqueError> {
        let string_res = serde_json::to_string(&self);
        if let Err(e) = string_res {
            return Err(P2POpaqueError::SerializationError(
                "JSON serialization of polynomial failed: ".to_string() + &e.to_string(),
            ));
        }
        Ok(string_res.unwrap().into_bytes())
    }
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, P2POpaqueError> {
        let res: Result<Self, _> = serde_json::from_slice(&bytes);
        if let Err(e) = res {
            return Err(P2POpaqueError::SerializationError(
                "JSON deserialization of polynomial failed: ".to_string() + &e.to_string(),
            ));
        }
        Ok(res.unwrap())
    }
    pub fn at(&self, i: usize) -> Scalar {
        let i_scalar = usize_to_scalar(i);
        let mut value = Scalar::ZERO;
        for index in 0..self.coeffs.len() {
            value = value * i_scalar + self.coeffs[index];
        }
        value
    }
}
