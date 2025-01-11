use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::opaque::P2POpaqueError;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OPRFClient {
    current_blinding_scalar: Option<Scalar>,
}

impl OPRFClient {
    pub fn blind(point: RistrettoPoint) -> (RistrettoPoint, Self) {
        let blinding_scalar = Scalar::random(&mut OsRng);
        return (
            blinding_scalar * point,
            OPRFClient {
                current_blinding_scalar: Some(blinding_scalar),
            },
        );
    }
    pub fn unblind(&self, point: RistrettoPoint) -> Result<RistrettoPoint, P2POpaqueError> {
        if let None = self.current_blinding_scalar {
            return Err(P2POpaqueError::CryptoError(
                "Blinding scalar not saved in OPRF client".to_string(),
            ));
        }

        Ok(self.current_blinding_scalar.unwrap().invert() * point)
    }
}

pub struct OPRFServer {}

impl OPRFServer {
    pub fn blind_evaluate(point: RistrettoPoint, eval_secret_share: Scalar) -> RistrettoPoint {
        return eval_secret_share * point;
    }
}

#[cfg(test)]
#[path = "oprf_tests.rs"]
mod oprf_test;
