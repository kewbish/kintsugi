use std::collections::HashMap;

#[allow(unused_imports)]
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, scalar::Scalar,
    RistrettoPoint,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{
    keypair::{Keypair, PrivateKey, PublicKey},
    opaque::P2POpaqueError,
    polynomial::Polynomial,
    zkp::ZKP,
};

pub struct ACSS {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ACSSDealerShare {
    pub(crate) index: usize,
    pub(crate) nonce: [u8; 12],
    pub(crate) v_i: Vec<u8>,
    pub(crate) v_hat_i: Vec<u8>,
    pub(crate) c_i: RistrettoPoint,
    pub(crate) poly_c_i: Vec<RistrettoPoint>,
    pub(crate) proof: ZKP,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ACSSNodeShare {
    pub(crate) s_i_d: Scalar,
    pub(crate) s_hat_i_d: Scalar,
    pub(crate) c_i: RistrettoPoint,
}

impl ACSS {
    pub fn share_dealer(
        h_point: RistrettoPoint,
        secret: Scalar,
        degree: usize,
        dealer_key: PrivateKey,
        peer_public_keys: HashMap<String, PublicKey>,
        peer_indexes: HashMap<String, i32>,
    ) -> Result<(HashMap<String, ACSSDealerShare>, Polynomial, Polynomial), P2POpaqueError> {
        let mut shares = HashMap::new();
        let phi = Polynomial::new_w_secret(degree, secret);
        let phi_hat = Polynomial::new(degree);

        for (_, (peer_id, i)) in peer_indexes.iter().enumerate() {
            let i = i.clone() as usize;
            let public_key = peer_public_keys.get(peer_id).unwrap();
            let dealer_private_key_scalar = Scalar::from_bytes_mod_order(dealer_key);
            let peer_public_key_point = CompressedRistretto::from_slice(public_key);
            if let Err(e) = peer_public_key_point {
                return Err(P2POpaqueError::SerializationError(
                    "Error deserializing public key ".to_string() + &e.to_string(),
                ));
            }
            let peer_public_key_point = peer_public_key_point.unwrap().decompress();
            if let None = peer_public_key_point {
                return Err(P2POpaqueError::SerializationError(
                    "Error deserializing public key".to_string(),
                ));
            }
            let shared_secret = dealer_private_key_scalar * peer_public_key_point.unwrap();

            let cipher =
                ChaCha20Poly1305::new(Key::from_slice(&shared_secret.compress().to_bytes()));
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

            let c_i = phi.at(i) * RISTRETTO_BASEPOINT_POINT + phi_hat.at(i) * h_point;
            let poly_c_i = phi
                .coeffs
                .iter()
                .map(|c| RISTRETTO_BASEPOINT_POINT * c)
                .collect();
            let proof = ZKP::new(phi.at(i), phi_hat.at(i), h_point, c_i);

            shares.insert(
                peer_id.clone(),
                ACSSDealerShare {
                    index: i,
                    nonce: nonce_bytes,
                    v_i,
                    v_hat_i,
                    c_i,
                    poly_c_i,
                    proof,
                },
            );
        }

        Ok((shares, phi, phi_hat))
    }

    pub fn share(
        h_point: RistrettoPoint,
        share: ACSSDealerShare,
        keypair: Keypair,
        dealer_key: PublicKey,
    ) -> Result<ACSSNodeShare, P2POpaqueError> {
        if !share.proof.verify(h_point, share.c_i) {
            return Err(P2POpaqueError::CryptoError(
                "ZKP was not accepted".to_string(),
            ));
        }

        let private_key_scalar = Scalar::from_bytes_mod_order(keypair.private_key);
        let dealer_public_key_point = CompressedRistretto::from_slice(&dealer_key);
        if let Err(e) = dealer_public_key_point {
            return Err(P2POpaqueError::SerializationError(
                "Error deserializing public key ".to_string() + &e.to_string(),
            ));
        }
        let dealer_public_key_point = dealer_public_key_point.unwrap().decompress();
        if let None = dealer_public_key_point {
            return Err(P2POpaqueError::SerializationError(
                "Error deserializing public key".to_string(),
            ));
        }
        let shared_secret = private_key_scalar * dealer_public_key_point.unwrap();

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&shared_secret.compress().to_bytes()));
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

        let c_i = s_i_d * RISTRETTO_BASEPOINT_POINT + s_hat_i_d * h_point;

        Ok(ACSSNodeShare {
            s_i_d,
            s_hat_i_d,
            c_i,
        })
    }
}

#[cfg(test)]
#[path = "acss_tests.rs"]
mod acss_test;
