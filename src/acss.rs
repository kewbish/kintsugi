use std::collections::{HashMap, HashSet};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::CompressedRistretto, scalar::Scalar,
    RistrettoPoint,
};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::{
    keypair::{Keypair, PrivateKey, PublicKey},
    polynomial::Polynomial,
    zkp::ZKP,
    P2POpaqueError,
};

struct ACSS {}

#[derive(Clone)]
struct ACSSInputs {
    h_point: RistrettoPoint,
    degree: usize,
    peer_public_keys: HashMap<String, PublicKey>,
}

#[derive(Clone)]
struct ACSSDealerShare {
    index: usize,
    nonce: [u8; 12],
    v_i: Vec<u8>,
    v_hat_i: Vec<u8>,
    c_i: RistrettoPoint,
    proof: ZKP,
}

#[derive(Clone)]
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
        dealer_key: PrivateKey,
    ) -> Result<HashMap<String, ACSSDealerShare>, P2POpaqueError> {
        let mut shares = HashMap::new();
        let phi = Polynomial::new_w_secret(degree, secret);
        let phi_hat = Polynomial::new(degree);

        for (i, (peer_id, public_key)) in inputs.peer_public_keys.iter().enumerate() {
            let dealer_private_key_scalar = Scalar::from_bytes_mod_order(dealer_key);
            let peer_public_key_point = CompressedRistretto::from_slice(public_key);
            if let Err(e) = peer_public_key_point {
                return Err(P2POpaqueError::SerializationError(
                    "Error deserializing public key".to_string(),
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

            let c_i = phi.at(i) * RISTRETTO_BASEPOINT_POINT + phi_hat.at(i) * inputs.h_point;
            let proof = ZKP::new(phi.at(i), phi_hat.at(i), inputs.h_point, c_i);

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
        dealer_key: PublicKey,
    ) -> Result<ACSSNodeShare, P2POpaqueError> {
        if !share.proof.verify(inputs.h_point, share.c_i) {
            return Err(P2POpaqueError::CryptoError(
                "ZKP was not accepted".to_string(),
            ));
        }

        let private_key_scalar = Scalar::from_bytes_mod_order(keypair.private_key);
        let dealer_public_key_point = CompressedRistretto::from_slice(&dealer_key);
        if let Err(e) = dealer_public_key_point {
            return Err(P2POpaqueError::SerializationError(
                "Error deserializing public key".to_string(),
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

        let c_i = s_i_d * RISTRETTO_BASEPOINT_POINT + s_hat_i_d * inputs.h_point;

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
