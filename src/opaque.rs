use crate::keypair::{Keypair, PublicKey};
use crate::oprf::{OPRFClient, OPRFServer};
use crate::polynomial::get_lagrange_coefficient;
use crate::signature::Signature;
use crate::util::i32_to_scalar;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{RistrettoPoint, Scalar};
use derive_more::Display;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_with::{serde_as, Bytes};
use sha3::{Digest, Sha3_256, Sha3_256Core, Sha3_512};
use std::collections::{HashMap, HashSet};
use voprf::{BlindedElement, EvaluationElement, OprfClient, OprfServer};

type CS = voprf::Ristretto255;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Display)]
pub enum P2POpaqueError {
    RegistrationError,
    CryptoError(String),
    SerializationError(String),
    FileError(String),
}

impl std::error::Error for P2POpaqueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct P2POpaqueNode {
    pub(crate) id: String,
    pub(crate) keypair: Keypair,
    pub(crate) peer_opaque_keys: HashMap<String, Keypair>,
    pub(crate) peer_attempted_public_keys: HashMap<String, PublicKey>,
    pub(crate) envelopes: HashMap<String, EncryptedEnvelope>,
    pub(crate) oprf_client: Option<OPRFClient>,
}

impl P2POpaqueNode {
    pub fn new(id: String) -> Self {
        P2POpaqueNode {
            id,
            keypair: Keypair::new(),
            peer_opaque_keys: HashMap::new(),
            peer_attempted_public_keys: HashMap::new(),
            envelopes: HashMap::new(),
            oprf_client: None,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct RegStartRequest {
    pub(crate) blinded_pwd: RistrettoPoint,
    pub(crate) peer_public_key: PublicKey,
    pub(crate) peer_id: String,
}

impl P2POpaqueNode {
    pub fn local_registration_start(
        &mut self,
        password: String,
    ) -> Result<RegStartRequest, P2POpaqueError> {
        let password_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(password.as_bytes());
        let (password_blind_result, state) = OPRFClient::blind(password_point);
        self.oprf_client = Some(state);
        Ok(RegStartRequest {
            blinded_pwd: password_blind_result,
            peer_public_key: self.keypair.public_key,
            peer_id: self.id.clone(),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct RegStartResponse {
    pub(crate) rwd: RistrettoPoint,
    pub(crate) index: i32,
    pub(crate) peer_public_key: PublicKey,
    pub(crate) peer_id: String,
}

impl P2POpaqueNode {
    pub fn peer_registration_start(
        &mut self,
        peer_req: RegStartRequest,
        index: i32,
        other_indices: HashSet<i32>,
    ) -> Result<RegStartResponse, P2POpaqueError> {
        let opaque_keypair = Keypair::new();
        self.peer_opaque_keys
            .insert(peer_req.peer_id.clone(), opaque_keypair.clone());
        if self
            .peer_attempted_public_keys
            .contains_key(&peer_req.peer_id)
        {
            return Err(P2POpaqueError::RegistrationError);
        }
        self.peer_attempted_public_keys
            .insert(peer_req.peer_id, peer_req.peer_public_key);
        let private_key = Scalar::from_canonical_bytes(opaque_keypair.private_key).into_option();
        if let None = private_key {
            return Err(P2POpaqueError::CryptoError(
                "Could not deserialize private key".to_string(),
            ));
        }
        let password_blind_eval = OPRFServer::blind_evaluate(
            peer_req.blinded_pwd,
            private_key.unwrap(),
            i32_to_scalar(index),
            other_indices
                .iter()
                .map(|i| i32_to_scalar(i.clone()))
                .collect(),
        );
        Ok(RegStartResponse {
            rwd: password_blind_eval,
            index,
            peer_public_key: self.keypair.public_key,
            peer_id: self.id.clone(),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct RegFinishRequest {
    pub(crate) peer_public_key: PublicKey,
    pub(crate) peer_id: String,
    pub(crate) nonce: [u8; 12],
    pub(crate) encrypted_envelope: Vec<u8>,
    pub(crate) signature: Signature,
}

#[serde_as]
#[derive(serde::Serialize, serde::Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct Envelope {
    pub(crate) keypair: Keypair,
    #[serde_as(as = "Bytes")]
    pub(crate) libp2p_keypair_bytes: [u8; 64],
    pub(crate) peer_public_key: PublicKey,
    pub(crate) peer_id: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct EncryptedEnvelope {
    pub(crate) public_key: Option<PublicKey>,
    pub(crate) encrypted_envelope: Vec<u8>,
    pub(crate) nonce: [u8; 12],
}

impl P2POpaqueNode {
    pub fn local_registration_finish(
        &mut self,
        password: String,
        libp2p_keypair_bytes: [u8; 64],
        peer_resp: Vec<RegStartResponse>,
    ) -> Result<Vec<RegFinishRequest>, P2POpaqueError> {
        if let None = self.oprf_client {
            return Err(P2POpaqueError::CryptoError(
                "OPRF client not initialized".to_string(),
            ));
        }
        let all_indices: HashSet<Scalar> = peer_resp
            .iter()
            .map(|resp| i32_to_scalar(resp.index.clone()))
            .collect();
        let combined_rwd = peer_resp
            .iter()
            .map(|resp| {
                get_lagrange_coefficient(i32_to_scalar(resp.index.clone()), all_indices.clone())
                    * resp.rwd
            })
            .sum();
        let oprf_client = self.oprf_client.as_ref().unwrap();
        let unblinded_rwd = oprf_client.unblind(combined_rwd);
        if let Err(e) = unblinded_rwd {
            return Err(P2POpaqueError::CryptoError(
                "Unblinding failed: ".to_string() + &e.to_string(),
            ));
        }
        let mut hasher = Sha3_256::new();
        hasher.update(unblinded_rwd.unwrap().compress().to_bytes());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut result = Vec::new();
        for peer_resp in peer_resp.iter() {
            let envelope = Envelope {
                keypair: self.keypair.clone(),
                libp2p_keypair_bytes,
                peer_public_key: peer_resp.peer_public_key,
                peer_id: peer_resp.peer_id.clone(),
            };
            let plaintext = serde_json::to_string(&envelope);
            if let Err(e) = plaintext {
                return Err(P2POpaqueError::SerializationError(
                    "JSON serialization of envelope failed: ".to_string() + &e.to_string(),
                ));
            }
            let ciphertext = cipher.encrypt(nonce, plaintext.unwrap().as_bytes());
            if let Err(e) = ciphertext {
                return Err(P2POpaqueError::CryptoError(
                    "Encryption of envelope failed: ".to_string() + &e.to_string(),
                ));
            }
            let ciphertext = ciphertext.unwrap();
            let signature = Signature::new_with_keypair(&ciphertext, self.keypair.clone());

            result.push(RegFinishRequest {
                peer_id: self.id.clone(),
                peer_public_key: self.keypair.public_key,
                encrypted_envelope: ciphertext,
                nonce: nonce_bytes,
                signature,
            })
        }

        Ok(result)
    }
}

impl P2POpaqueNode {
    pub fn peer_registration_finish(
        &mut self,
        peer_req: RegFinishRequest,
    ) -> Result<(), P2POpaqueError> {
        let peer_public_key = self.peer_attempted_public_keys.get(&peer_req.peer_id);
        if let None = peer_public_key {
            // don't leak that a registration attempt was not started
            return Ok(());
        }
        if !peer_req.signature.verify(
            &peer_req.encrypted_envelope,
            peer_public_key.unwrap().clone(),
        ) {
            return Err(P2POpaqueError::CryptoError(
                "Could not verify signature of registration request".to_string(),
            ));
        }
        self.envelopes.insert(
            peer_req.peer_id,
            EncryptedEnvelope {
                public_key: Some(peer_req.peer_public_key),
                encrypted_envelope: peer_req.encrypted_envelope,
                nonce: peer_req.nonce,
            },
        );
        return Ok(());
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct LoginStartRequest {
    pub(crate) blinded_pwd: RistrettoPoint,
    pub(crate) peer_id: String,
}

impl P2POpaqueNode {
    pub fn local_login_start(
        &mut self,
        password: String,
    ) -> Result<LoginStartRequest, P2POpaqueError> {
        let password_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(password.as_bytes());
        let (password_blind_result, state) = OPRFClient::blind(password_point);
        self.oprf_client = Some(state);
        Ok(LoginStartRequest {
            blinded_pwd: password_blind_result,
            peer_id: self.id.clone(),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct LoginStartResponse {
    pub(crate) rwd: RistrettoPoint,
    pub(crate) index: i32,
    pub(crate) envelope: EncryptedEnvelope,
    pub(crate) peer_public_key: PublicKey,
    pub(crate) peer_id: String,
}

impl P2POpaqueNode {
    pub fn peer_login_start(
        &self,
        peer_req: LoginStartRequest,
        index: i32,
        other_indices: HashSet<i32>,
    ) -> Result<LoginStartResponse, P2POpaqueError> {
        let local_opaque_keypair = self.peer_opaque_keys.get(&peer_req.peer_id);
        if let None = local_opaque_keypair {
            return Err(P2POpaqueError::RegistrationError);
        }
        let envelope = self.envelopes.get(&peer_req.peer_id);
        if let None = envelope {
            return Err(P2POpaqueError::RegistrationError);
        }
        let private_key =
            Scalar::from_canonical_bytes(local_opaque_keypair.unwrap().private_key).into_option();
        let password_blind_eval = OPRFServer::blind_evaluate(
            peer_req.blinded_pwd,
            private_key.unwrap(),
            i32_to_scalar(index),
            other_indices
                .iter()
                .map(|i| i32_to_scalar(i.clone()))
                .collect(),
        );
        Ok(LoginStartResponse {
            rwd: password_blind_eval,
            index,
            envelope: envelope.unwrap().clone(),
            peer_public_key: self.keypair.public_key,
            peer_id: self.id.clone(),
        })
    }
}

impl P2POpaqueNode {
    pub fn local_login_finish(
        &self,
        password: String,
        libp2p_keypair_bytes: [u8; 64],
        peer_resp: Vec<LoginStartResponse>,
    ) -> Result<(Keypair, [u8; 64]), P2POpaqueError> {
        if let None = self.oprf_client {
            return Err(P2POpaqueError::CryptoError(
                "OPRF client not initialized".to_string(),
            ));
        }
        let all_indices: HashSet<Scalar> = peer_resp
            .iter()
            .map(|resp| i32_to_scalar(resp.index.clone()))
            .collect();
        let combined_rwd = peer_resp
            .iter()
            .map(|resp| {
                get_lagrange_coefficient(i32_to_scalar(resp.index.clone()), all_indices.clone())
                    * resp.rwd
            })
            .sum();
        let oprf_client = self.oprf_client.as_ref().unwrap();
        let unblinded_rwd = oprf_client.unblind(combined_rwd);
        if let Err(e) = unblinded_rwd {
            return Err(P2POpaqueError::CryptoError(
                "Unblinding failed: ".to_string() + &e.to_string(),
            ));
        }
        let unblinded_rwd = unblinded_rwd.unwrap();
        let mut hasher = Sha3_256::new();
        hasher.update(unblinded_rwd.compress().to_bytes());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce_bytes = peer_resp[0].envelope.nonce;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext_bytes =
            cipher.decrypt(nonce, peer_resp[0].envelope.encrypted_envelope.as_ref());
        if let Err(e) = plaintext_bytes {
            return Err(P2POpaqueError::CryptoError(
                "Decryption failed: ".to_string() + &e.to_string(),
            ));
        }
        let plaintext_bytes = plaintext_bytes.unwrap();
        let plaintext: Result<Envelope, _> = serde_json::from_slice(&plaintext_bytes);
        if let Err(e) = plaintext {
            return Err(P2POpaqueError::SerializationError(
                "Deserialization failed: ".to_string() + &e.to_string(),
            ));
        }
        let plaintext = plaintext.unwrap();
        Ok((plaintext.keypair, plaintext.libp2p_keypair_bytes))
    }
}

#[cfg(test)]
#[path = "opaque_tests.rs"]
mod opaque_test;
