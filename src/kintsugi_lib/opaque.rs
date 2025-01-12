use crate::kintsugi_lib::error::KintsugiError;
use crate::kintsugi_lib::keypair::{Keypair, PublicKey};
use crate::kintsugi_lib::oprf::{OPRFClient, OPRFServer};
use crate::kintsugi_lib::polynomial;
use crate::kintsugi_lib::signature::Signature;
use crate::kintsugi_lib::util::i32_to_scalar;
#[allow(unused_imports)]
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::rngs::OsRng;
use rand::RngCore;
#[allow(unused_imports)]
use sha3::{Digest, Sha3_256, Sha3_256Core, Sha3_512};
use std::collections::{HashMap, HashSet};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct P2POpaqueNode {
    pub(crate) id: String,
    pub(crate) keypair: Keypair,
    pub(crate) peer_opaque_keys: HashMap<String, Keypair>,
    pub(crate) peer_attempted_public_keys: HashMap<String, PublicKey>,
    pub(crate) envelopes: HashMap<String, EncryptedEnvelope>,
    pub(crate) peer_oprf_clients: HashMap<String, OPRFClient>,
}

impl P2POpaqueNode {
    pub fn new(id: String) -> Self {
        P2POpaqueNode {
            id,
            keypair: Keypair::new(),
            peer_opaque_keys: HashMap::new(),
            peer_attempted_public_keys: HashMap::new(),
            peer_oprf_clients: HashMap::new(),
            envelopes: HashMap::new(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct RegStartRequest {
    pub(crate) blinded_pwd: RistrettoPoint,
    pub(crate) peer_public_key: PublicKey,
    pub(crate) user_username: String,
}

impl P2POpaqueNode {
    pub fn local_registration_start(
        &mut self,
        password: String,
        node_username: String,
    ) -> Result<RegStartRequest, KintsugiError> {
        let password_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(password.as_bytes());
        let (password_blind_result, state) = OPRFClient::blind(password_point);
        self.peer_oprf_clients.insert(node_username, state);
        Ok(RegStartRequest {
            blinded_pwd: password_blind_result,
            peer_public_key: self.keypair.public_key,
            user_username: self.id.clone(),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct RegStartResponse {
    pub(crate) rwd: RistrettoPoint,
    pub(crate) index: i32,
    pub(crate) peer_public_key: PublicKey,
    pub(crate) node_username: String,
}

impl P2POpaqueNode {
    pub fn peer_registration_start(
        &mut self,
        peer_req: RegStartRequest,
        s_i_d: Scalar,
        index: i32,
    ) -> Result<RegStartResponse, KintsugiError> {
        let opaque_keypair = Keypair::new();
        self.peer_opaque_keys
            .insert(peer_req.user_username.clone(), opaque_keypair.clone());
        if self
            .peer_attempted_public_keys
            .contains_key(&peer_req.user_username)
        {
            return Err(KintsugiError::RegistrationError);
        }
        self.peer_attempted_public_keys
            .insert(peer_req.user_username, peer_req.peer_public_key);
        let password_blind_eval = OPRFServer::blind_evaluate(peer_req.blinded_pwd, s_i_d);
        Ok(RegStartResponse {
            rwd: password_blind_eval,
            index,
            peer_public_key: self.keypair.public_key,
            node_username: self.id.clone(),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct RegFinishRequest {
    pub(crate) peer_public_key: PublicKey,
    pub(crate) user_username: String,
    pub(crate) node_username: String,
    pub(crate) nonce: [u8; 12],
    pub(crate) encrypted_envelope: Vec<u8>,
    pub(crate) signature: Signature,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct Envelope {
    pub(crate) keypair: Keypair,
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
        peer_resps: Vec<RegStartResponse>,
    ) -> Result<Vec<RegFinishRequest>, KintsugiError> {
        let mut combined_rwds = Vec::new();
        let other_indices: HashSet<Scalar> =
            peer_resps.iter().map(|v| i32_to_scalar(v.index)).collect();
        for peer_resp in peer_resps.iter() {
            let oprf_client = self.peer_oprf_clients.get(&peer_resp.node_username);
            if let None = oprf_client {
                return Err(KintsugiError::CryptoError(
                    "OPRF client not initialized".to_string(),
                ));
            }
            let oprf_client = oprf_client.unwrap();
            let unblinded_rwd = oprf_client.unblind(peer_resp.rwd);
            if let Err(e) = unblinded_rwd {
                return Err(KintsugiError::CryptoError(
                    "Unblinding failed: ".to_string() + &e.to_string(),
                ));
            }
            let lagrange_coeff = polynomial::get_lagrange_coefficient(
                i32_to_scalar(peer_resp.index),
                other_indices.clone(),
            );
            combined_rwds.push(lagrange_coeff * unblinded_rwd.unwrap());
        }
        let combined_rwd: RistrettoPoint = combined_rwds.iter().sum();

        let mut hasher = Sha3_256::new();
        hasher.update(combined_rwd.compress().to_bytes());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut result = Vec::new();
        let envelope = Envelope {
            keypair: self.keypair.clone(),
        };
        let plaintext = serde_json::to_string(&envelope);
        if let Err(e) = plaintext {
            return Err(KintsugiError::SerializationError(
                "JSON serialization of envelope failed: ".to_string() + &e.to_string(),
            ));
        }
        let ciphertext = cipher.encrypt(nonce, plaintext.unwrap().as_bytes());
        if let Err(e) = ciphertext {
            return Err(KintsugiError::CryptoError(
                "Encryption of envelope failed: ".to_string() + &e.to_string(),
            ));
        }
        let ciphertext = ciphertext.unwrap();
        let signature = Signature::new_with_keypair(&ciphertext, self.keypair.clone());

        for peer_resp in peer_resps.iter() {
            result.push(RegFinishRequest {
                user_username: self.id.clone(),
                node_username: peer_resp.node_username.clone(),
                peer_public_key: self.keypair.public_key,
                encrypted_envelope: ciphertext.clone(),
                nonce: nonce_bytes,
                signature: signature.clone(),
            })
        }

        self.peer_oprf_clients = HashMap::new(); // clear OPRF clients

        Ok(result)
    }
}

impl P2POpaqueNode {
    pub fn peer_registration_finish(
        &mut self,
        peer_req: RegFinishRequest,
    ) -> Result<(), KintsugiError> {
        let peer_public_key = self.peer_attempted_public_keys.get(&peer_req.user_username);
        if let None = peer_public_key {
            // don't leak that a registration attempt was not started
            return Ok(());
        }
        if !peer_req.signature.verify(
            &peer_req.encrypted_envelope,
            peer_public_key.unwrap().clone(),
        ) {
            return Err(KintsugiError::CryptoError(
                "Could not verify signature of registration request".to_string(),
            ));
        }
        self.envelopes.insert(
            peer_req.user_username,
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
    pub(crate) user_username: String,
}

impl P2POpaqueNode {
    pub fn local_login_start(
        &mut self,
        password: String,
        node_username: String,
    ) -> Result<LoginStartRequest, KintsugiError> {
        let password_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(password.as_bytes());
        let (password_blind_result, state) = OPRFClient::blind(password_point);
        self.peer_oprf_clients.insert(node_username, state);
        Ok(LoginStartRequest {
            blinded_pwd: password_blind_result,
            user_username: self.id.clone(),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct LoginStartResponse {
    pub(crate) rwd: RistrettoPoint,
    pub(crate) index: i32,
    pub(crate) envelope: EncryptedEnvelope,
    pub(crate) peer_public_key: PublicKey,
    pub(crate) node_username: String,
}

impl P2POpaqueNode {
    pub fn peer_login_start(
        &self,
        peer_req: LoginStartRequest,
        s_i_d: Scalar,
        index: i32,
    ) -> Result<LoginStartResponse, KintsugiError> {
        let local_opaque_keypair = self.peer_opaque_keys.get(&peer_req.user_username);
        if let None = local_opaque_keypair {
            return Err(KintsugiError::RegistrationError);
        }
        let envelope = self.envelopes.get(&peer_req.user_username);
        if let None = envelope {
            return Err(KintsugiError::RegistrationError);
        }
        let password_blind_eval = OPRFServer::blind_evaluate(peer_req.blinded_pwd, s_i_d);
        Ok(LoginStartResponse {
            rwd: password_blind_eval,
            index,
            envelope: envelope.unwrap().clone(),
            peer_public_key: self.keypair.public_key,
            node_username: self.id.clone(),
        })
    }
}

impl P2POpaqueNode {
    pub fn local_login_finish(
        &mut self,
        peer_resps: Vec<LoginStartResponse>,
    ) -> Result<Keypair, KintsugiError> {
        let mut combined_rwds = Vec::new();
        let other_indices: HashSet<Scalar> =
            peer_resps.iter().map(|v| i32_to_scalar(v.index)).collect();
        for peer_resp in peer_resps.iter() {
            let oprf_client = self.peer_oprf_clients.get(&peer_resp.node_username);
            if let None = oprf_client {
                return Err(KintsugiError::CryptoError(
                    "OPRF client not initialized".to_string(),
                ));
            }
            let oprf_client = oprf_client.unwrap();
            let unblinded_rwd = oprf_client.unblind(peer_resp.rwd);
            if let Err(e) = unblinded_rwd {
                return Err(KintsugiError::CryptoError(
                    "Unblinding failed: ".to_string() + &e.to_string(),
                ));
            }
            let lagrange_coeff = polynomial::get_lagrange_coefficient(
                i32_to_scalar(peer_resp.index),
                other_indices.clone(),
            );
            combined_rwds.push(lagrange_coeff * unblinded_rwd.unwrap());
        }
        let combined_rwd: RistrettoPoint = combined_rwds.iter().sum();

        let mut hasher = Sha3_256::new();
        hasher.update(combined_rwd.compress().to_bytes());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce_bytes = peer_resps[0].envelope.nonce;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext_bytes =
            cipher.decrypt(nonce, peer_resps[0].envelope.encrypted_envelope.as_ref());
        if let Err(e) = plaintext_bytes {
            return Err(KintsugiError::CryptoError(
                "Decryption failed: ".to_string() + &e.to_string(),
            ));
        }
        let plaintext_bytes = plaintext_bytes.unwrap();
        let plaintext: Result<Envelope, _> = serde_json::from_slice(&plaintext_bytes);
        if let Err(e) = plaintext {
            return Err(KintsugiError::SerializationError(
                "Deserialization failed: ".to_string() + &e.to_string(),
            ));
        }

        self.peer_oprf_clients = HashMap::new(); // clear OPRF clients

        let plaintext = plaintext.unwrap();
        Ok(plaintext.keypair)
    }
}

#[cfg(test)]
#[path = "opaque_tests.rs"]
mod opaque_test;
