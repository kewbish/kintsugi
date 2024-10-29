use crate::keypair::{Keypair, PublicKey};
use crate::signature::Signature;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use derive_more::Display;
use rand::rngs::OsRng;
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use voprf::{BlindedElement, EvaluationElement, OprfClient, OprfServer};

type CS = voprf::Ristretto255;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Display)]
pub enum P2POpaqueError {
    RegistrationError,
    CryptoError(String),
    SerializationError(String),
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
    pub(crate) oprf_client: Option<OprfClient<CS>>,
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
    pub(crate) blinded_pwd: BlindedElement<CS>,
    pub(crate) peer_public_key: PublicKey,
    pub(crate) peer_id: String,
}

impl P2POpaqueNode {
    pub fn local_registration_start(
        &mut self,
        password: String,
    ) -> Result<RegStartRequest, P2POpaqueError> {
        let mut rng = OsRng;
        let password_blind_result = OprfClient::<CS>::blind(password.as_bytes(), &mut rng);
        if let Err(e) = password_blind_result {
            return Err(P2POpaqueError::CryptoError(
                "OPRF client blinding failed: ".to_string() + &e.to_string(),
            ));
        }
        let password_blind_ok = password_blind_result.unwrap();
        self.oprf_client = Some(password_blind_ok.state);
        Ok(RegStartRequest {
            blinded_pwd: password_blind_ok.message,
            peer_public_key: self.keypair.public_key,
            peer_id: self.id.clone(),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct RegStartResponse {
    pub(crate) rwd: EvaluationElement<CS>,
    pub(crate) peer_public_key: PublicKey,
    pub(crate) peer_id: String,
}

impl P2POpaqueNode {
    pub fn peer_registration_start(
        &mut self,
        peer_req: RegStartRequest,
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
        let server = OprfServer::<CS>::new_with_key(&opaque_keypair.private_key);
        if let Err(e) = server {
            return Err(P2POpaqueError::CryptoError(
                "OPRF server creation failed: ".to_string() + &e.to_string(),
            ));
        }
        let password_blind_eval = server.unwrap().blind_evaluate(&peer_req.blinded_pwd);
        Ok(RegStartResponse {
            rwd: password_blind_eval,
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

#[derive(serde::Serialize, serde::Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct Envelope {
    pub(crate) keypair: Keypair,
    pub(crate) peer_public_key: PublicKey,
    pub(crate) peer_id: String,
}

impl Envelope {
    pub fn encrypt_w_password(self, password: String) -> Result<EncryptedEnvelope, P2POpaqueError> {
        let mut hasher = Sha3_256::new();
        hasher.update(password.as_bytes());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = serde_json::to_string(&self);
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

        Ok(EncryptedEnvelope {
            public_key: None,
            encrypted_envelope: ciphertext,
            nonce: nonce_bytes,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct EncryptedEnvelope {
    pub(crate) public_key: Option<PublicKey>,
    pub(crate) encrypted_envelope: Vec<u8>,
    pub(crate) nonce: [u8; 12],
}

impl EncryptedEnvelope {
    pub fn decrypt_w_password(self, password: String) -> Result<Envelope, P2POpaqueError> {
        let mut hasher = Sha3_256::new();
        hasher.update(password.as_bytes());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&self.nonce);
        let plaintext_bytes = cipher.decrypt(nonce, self.encrypted_envelope.as_ref());
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
        Ok(plaintext.unwrap())
    }
}

impl P2POpaqueNode {
    pub fn local_registration_finish(
        &mut self,
        password: String,
        peer_resp: RegStartResponse,
    ) -> Result<RegFinishRequest, P2POpaqueError> {
        if let None = self.oprf_client {
            return Err(P2POpaqueError::CryptoError(
                "OPRF client not initialized".to_string(),
            ));
        }
        let oprf_client = self.oprf_client.as_ref().unwrap();
        let unblinded_rwd = oprf_client.finalize(&password.as_bytes(), &peer_resp.rwd);
        if let Err(e) = unblinded_rwd {
            return Err(P2POpaqueError::CryptoError(
                "Unblinding failed: ".to_string() + &e.to_string(),
            ));
        }
        let unblinded_rwd = unblinded_rwd.unwrap();
        let mut hasher = Sha3_256::new();
        hasher.update(unblinded_rwd.as_slice());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let envelope = Envelope {
            keypair: self.keypair.clone(),
            peer_public_key: peer_resp.peer_public_key,
            peer_id: peer_resp.peer_id,
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

        Ok(RegFinishRequest {
            peer_id: self.id.clone(),
            peer_public_key: self.keypair.public_key,
            encrypted_envelope: ciphertext,
            nonce: nonce_bytes,
            signature,
        })
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
    pub(crate) blinded_pwd: BlindedElement<CS>,
    pub(crate) peer_id: String,
}

impl P2POpaqueNode {
    pub fn local_login_start(
        &mut self,
        password: String,
    ) -> Result<LoginStartRequest, P2POpaqueError> {
        let mut rng = OsRng;
        let password_blind_result = OprfClient::<CS>::blind(password.as_bytes(), &mut rng);
        if let Err(e) = password_blind_result {
            return Err(P2POpaqueError::CryptoError(
                "OPRF client blinding failed: ".to_string() + &e.to_string(),
            ));
        }
        let password_blind_ok = password_blind_result.unwrap();
        self.oprf_client = Some(password_blind_ok.state);
        Ok(LoginStartRequest {
            blinded_pwd: password_blind_ok.message,
            peer_id: self.id.clone(),
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct LoginStartResponse {
    pub(crate) rwd: EvaluationElement<CS>,
    pub(crate) envelope: EncryptedEnvelope,
    pub(crate) peer_public_key: PublicKey,
    pub(crate) peer_id: String,
}

impl P2POpaqueNode {
    pub fn peer_login_start(
        &self,
        peer_req: LoginStartRequest,
    ) -> Result<LoginStartResponse, P2POpaqueError> {
        let local_opaque_keypair = self.peer_opaque_keys.get(&peer_req.peer_id);
        if let None = local_opaque_keypair {
            return Err(P2POpaqueError::RegistrationError);
        }
        let envelope = self.envelopes.get(&peer_req.peer_id);
        if let None = envelope {
            return Err(P2POpaqueError::RegistrationError);
        }
        let server = OprfServer::<CS>::new_with_key(&local_opaque_keypair.unwrap().private_key);
        if let Err(e) = server {
            return Err(P2POpaqueError::CryptoError(
                "OPRF server creation failed: ".to_string() + &e.to_string(),
            ));
        }
        let password_blind_eval = server.unwrap().blind_evaluate(&peer_req.blinded_pwd);
        Ok(LoginStartResponse {
            rwd: password_blind_eval,
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
        peer_resp: LoginStartResponse,
    ) -> Result<Keypair, P2POpaqueError> {
        if let None = self.oprf_client {
            return Err(P2POpaqueError::CryptoError(
                "OPRF client not initialized".to_string(),
            ));
        }
        let oprf_client = self.oprf_client.as_ref().unwrap();
        let unblinded_rwd = oprf_client.finalize(&password.as_bytes(), &peer_resp.rwd);
        if let Err(e) = unblinded_rwd {
            return Err(P2POpaqueError::CryptoError(
                "Unblinding failed: ".to_string() + &e.to_string(),
            ));
        }
        let unblinded_rwd = unblinded_rwd.unwrap();
        let mut hasher = Sha3_256::new();
        hasher.update(unblinded_rwd.as_slice());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce_bytes = peer_resp.envelope.nonce;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext_bytes = cipher.decrypt(nonce, peer_resp.envelope.encrypted_envelope.as_ref());
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
        Ok(plaintext.keypair)
    }
}

#[cfg(test)]
#[path = "opaque_tests.rs"]
mod local_encdec_test;

#[cfg(test)]
#[path = "opaque_tests.rs"]
mod opaque_test;
