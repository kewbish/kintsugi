#[allow(unused_imports)]
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use voprf::{BlindedElement, EvaluationElement, OprfClient, OprfServer};

mod keypair;
use crate::keypair::{Keypair, PublicKey};

mod signature;
use crate::signature::Signature;

mod acss;
mod dpss;
mod polynomial;

type CS = voprf::Ristretto255;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum P2POpaqueError {
    RegistrationError,
    CryptoError(String),
    SerializationError(String),
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct P2POpaqueNode {
    id: String,
    keypair: Keypair,
    peer_opaque_keys: HashMap<String, Keypair>,
    peer_attempted_public_keys: HashMap<String, PublicKey>,
    envelopes: HashMap<String, EncryptedEnvelope>,
    oprf_client: Option<OprfClient<CS>>,
}

impl P2POpaqueNode {
    fn new(id: String) -> Self {
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
struct RegStartRequest {
    blinded_pwd: BlindedElement<CS>,
    peer_public_key: PublicKey,
    peer_id: String,
}

impl P2POpaqueNode {
    fn local_registration_start(
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
struct RegStartResponse {
    rwd: EvaluationElement<CS>,
    peer_public_key: PublicKey,
    peer_id: String,
}

impl P2POpaqueNode {
    fn peer_registration_start(
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
struct RegFinishRequest {
    peer_public_key: PublicKey,
    peer_id: String,
    nonce: [u8; 12],
    encrypted_envelope: Vec<u8>,
    signature: Signature,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct Envelope {
    keypair: Keypair,
    peer_public_key: PublicKey,
    peer_id: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct EncryptedEnvelope {
    public_key: PublicKey,
    encrypted_envelope: Vec<u8>,
    nonce: [u8; 12],
}

impl P2POpaqueNode {
    fn local_registration_finish(
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
    fn peer_registration_finish(
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
                public_key: peer_req.peer_public_key,
                encrypted_envelope: peer_req.encrypted_envelope,
                nonce: peer_req.nonce,
            },
        );
        return Ok(());
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct LoginStartRequest {
    blinded_pwd: BlindedElement<CS>,
    peer_id: String,
}

impl P2POpaqueNode {
    fn local_login_start(&mut self, password: String) -> Result<LoginStartRequest, P2POpaqueError> {
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
struct LoginStartResponse {
    rwd: EvaluationElement<CS>,
    envelope: EncryptedEnvelope,
    peer_public_key: PublicKey,
    peer_id: String,
}

impl P2POpaqueNode {
    fn peer_login_start(
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
    fn local_login_finish(
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
#[path = "main_tests.rs"]
mod test;

fn main() {}
