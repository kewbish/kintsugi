use crate::keypair::{Keypair, PublicKey};
use crate::opaque::P2POpaqueError;

#[allow(unused_imports)]
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use sha3::{Digest, Sha3_256};

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct LocalEnvelope {
    pub(crate) keypair: Keypair,
    #[serde_as(as = "Bytes")]
    pub(crate) libp2p_keypair_bytes: [u8; 64],
    pub(crate) peer_public_key: PublicKey,
    pub(crate) peer_id: String,
    pub(crate) username: String,
}

impl LocalEnvelope {
    pub fn encrypt_w_password(
        self,
        password: String,
    ) -> Result<LocalEncryptedEnvelope, P2POpaqueError> {
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

        Ok(LocalEncryptedEnvelope {
            encrypted_envelope: ciphertext,
            nonce: nonce_bytes,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct LocalEncryptedEnvelope {
    pub(crate) encrypted_envelope: Vec<u8>,
    pub(crate) nonce: [u8; 12],
}

impl LocalEncryptedEnvelope {
    pub fn decrypt_w_password(self, password: String) -> Result<LocalEnvelope, P2POpaqueError> {
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
        let plaintext: Result<LocalEnvelope, _> = serde_json::from_slice(&plaintext_bytes);
        if let Err(e) = plaintext {
            return Err(P2POpaqueError::SerializationError(
                "Deserialization failed: ".to_string() + &e.to_string(),
            ));
        }
        Ok(plaintext.unwrap())
    }
}

#[cfg(test)]
#[path = "local_envelope_tests.rs"]
mod local_encdec_test;
