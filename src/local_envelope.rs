use crate::keypair::{Keypair, PublicKey};
use crate::opaque::P2POpaqueError;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::Deserializer;
use serde::{ser::SerializeStruct, Serialize, Serializer};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone)]
pub struct LocalEnvelope {
    pub(crate) keypair: Keypair,
    pub(crate) libp2p_keypair: libp2p::identity::ed25519::Keypair,
    pub(crate) peer_public_key: PublicKey,
    pub(crate) peer_id: String,
}

impl serde::Serialize for LocalEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("LocalEnvelope", 4)?;
        state.serialize_field("keypair", &self.keypair)?;
        state.serialize_field("libp2p_keypair", &self.libp2p_keypair.to_bytes().to_vec())?;
        state.serialize_field("peer_public_key", &self.peer_public_key)?;
        state.serialize_field("peer_id", &self.peer_id)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for LocalEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct LocalEnvelopeRaw {
            keypair: Keypair,
            libp2p_keypair: Vec<u8>,
            peer_public_key: PublicKey,
            peer_id: String,
        }

        let raw = LocalEnvelopeRaw::deserialize(deserializer)?;

        let mut libp2p_keypair_bytes: [u8; 32] = raw
            .libp2p_keypair
            .as_slice()
            .try_into()
            .map_err(serde::de::Error::custom)?;

        let libp2p_keypair =
            libp2p::identity::ed25519::Keypair::try_from_bytes(&mut libp2p_keypair_bytes)
                .map_err(serde::de::Error::custom)?;

        Ok(LocalEnvelope {
            keypair: raw.keypair,
            libp2p_keypair,
            peer_public_key: raw.peer_public_key,
            peer_id: raw.peer_id,
        })
    }
}

impl PartialEq for LocalEnvelope {
    fn eq(&self, other: &Self) -> bool {
        self.keypair == other.keypair
            && self.libp2p_keypair.to_bytes() == other.libp2p_keypair.to_bytes()
            && self.peer_public_key == other.peer_public_key
            && self.peer_id == other.peer_id
    }
}
impl Eq for LocalEnvelope {}

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
