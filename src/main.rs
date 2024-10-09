#[allow(unused_imports)]
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use voprf::{BlindedElement, EvaluationElement, OprfClient, OprfServer};

type CS = voprf::Ristretto255;

type PublicKey = [u8; 32];
type PrivateKey = [u8; 32];

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct Keypair {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl Keypair {
    fn new() -> Self {
        let private_key = Scalar::random(&mut OsRng);
        let public_key = &constants::RISTRETTO_BASEPOINT_POINT * private_key;
        Keypair {
            private_key: private_key.to_bytes(),
            public_key: public_key.compress().to_bytes(),
        }
    }
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
    fn local_registration_start(&mut self, password: String) -> RegStartRequest {
        let mut rng = OsRng;
        let password_blind_result = OprfClient::<CS>::blind(password.as_bytes(), &mut rng)
            .expect("OPRF client blinding failed for local registration start");
        self.oprf_client = Some(password_blind_result.state);
        RegStartRequest {
            blinded_pwd: password_blind_result.message,
            peer_public_key: self.keypair.public_key,
            peer_id: self.id.clone(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct RegStartResponse {
    rwd: EvaluationElement<CS>,
    peer_public_key: PublicKey,
    peer_id: String,
}

impl P2POpaqueNode {
    fn peer_registration_start(&mut self, peer_req: RegStartRequest) -> RegStartResponse {
        let opaque_keypair = Keypair::new();
        self.peer_opaque_keys
            .insert(peer_req.peer_id.clone(), opaque_keypair.clone());
        if self
            .peer_attempted_public_keys
            .contains_key(&peer_req.peer_id)
        {
            panic!(
                "A registration attempt from this node already exists in peer registration start"
            )
        }
        self.peer_attempted_public_keys
            .insert(peer_req.peer_id, peer_req.peer_public_key);
        let server = OprfServer::<CS>::new_with_key(&opaque_keypair.private_key)
            .expect("OPRF server creation failed for peer registration start");
        let password_blind_eval = server.blind_evaluate(&peer_req.blinded_pwd);
        RegStartResponse {
            rwd: password_blind_eval,
            peer_public_key: self.keypair.public_key,
            peer_id: self.id.clone(),
        }
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

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct Signature {
    r_point: RistrettoPoint,
    signature: Scalar,
}

impl Signature {
    fn new_with_keypair(message: &[u8], keypair: Keypair) -> Self {
        let nonce = Scalar::random(&mut OsRng);
        let r_point = &constants::RISTRETTO_BASEPOINT_POINT * nonce;
        let mut hasher = Sha3_256::new();
        hasher.update(r_point.compress().as_bytes());
        hasher.update(keypair.public_key.as_slice());
        hasher.update(message);
        let hash = hasher.finalize();
        let hash_scalar = Scalar::from_bytes_mod_order(hash.as_slice().try_into().unwrap());
        let private_key = Scalar::from_canonical_bytes(keypair.private_key)
            .expect("Could not deserialize private key in signature generation");
        Signature {
            r_point,
            signature: nonce + (private_key * hash_scalar),
        }
    }

    fn verify(self, message: &[u8], public_key: PublicKey) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(self.r_point.compress().as_bytes());
        hasher.update(public_key.as_slice());
        hasher.update(message);
        let hash = hasher.finalize();
        let hash_scalar = Scalar::from_bytes_mod_order(hash.as_slice().try_into().unwrap());
        let public_key_point = CompressedRistretto::from_slice(&public_key)
            .expect("Could not deserialize public key in signature verification")
            .decompress()
            .expect("Could not deserialize public key in signature verification");
        let r_prime =
            &constants::RISTRETTO_BASEPOINT_POINT * self.signature - hash_scalar * public_key_point;
        r_prime == self.r_point
    }
}

impl P2POpaqueNode {
    fn local_registration_finish(
        &mut self,
        password: String,
        peer_resp: RegStartResponse,
    ) -> RegFinishRequest {
        if let None = self.oprf_client {
            panic!("OPRF client not initialized during local registration finish")
        }
        let oprf_client = self.oprf_client.as_ref().unwrap();
        let unblinded_rwd = oprf_client
            .finalize(&password.as_bytes(), &peer_resp.rwd)
            .expect("Unblinding failed for local registration finish");
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
        let plaintext = serde_json::to_string(&envelope)
            .expect("JSON serialization of envelope failed in local registration finish");
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .expect("Encryption of envelope failed in local registration finish");

        let signature = Signature::new_with_keypair(&ciphertext, self.keypair.clone());

        RegFinishRequest {
            peer_id: self.id.clone(),
            peer_public_key: self.keypair.public_key,
            encrypted_envelope: ciphertext,
            nonce: nonce_bytes,
            signature,
        }
    }
}

impl P2POpaqueNode {
    fn peer_registration_finish(&mut self, peer_req: RegFinishRequest) {
        let peer_public_key = self.peer_attempted_public_keys.get(&peer_req.peer_id);
        if let None = peer_public_key {
            panic!(
                "A registration attempt from this node does not exist in peer registration finish"
            )
        }
        if !peer_req.signature.verify(
            &peer_req.encrypted_envelope,
            peer_public_key.unwrap().clone(),
        ) {
            panic!("Could not verify signature of registration request in peer registration finish")
        }
        self.envelopes.insert(
            peer_req.peer_id,
            EncryptedEnvelope {
                public_key: peer_req.peer_public_key,
                encrypted_envelope: peer_req.encrypted_envelope,
                nonce: peer_req.nonce,
            },
        );
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct LoginStartRequest {
    blinded_pwd: BlindedElement<CS>,
    peer_id: String,
}

impl P2POpaqueNode {
    fn local_login_start(&mut self, password: String) -> LoginStartRequest {
        let mut rng = OsRng;
        let password_blind_result = OprfClient::<CS>::blind(password.as_bytes(), &mut rng)
            .expect("OPRF client blinding failed for local login start");
        self.oprf_client = Some(password_blind_result.state);
        LoginStartRequest {
            blinded_pwd: password_blind_result.message,
            peer_id: self.id.clone(),
        }
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
    fn peer_login_start(&self, peer_req: LoginStartRequest) -> LoginStartResponse {
        let local_opaque_keypair = self.peer_opaque_keys.get(&peer_req.peer_id);
        if let None = local_opaque_keypair {
            panic!("Could not find local keypair for peer login start")
        }
        let envelope = self.envelopes.get(&peer_req.peer_id);
        if let None = envelope {
            panic!("Could not find envelope for peer login start")
        }
        let server = OprfServer::<CS>::new_with_key(&local_opaque_keypair.unwrap().private_key)
            .expect("OPRF server creation failed for peer login start");
        let password_blind_eval = server.blind_evaluate(&peer_req.blinded_pwd);
        LoginStartResponse {
            rwd: password_blind_eval,
            envelope: envelope.unwrap().clone(),
            peer_public_key: self.keypair.public_key,
            peer_id: self.id.clone(),
        }
    }
}

impl P2POpaqueNode {
    fn local_login_finish(&self, password: String, peer_resp: LoginStartResponse) -> Keypair {
        if let None = self.oprf_client {
            panic!("OPRF client not initialized during local registration finish")
        }
        let oprf_client = self.oprf_client.as_ref().unwrap();
        let unblinded_rwd = oprf_client
            .finalize(&password.as_bytes(), &peer_resp.rwd)
            .expect("Unblinding failed for local login finish");
        let mut hasher = Sha3_256::new();
        hasher.update(unblinded_rwd.as_slice());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce_bytes = peer_resp.envelope.nonce;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext_bytes = cipher
            .decrypt(nonce, peer_resp.envelope.encrypted_envelope.as_ref())
            .expect("Decryption failed for local login finish");
        let plaintext: Envelope = serde_json::from_slice(&plaintext_bytes)
            .expect("Deserialization failed for local login finish");
        plaintext.keypair
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod test;

fn main() {}
