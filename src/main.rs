use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit},
    consts::U12,
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;
use voprf::{
    BlindedElement, EvaluationElement, OprfClient, OprfClientBlindResult, OprfServer, Ristretto255,
};

type CS = voprf::Ristretto255;

type PublicKey = [u8; 32];
type PrivateKey = [u8; 32];

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Keypair {
    private_key: PrivateKey,
    public_key: PublicKey,
}

impl Keypair {
    fn new() -> Self {
        let private_key = Scalar::random(&mut OsRng);
        let public_key = RistrettoPoint::default() * private_key;
        Keypair {
            private_key: private_key.to_bytes(),
            public_key: public_key.compress().to_bytes(),
        }
    }
}

struct P2POpaqueNode {
    id: String,
    keypair: Keypair,
    peer_opaque_keys: HashMap<String, Keypair>,
    envelopes: HashMap<String, EncryptedEnvelope>,
    oprf_client: Option<OprfClient<CS>>,
}

impl P2POpaqueNode {
    fn new(id: String) -> Self {
        P2POpaqueNode {
            id,
            keypair: Keypair::new(),
            peer_opaque_keys: HashMap::new(),
            envelopes: HashMap::new(),
            oprf_client: None,
        }
    }
}

struct RegStartRequest {
    blinded_pwd: BlindedElement<CS>,
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
            peer_id: self.id.clone(),
        }
    }
}

struct RegStartResponse {
    rwd: EvaluationElement<CS>,
    peer_public_key: PublicKey,
    peer_id: String,
}

impl P2POpaqueNode {
    fn peer_registration_start(&mut self, peer_req: RegStartRequest) -> RegStartResponse {
        let opaque_keypair = Keypair::new();
        self.peer_opaque_keys
            .insert(peer_req.peer_id, opaque_keypair.clone());
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

struct RegFinishRequest {
    public_key: PublicKey,
    peer_id: String,
    encrypted_envelope: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Envelope {
    keypair: Keypair,
    peer_public_key: PublicKey,
    peer_id: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct EncryptedEnvelope {
    public_key: PublicKey,
    encrypted_envelope: Vec<u8>,
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
        let cipher = ChaCha20Poly1305::new(Key::from_slice(unblinded_rwd.as_slice()));
        let identity_keypair = Keypair::new();
        let nonce_bytes = [0u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let envelope = Envelope {
            keypair: identity_keypair,
            peer_public_key: peer_resp.peer_public_key,
            peer_id: peer_resp.peer_id,
        };
        let plaintext = serde_json::to_string(&envelope)
            .expect("JSON serialization of envelope failed in local registration finish");
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .expect("Encryption of envelope failed in local registration finish");
        RegFinishRequest {
            peer_id: self.id.clone(),
            public_key: self.keypair.public_key,
            encrypted_envelope: ciphertext,
        }
    }
}

impl P2POpaqueNode {
    fn peer_registration_finish(&mut self, peer_req: RegFinishRequest) {
        self.envelopes.insert(
            peer_req.peer_id,
            EncryptedEnvelope {
                public_key: peer_req.public_key,
                encrypted_envelope: peer_req.encrypted_envelope,
            },
        );
    }
}

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
            .expect("OPRF server creation failed for peer registration start");
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
        let oprf_client = self.oprf_client.as_ref().unwrap();
        let unblinded_rwd = oprf_client
            .finalize(&password.as_bytes(), &peer_resp.rwd)
            .expect("Unblinding failed for local login finish");
        let cipher = ChaCha20Poly1305::new(Key::from_slice(unblinded_rwd.as_slice()));
        let nonce_bytes = [0u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext_bytes = cipher
            .decrypt(nonce, peer_resp.envelope.encrypted_envelope.as_ref())
            .expect("Decryption failed for local login finish");
        let plaintext: Envelope = serde_json::from_slice(&plaintext_bytes)
            .expect("Deserialization failed for local login finish");
        plaintext.keypair
    }
}

fn main() {}
