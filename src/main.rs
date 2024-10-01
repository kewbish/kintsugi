use std::collections::HashMap;

use argon2::Argon2;
use opaque_ke::{
    ciphersuite::CipherSuite, ClientRegistration, ClientRegistrationFinishParameters,
    RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;

#[allow(dead_code)]
struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;

    type Ksf = Argon2<'static>;
}

struct PeerDatabaseEntry {
    password_bytes: String,
}

struct LocalDatabaseEntry {
    client_registration: ClientRegistration<DefaultCipherSuite>,
}

struct P2POpaqueNode {
    id: String,
    local_db: HashMap<String, LocalDatabaseEntry>,
    peer_db: HashMap<String, PeerDatabaseEntry>,
}

impl P2POpaqueNode {
    fn new(id: String) -> Self {
        P2POpaqueNode {
            id,
            local_db: HashMap::new(),
            peer_db: HashMap::new(),
        }
    }
    fn local_registration_start(
        &mut self,
        peer_id: String,
        password: String,
    ) -> RegistrationRequest<DefaultCipherSuite> {
        let mut rng = OsRng;
        let client_registration_start_result =
            ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password.as_bytes());
        if let Ok(crsr) = client_registration_start_result {
            self.local_db.insert(
                peer_id,
                LocalDatabaseEntry {
                    client_registration: crsr.state,
                },
            );
            return crsr.message;
        } else {
            panic!("Local registration start failed.")
        }
    }
    fn peer_registration_start(
        &mut self,
        peer_id: String,
        peer_reg_start_message: RegistrationRequest<DefaultCipherSuite>,
    ) -> RegistrationResponse<DefaultCipherSuite> {
        let mut rng = OsRng;
        let local_setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
        let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
            &local_setup,
            peer_reg_start_message,
            peer_id.as_bytes(),
        );
        if let Ok(srsr) = server_registration_start_result {
            self.peer_db.insert(
                peer_id,
                PeerDatabaseEntry {
                    password_bytes: String::new(),
                },
            );
            return srsr.message;
        } else {
            panic!("Peer registration start failed")
        }
    }
    fn local_registration_finish(
        &mut self,
        peer_id: String,
        password: String,
        peer_reg_start_message: RegistrationResponse<DefaultCipherSuite>,
    ) -> RegistrationUpload<DefaultCipherSuite> {
        let client_registration_state = self.local_db.remove(&peer_id);
        if let None = client_registration_state {
            panic!("Could not retrieve local registration start state")
        }
        let mut rng = OsRng;
        let client_registration = client_registration_state.unwrap().client_registration;
        let client_registration_finish_result = client_registration.finish(
            &mut rng,
            password.as_bytes(),
            peer_reg_start_message,
            ClientRegistrationFinishParameters::default(),
        );
        if let Ok(crfr) = client_registration_finish_result {
            return crfr.message;
        } else {
            panic!("Local registration finish failed")
        }
    }
    fn peer_registration_finish(
        &mut self,
        peer_id: String,
        peer_reg_finish_message: RegistrationUpload<DefaultCipherSuite>,
    ) {
        let peer_id_envelope =
            ServerRegistration::<DefaultCipherSuite>::finish(peer_reg_finish_message);
        let serialized_peer_id_envelope = serde_json::to_string(&peer_id_envelope.serialize());
        if let Ok(spie) = serialized_peer_id_envelope {
            self.peer_db.insert(
                peer_id,
                PeerDatabaseEntry {
                    password_bytes: spie,
                },
            );
        } else {
            panic!("Serializing peer registration finish envelope failed")
        }
    }
    fn local_login_start() {}
    fn peer_login_start() {}
    fn local_login_finish() {}
    fn peer_login_finish() {}
}

fn main() {}
