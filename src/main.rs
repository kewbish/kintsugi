mod acss;
mod coin;
mod dkg;
mod dpss;
mod file_sss;
mod keypair;
mod local_envelope;
mod opaque;
mod oprf;
mod polynomial;
mod signature;
mod util;
mod zkp;

use acss::{ACSSDealerShare, ACSSInputs, ACSSNodeShare, ACSS};
#[allow(unused_imports)]
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{RistrettoPoint, Scalar};
use dpss::DPSS;
use futures::prelude::*;
use keypair::{Keypair, PublicKey};
use libp2p::kad::QueryResult;
use libp2p::kad::{
    store::{MemoryStore, RecordStore},
    GetRecordOk, PeerRecord,
};
use libp2p::{
    identify,
    kad::{self, InboundRequest, QueryId},
    mdns,
    request_response::{self, ProtocolSupport, ResponseChannel},
    Multiaddr, PeerId, StreamProtocol, Swarm,
};
use libp2p::{
    kad::{Record, RecordKey},
    swarm::{NetworkBehaviour, SwarmEvent},
};
use local_envelope::{LocalEncryptedEnvelope, LocalEnvelope};
use opaque::{
    EncryptedEnvelope, LoginStartRequest, LoginStartResponse, P2POpaqueNode, RegFinishRequest,
    RegStartRequest, RegStartResponse,
};
use polynomial::Polynomial;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use sha3::{Digest, Sha3_256};
use signature::Signature;
use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tauri::{Manager, State};
use tokio::{select, sync::mpsc};
use util::i32_to_scalar;

// --- state structs --- //

#[derive(Debug, Clone)]
struct NodeState {
    peer_id: PeerId,
    username: String,
    opaque_keypair: Keypair,
    libp2p_keypair_bytes: [u8; 64],
    is_bootstrap: bool,
    threshold: usize,
    username_to_peer_id: HashMap<String, PeerId>,
    username_to_index: HashMap<String, i32>, // this node's recovery nodes' indices
    username_to_opaque_pkey: HashMap<String, PublicKey>,
    acss_inputs: ACSSInputs,
    opaque_node: P2POpaqueNode,
    // the indices for nodes for which this node is a recovery node
    peer_recoveries: HashMap<String, (ACSSNodeShare, i32)>,
    phi_polynomials: Option<(Polynomial, Polynomial)>,
    registration_received: Option<HashMap<String, RegStartResponse>>,
    recovery_received: Option<HashMap<String, LoginStartResponse>>,
    reshare_received: Option<HashMap<String, (ACSSNodeShare, ACSSNodeShare)>>,
    kad_filtering: HashMap<QueryId, Record>,
    waiting_for_peer_id: HashMap<String, Vec<RequestMessage>>,
}

#[serde_as]
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct BootstrapNodeState {
    peer_id: PeerId,
    opaque_keypair: Keypair,
    #[serde_as(as = "Bytes")]
    libp2p_keypair_bytes: [u8; 64],
}

// --- message structs --- //

#[derive(Serialize, Deserialize, Clone, Debug)]
struct OPRFRegInitMessage {
    inputs: ACSSInputs,
    reg_start_req: RegStartRequest,
    dealer_shares: HashMap<String, ACSSDealerShare>,
    dealer_key: PublicKey,
    user_username: String,
    node_index: i32,
    node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct OPRFRegStartRespMessage {
    reg_start_resp: RegStartResponse,
    user_username: String,
    node_index: i32,
    node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct OPRFRegFinishReqMessage {
    reg_finish_req: RegFinishRequest,
    user_username: String,
    node_index: i32,
    node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct OPRFRecoveryStartReqMessage {
    recovery_start_req: LoginStartRequest,
    other_indices: HashSet<i32>,
    user_username: String,
    node_index: i32,
    node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct OPRFRecoveryStartRespMessage {
    recovery_start_resp: LoginStartResponse,
    user_username: String,
    node_index: i32,
    node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct DPSSRefreshInitMessage {
    new_recovery_addresses: HashMap<String, i32>,
    new_threshold: usize,
    user_username: String,
    node_index: i32,
    node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct DPSSRefreshReshareMessage {
    inputs: ACSSInputs,
    dealer_shares: HashMap<String, ACSSDealerShare>,
    dealer_shares_hat: HashMap<String, ACSSDealerShare>,
    commitments: HashMap<Scalar, RistrettoPoint>,
    dealer_key: PublicKey,
    new_threshold: usize,
    user_username: String,
    node_index: i32,
    node_username: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
enum RequestMessage {
    OPRFRegInitMessage(OPRFRegInitMessage),
    OPRFRegFinishReqMessage(OPRFRegFinishReqMessage),
    OPRFRecoveryStartReqMessage(OPRFRecoveryStartReqMessage),
    DPSSRefreshInitMessage(DPSSRefreshInitMessage),
    DPSSRefreshReshareMessage(DPSSRefreshReshareMessage),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
enum ResponseMessage {
    OPRFRegStartRespMessage(OPRFRegStartRespMessage),
    OPRFRecoveryStartRespMessage(OPRFRecoveryStartRespMessage),
}

#[derive(NetworkBehaviour)]
struct P2PBehaviour {
    kad: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    mdns: mdns::tokio::Behaviour,
    request_response: request_response::json::Behaviour<RequestMessage, ResponseMessage>,
}

enum TauriToRustCommand {
    RegStart(String, String, HashMap<String, i32>, usize),
    RecoveryStart(String, String, HashMap<String, i32>),
    RefreshStart(HashMap<String, i32>, i32),
}

/*#[derive(Clone, Debug, Eq, PartialEq)]
struct HashedKadRecord(Record);

impl std::hash::Hash for HashedKadRecord {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.key.hash(state);
        self.0.value.hash(state);
        self.0.publisher.hash(state);
        self.0.expires.hash(state);
    }
}*/

#[derive(serde::Serialize, serde::Deserialize)]
struct KadRecord {
    data: KadRecordType,
    username: String,
    signature: Signature,
}

impl KadRecord {
    fn new(
        key: RecordKey,
        data: KadRecordType,
        username: String,
        publisher: PeerId,
        signing_keypair: Keypair,
    ) -> (Self, Record) {
        let mut data_to_sign = key.to_vec();
        data_to_sign.extend_from_slice(username.as_bytes());
        let serialized_data = serde_json::to_vec(&data).unwrap();
        data_to_sign.extend(serialized_data);
        let kad_record = KadRecord {
            data,
            username,
            signature: Signature::new_with_keypair(data_to_sign.as_slice(), signing_keypair),
        };
        let record = Record {
            key,
            value: serde_json::to_vec(&kad_record).unwrap(),
            publisher: Some(publisher),
            expires: None,
        };
        (kad_record, record)
    }
    fn signed_data(&self) -> Vec<u8> {
        let mut vec = Vec::from(self.username.as_bytes());
        let serialized_data = serde_json::to_vec(&self.data).unwrap();
        vec.extend(serialized_data);
        vec
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
enum KadRecordType {
    Pk(PublicKey),
    RecvAddr(HashMap<String, i32>, usize),
    PeerId(PeerId),
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedTauriNotepad {
    encrypted_contents: Vec<u8>,
    nonce: [u8; 12],
}

#[allow(deprecated)]
fn new_swarm(
    keypair: libp2p::identity::ed25519::Keypair,
) -> Result<Swarm<P2PBehaviour>, Box<dyn Error>> {
    let libp2p_keypair = libp2p::identity::Keypair::from(keypair);
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(libp2p_keypair.clone())
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let mut kad_config = kad::Config::new(StreamProtocol::new("/kintsugi/kad/1.0.0"));
            kad_config.set_record_filtering(kad::StoreInserts::FilterBoth);
            let kad = kad::Behaviour::with_config(
                key.public().to_peer_id(),
                kad::store::MemoryStore::new(key.public().to_peer_id()),
                kad_config,
            );

            let identify = identify::Behaviour::new(identify::Config::new(
                "/ipfs/id/1.0.0".to_string(),
                key.public(),
            ));

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;

            let request_response = request_response::json::Behaviour::new(
                [(
                    StreamProtocol::new("/kintsugi/1.0.0"),
                    ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            );

            Ok(P2PBehaviour {
                kad,
                identify,
                mdns,
                request_response,
            })
        })?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(std::time::Duration::from_secs(u64::MAX))
        })
        .build();
    swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Server));
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    Ok(swarm)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let (tx, mut rx) = mpsc::channel::<TauriToRustCommand>(32);
    let mut state = NodeState {
        peer_id: PeerId::random(), // temp
        username: "".to_string(),  // temp
        opaque_keypair: Keypair::new(),
        libp2p_keypair_bytes: [0u8; 64],
        is_bootstrap: false,
        threshold: 1, // temp
        username_to_peer_id: HashMap::new(),
        username_to_index: HashMap::new(), // temp
        username_to_opaque_pkey: HashMap::new(),
        acss_inputs: ACSSInputs {
            h_point: Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT,
            degree: 1,
            peer_public_keys: HashMap::new(),
        },
        opaque_node: P2POpaqueNode::new("".to_string()),
        peer_recoveries: HashMap::new(),
        phi_polynomials: None,
        registration_received: None,
        recovery_received: None,
        reshare_received: None,
        threshold: 1, // temp
        kad_filtering: HashMap::new(),
        waiting_for_peer_id: HashMap::new(),
    };
    let mut is_bootstrap = false;
    let mut bootstrap_keypair: libp2p::identity::ed25519::Keypair =
        libp2p::identity::ed25519::Keypair::generate();
    let mut bootstrap_username = "".to_string();

    let args: Vec<String> = env::args().collect();
    if args.len() == 3 && args[1] != "BOOTSTRAP" {
        state.username = args[1].clone();
        state.peer_id = PeerId::from_str(&args[2])?;
    } else if args.len() == 3 && args[1] == "BOOTSTRAP" {
        is_bootstrap = true;
        state.is_bootstrap = true;
        let file_path = format!("tmp/bootstrap_0.envelope");
        if Path::new(&file_path).exists() {
            let parsed_index: i32 = args[2].parse()?;
            let file_path = format!("tmp/bootstrap_{}.envelope", parsed_index);
            let contents = std::fs::read_to_string(file_path);
            let bootstrap_node_state: BootstrapNodeState =
                serde_json::from_str(&contents.unwrap())?;

            state.username = format!("bootstrap{parsed_index}");
            state.peer_id = bootstrap_node_state.peer_id;
            state.libp2p_keypair_bytes = bootstrap_node_state.libp2p_keypair_bytes;
            bootstrap_keypair = libp2p::identity::ed25519::Keypair::try_from_bytes(
                &mut state.libp2p_keypair_bytes.clone(),
            )
            .unwrap();
            state.opaque_keypair = bootstrap_node_state.opaque_keypair;
        } else {
            for i in 0..3 {
                let libp2p_keypair = libp2p::identity::ed25519::Keypair::generate();
                let new_peer_id = PeerId::from_public_key(
                    &(libp2p::identity::PublicKey::from(libp2p_keypair.public())),
                );
                let opaque_keypair = Keypair::new();

                let serialized_keypairs = serde_json::to_string(&BootstrapNodeState {
                    libp2p_keypair_bytes: libp2p_keypair.to_bytes(),
                    peer_id: new_peer_id,
                    opaque_keypair: opaque_keypair.clone(),
                })?;
                let file_path = format!("tmp/bootstrap_{i}.envelope");
                let mut file = fs::File::create(file_path)?;
                file.write_all(serialized_keypairs.as_bytes())?;

                if i == 0 {
                    state.username = format!("bootstrap{i}");
                    state.peer_id = new_peer_id;
                    state.libp2p_keypair_bytes = libp2p_keypair.to_bytes();
                    bootstrap_keypair = libp2p_keypair;
                    state.opaque_keypair = opaque_keypair;
                }
            }
        }

        println!("[BOOTSTRAP] Node is running at peer ID {}", state.peer_id);
    }

    if !is_bootstrap {
        state.peer_id = PeerId::from(libp2p::identity::PublicKey::from(
            bootstrap_keypair.public(),
        ));
    }

    let state_arc = Arc::new(Mutex::new(state));

    let mut swarm = new_swarm(bootstrap_keypair)?;

    fn handle_request(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        request: RequestMessage,
        channel: ResponseChannel<ResponseMessage>,
    ) -> Result<(), Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();

        match request {
            RequestMessage::OPRFRegInitMessage(msg) => {
                handle_message_reg_init(&mut state, swarm, peer_id, msg, channel)
            }
            RequestMessage::OPRFRegFinishReqMessage(msg) => {
                handle_message_reg_finish_req(&mut state, swarm, peer_id, msg)?;
                update_recovery_addrs(state_arc.clone(), swarm)
            }
            RequestMessage::OPRFRecoveryStartReqMessage(msg) => {
                handle_message_rec_start_req(&mut state, swarm, peer_id, msg, channel)
            }
            RequestMessage::DPSSRefreshInitMessage(msg) => {
                handle_message_dpss_init(&mut state, swarm, peer_id, msg)
            }
            RequestMessage::DPSSRefreshReshareMessage(msg) => {
                handle_message_dpss_reshare(&mut state, swarm, peer_id, msg)?;
                update_recovery_addrs(state_arc.clone(), swarm)
            }
        }
    }

    fn handle_response(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        response: ResponseMessage,
    ) -> Result<(), Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();

        match response {
            ResponseMessage::OPRFRegStartRespMessage(msg) => {
                handle_message_reg_start_resp(&mut state, swarm, peer_id, msg)
            }
            ResponseMessage::OPRFRecoveryStartRespMessage(msg) => {
                handle_message_rec_start_resp(&mut state, swarm, peer_id, msg)
            }
        }
    }

    fn handle_username_update(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        username: String,
    ) -> Result<(), String> {
        if username != "" {
            let mut state = state_arc.lock().unwrap();

            state.username = username.clone();
            state.opaque_node.id = username.clone();

            println!("[DEBUG] Updating username to {:?}", username.clone());

            let (_peer_id_kad_record, peer_id_record) = KadRecord::new(
                RecordKey::new(&format!("/peer_id/{}", state.username)),
                KadRecordType::PeerId(state.peer_id),
                username.clone(),
                state.peer_id,
                state.opaque_keypair.clone(),
            );
            if let Err(e) = swarm.behaviour_mut().kad.put_record(
                peer_id_record,
                kad::Quorum::N(NonZeroUsize::new(state.threshold).unwrap()),
            ) {
                println!("[KAD] Error {:?}", e.to_string());
                return Err(e.to_string());
            }

            let (_pk_kad_record, pk_record) = KadRecord::new(
                RecordKey::new(&format!("/pk/{}", state.username)),
                KadRecordType::Pk(state.opaque_keypair.clone().public_key),
                username.clone(),
                state.peer_id,
                state.opaque_keypair.clone(),
            );
            if let Err(e) = swarm.behaviour_mut().kad.put_record(
                pk_record,
                kad::Quorum::N(NonZeroUsize::new(state.threshold).unwrap()),
            ) {
                println!("[KAD] Error {:?}", e.to_string());
                return Err(e.to_string());
            }

            if state.username_to_index.len() == 0 {
                let file_path = format!("tmp/{}_peers.list", state.username);
                if Path::new(&file_path).exists() {
                    let contents = std::fs::read_to_string(file_path);
                    if let Err(e) = contents {
                        return Err(e.to_string());
                    }
                    let peers_list: Result<
                        (
                            usize,
                            HashMap<String, i32>,
                            HashMap<String, (ACSSNodeShare, i32)>,
                        ),
                        _,
                    > = serde_json::from_str(&contents.unwrap());
                    if let Err(e) = peers_list {
                        return Err(e.to_string());
                    }
                    let peers_list = peers_list.unwrap();
                    state.threshold = peers_list.0;
                    state.username_to_index = peers_list.1;
                    state.peer_recoveries = peers_list.2;
                }
            }

            if state.opaque_node.envelopes.len() == 0 {
                let file_path = format!("tmp/{}_envelopes.list", state.username);
                if Path::new(&file_path).exists() {
                    let contents = std::fs::read_to_string(file_path);
                    if let Err(e) = contents {
                        return Err(e.to_string());
                    }
                    let envelopes_list: Result<HashMap<String, EncryptedEnvelope>, _> =
                        serde_json::from_str(&contents.unwrap());
                    if let Err(e) = envelopes_list {
                        return Err(e.to_string());
                    }
                    state.opaque_node.envelopes = envelopes_list.unwrap();
                }
            }
        }

        Ok(())
    }

    fn send_request_msg(
        swarm: &mut Swarm<P2PBehaviour>,
        state: &mut NodeState,
        username: String,
        msg: RequestMessage,
    ) {
        let destination_peer_id = state.username_to_peer_id.get(&username);
        println!(
            "[DEBUG] Sending to {:?}, peer ID {:?}",
            username.clone(),
            destination_peer_id
        );
        match destination_peer_id {
            Some(peer) => {
                swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(peer, msg);
            }
            None => {
                if state.waiting_for_peer_id.contains_key(&username) {
                    state
                        .waiting_for_peer_id
                        .get_mut(&username)
                        .unwrap()
                        .push(msg);
                } else {
                    state.waiting_for_peer_id.insert(username, Vec::from([msg]));
                }
            }
        }
    }

    fn handle_reg_init(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        password: String,
        recovery_addresses: HashMap<String, i32>,
        threshold: usize,
    ) -> Result<(), Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();

        state.acss_inputs.peer_public_keys = recovery_addresses
            .iter()
            .map(|(k, _)| {
                (
                    k.clone(),
                    state.username_to_opaque_pkey.get(k).unwrap().clone(),
                )
            })
            .collect();
        state.acss_inputs.degree = threshold - 1;

        let s = Scalar::random(&mut OsRng);
        let (acss_dealer_shares, phi, phi_hat) = ACSS::share_dealer(
            state.acss_inputs.clone(),
            s,
            threshold - 1,
            state.opaque_keypair.private_key,
        )?;
        state.phi_polynomials = Some((phi, phi_hat));
        state.registration_received = Some(HashMap::new());

        let reg_start_req = state.opaque_node.local_registration_start(password)?;

        state.threshold = threshold;
        for (username, index) in recovery_addresses.iter() {
            state
                .username_to_index
                .insert(username.clone(), index.clone());

            let init_message = RequestMessage::OPRFRegInitMessage(OPRFRegInitMessage {
                inputs: state.acss_inputs.clone(),
                reg_start_req: reg_start_req.clone(),
                dealer_shares: acss_dealer_shares.clone(),
                dealer_key: state.opaque_keypair.public_key,
                user_username: state.username.clone(),
                node_index: index.clone(),
                node_username: username.clone(),
            });

            send_request_msg(swarm, &mut state, username.clone(), init_message);
            println!(
                "[INIT] Sending ACSS share messages for user {}",
                state.username
            );
        }

        std::mem::drop(state);

        update_recovery_addrs(state_arc.clone(), swarm)?;

        Ok(())
    }

    fn handle_message_reg_init(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        _peer_id: PeerId,
        message: OPRFRegInitMessage,
        channel: ResponseChannel<ResponseMessage>,
    ) -> Result<(), Box<dyn Error>> {
        let node_share = ACSS::share(
            message.inputs.clone(),
            message
                .dealer_shares
                .get(&state.username.clone())
                .unwrap()
                .clone(),
            state.opaque_keypair.clone(),
            message.dealer_key,
        )?;

        state.peer_recoveries.insert(
            message.node_username,
            (node_share.clone(), message.node_index),
        );

        let other_indices = message
            .dealer_shares
            .values()
            .map(|share| share.index.try_into().unwrap())
            .collect();
        let reg_start_resp = state.opaque_node.peer_registration_start(
            message.reg_start_req,
            message.node_index,
            other_indices,
        )?;
        let reg_start_resp_message =
            ResponseMessage::OPRFRegStartRespMessage(OPRFRegStartRespMessage {
                reg_start_resp,
                user_username: message.user_username.clone(),
                node_index: message.node_index,
                node_username: state.username.clone(),
            });

        if let Err(e) = swarm
            .behaviour_mut()
            .request_response
            .send_response(channel, reg_start_resp_message)
        {
            println!("[REG INIT] Publish error: {e:?}");
        } else {
            println!(
                "[REG INIT] Published acknowledgement message for user {}",
                message.user_username
            );
        }

        Ok(())
    }

    fn handle_message_reg_start_resp(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        _peer_id: PeerId,
        message: OPRFRegStartRespMessage,
    ) -> Result<(), Box<dyn Error>> {
        if let None = state.registration_received {
            return Ok(());
        }

        let mut s = state.registration_received.take().unwrap();
        s.insert(message.node_username, message.reg_start_resp);

        if s.len() < state.threshold {
            state.registration_received = Some(s);
            return Ok(());
        }

        let reg_finish_reqs = state
            .opaque_node
            .local_registration_finish(s.values().map(|v| v.clone()).collect(), state.threshold)?;
        for reg_finish_req in reg_finish_reqs.iter() {
            let index = state
                .username_to_index
                .get(&reg_finish_req.node_username)
                .unwrap()
                .clone();
            let reg_finish_req_message =
                RequestMessage::OPRFRegFinishReqMessage(OPRFRegFinishReqMessage {
                    reg_finish_req: reg_finish_req.clone(),
                    user_username: state.username.clone(),
                    node_index: index,
                    node_username: reg_finish_req.node_username.clone(),
                });

            send_request_msg(
                swarm,
                state,
                reg_finish_req.node_username.clone(),
                reg_finish_req_message,
            );
            println!(
                "[REG START RESP] Sending reg start finish message for user {} at index {}",
                state.username, index
            );
        }

        Ok(())
    }

    fn handle_message_reg_finish_req(
        state: &mut NodeState,
        _swarm: &mut Swarm<P2PBehaviour>,
        _peer_id: PeerId,
        message: OPRFRegFinishReqMessage,
    ) -> Result<(), Box<dyn Error>> {
        state
            .opaque_node
            .peer_registration_finish(message.reg_finish_req)?;

        let serialized_envelopes = serde_json::to_string(&state.opaque_node.envelopes)?;
        let file_path = format!("tmp/{}_envelopes.list", state.username);
        let mut file = fs::File::create(file_path)?;
        file.write_all(serialized_envelopes.as_bytes())?;

        println!(
            "[REG FINISH] Finished peer registration for user at peer ID {}",
            message.user_username
        );

        Ok(())
    }

    fn handle_recovery_init(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        username: String,
        password: String,
        recovery_addresses: HashMap<String, i32>,
    ) -> Result<(), Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();
        state.username = username;
        state.recovery_received = Some(HashMap::new());

        let recovery_start_req = state.opaque_node.local_login_start(password)?;

        let other_indices: HashSet<i32> = recovery_addresses
            .clone()
            .values()
            .map(|v| v.clone())
            .collect();
        for (username, index) in recovery_addresses.iter() {
            let login_start_req =
                RequestMessage::OPRFRecoveryStartReqMessage(OPRFRecoveryStartReqMessage {
                    recovery_start_req: recovery_start_req.clone(),
                    other_indices: other_indices.clone(),
                    user_username: state.username.clone(),
                    node_index: index.clone(),
                    node_username: username.clone(),
                });

            send_request_msg(swarm, &mut state, username.clone(), login_start_req);
            println!(
                "[REC INIT] Sending initial req for user {} at index {}",
                state.username, index
            );
        }

        Ok(())
    }

    fn handle_message_rec_start_req(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        _peer_id: PeerId,
        message: OPRFRecoveryStartReqMessage,
        channel: ResponseChannel<ResponseMessage>,
    ) -> Result<(), Box<dyn Error>> {
        let rec_start_resp = state.opaque_node.peer_login_start(
            message.recovery_start_req,
            message.node_index,
            message.other_indices,
        )?;
        let rec_start_resp_message =
            ResponseMessage::OPRFRecoveryStartRespMessage(OPRFRecoveryStartRespMessage {
                recovery_start_resp: rec_start_resp,
                user_username: message.user_username.clone(),
                node_index: message.node_index,
                node_username: state.username.clone(),
            });

        if let Err(e) = swarm
            .behaviour_mut()
            .request_response
            .send_response(channel, rec_start_resp_message)
        {
            println!("[REC START REQ] Publish error: {e:?}");
        } else {
            println!(
                "[REC START REQ] Published acknowledgement message for user at peer ID {}",
                message.user_username
            );
        }

        Ok(())
    }

    fn handle_message_rec_start_resp(
        state: &mut NodeState,
        _swarm: &mut Swarm<P2PBehaviour>,
        _peer_id: PeerId,
        message: OPRFRecoveryStartRespMessage,
    ) -> Result<(), Box<dyn Error>> {
        if let None = state.recovery_received {
            return Ok(());
        }

        let mut s = state.recovery_received.take().unwrap();
        s.insert(message.node_username.clone(), message.recovery_start_resp);

        if s.len() < state.threshold {
            state.recovery_received = Some(s);
            return Ok(());
        }

        let opaque_keypair = state
            .opaque_node
            .local_login_finish(s.values().map(|v| v.clone()).collect())?;
        state.opaque_keypair = opaque_keypair;

        Ok(())
    }

    fn handle_refresh_init(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        new_recovery_addresses: HashMap<String, i32>,
        new_threshold: usize,
    ) -> Result<(), Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();
        if new_threshold + 1 > new_recovery_addresses.len() {
            return Err(Box::from(
                "Not enough recovery addresses for this threshold",
            ));
        }

        let username_to_index_map = state.username_to_index.clone();
        for (username, index) in username_to_index_map.iter() {
            let init_message = RequestMessage::DPSSRefreshInitMessage(DPSSRefreshInitMessage {
                new_recovery_addresses: new_recovery_addresses.clone(),
                new_threshold,
                user_username: state.username.clone(),
                node_index: index.clone(),
                node_username: username.clone(),
            });

            send_request_msg(swarm, &mut state, username.clone(), init_message);
            println!(
                "[DPSS INIT] Sending init message for user {}",
                state.username
            );
        }

        state.username_to_index = new_recovery_addresses;

        Ok(())
    }

    fn handle_message_dpss_init(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        _peer_id: PeerId,
        message: DPSSRefreshInitMessage,
    ) -> Result<(), Box<dyn Error>> {
        let (node_share, _) = state.peer_recoveries.get(&message.node_username).unwrap();
        let (acss_dealer_share_s, _, _) = ACSS::share_dealer(
            state.acss_inputs.clone(),
            node_share.s_i_d,
            message.new_threshold - 1,
            state.opaque_keypair.private_key,
        )?;

        let (acss_dealer_share_s_hat, _, _) = ACSS::share_dealer(
            state.acss_inputs.clone(),
            node_share.s_hat_i_d,
            message.new_threshold - 1,
            state.opaque_keypair.private_key,
        )?;

        let old_commitments: HashMap<Scalar, RistrettoPoint> = state
            .peer_recoveries
            .iter()
            .map(|(_, v)| (i32_to_scalar(v.1), v.0.c_i.clone()))
            .collect();

        for (username, index) in message.new_recovery_addresses.iter() {
            let reshare_msg =
                RequestMessage::DPSSRefreshReshareMessage(DPSSRefreshReshareMessage {
                    inputs: state.acss_inputs.clone(),
                    dealer_shares: acss_dealer_share_s.clone(),
                    dealer_shares_hat: acss_dealer_share_s_hat.clone(),
                    dealer_key: state.opaque_keypair.private_key,
                    new_threshold: message.new_threshold,
                    commitments: old_commitments.clone(),
                    user_username: state.username.clone(),
                    node_index: index.clone(),
                    node_username: username.clone(),
                });

            send_request_msg(swarm, state, username.clone(), reshare_msg);
            println!(
                "[DPSS REFR INIT] Sending initial ACSS reshares for user {} at index {}",
                state.username, index
            );
        }

        if !message.new_recovery_addresses.contains_key(&state.username) {
            state.peer_recoveries.remove(&message.user_username);
        }

        Ok(())
    }

    fn handle_message_dpss_reshare(
        state: &mut NodeState,
        _swarm: &mut Swarm<P2PBehaviour>,
        _peer_id: PeerId,
        message: DPSSRefreshReshareMessage,
    ) -> Result<(), Box<dyn Error>> {
        let node_share = ACSS::share(
            message.inputs.clone(),
            message.dealer_shares.get(&state.username).unwrap().clone(),
            state.opaque_keypair.clone(),
            message.dealer_key,
        )?;
        let node_share_hat = ACSS::share(
            message.inputs.clone(),
            message
                .dealer_shares_hat
                .get(&state.username)
                .unwrap()
                .clone(),
            state.opaque_keypair.clone(),
            message.dealer_key,
        )?;

        let mut s: HashMap<String, (ACSSNodeShare, ACSSNodeShare)>;
        if let None = state.reshare_received {
            s = HashMap::new();
        } else {
            s = state.reshare_received.take().unwrap();
        }

        s.insert(message.node_username.clone(), (node_share, node_share_hat));

        if s.len() < state.threshold {
            state.reshare_received = Some(s);
            return Ok(());
        }

        let evaluations: HashMap<Scalar, Scalar> = s
            .iter()
            .map(|(_, v)| (i32_to_scalar(message.node_index), v.0.s_i_d))
            .collect();
        let evaluations_hat: HashMap<Scalar, Scalar> = s
            .iter()
            .map(|(_, v)| (i32_to_scalar(message.node_index), v.1.s_i_d))
            .collect();
        let (s_i_d_prime, s_hat_i_d_prime, new_commitments) =
            DPSS::reshare_w_evals(evaluations, evaluations_hat, message.commitments)?;
        let commitment_i = new_commitments
            .get(&i32_to_scalar(message.node_index))
            .unwrap();

        state.peer_recoveries.insert(
            message.node_username,
            (
                ACSSNodeShare {
                    s_i_d: s_i_d_prime,
                    s_hat_i_d: s_hat_i_d_prime,
                    c_i: commitment_i.clone(),
                },
                message.node_index,
            ),
        );
        state.threshold = message.new_threshold;

        Ok(())
    }

    fn update_recovery_addrs(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
    ) -> Result<(), Box<dyn Error>> {
        let state = state_arc.lock().unwrap();

        let serialized_peers = serde_json::to_string(&(
            state.threshold.clone(),
            state.username_to_index.clone(),
            state.peer_recoveries.clone(),
        ))?;
        let file_path = format!("tmp/{}_peers.list", state.username);
        let mut file = fs::File::create(file_path)?;
        file.write_all(serialized_peers.as_bytes())?;

        let (_recv_addr_kad_record, recv_addr_record) = KadRecord::new(
            RecordKey::new(&format!("/recv_addr/{}", state.peer_id)),
            KadRecordType::RecvAddr(state.username_to_index.clone(), state.threshold),
            state.username.clone(),
            state.peer_id,
            state.opaque_keypair.clone(),
        );

        swarm.behaviour_mut().kad.put_record(
            recv_addr_record.clone(),
            kad::Quorum::N(NonZeroUsize::new(state.threshold).unwrap()),
        )?;

        Ok(())
    }

    fn add_peer(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        peer: PeerId,
        multiaddr: Multiaddr,
    ) {
        println!("[LOCAL] Routing updated with peer: {:?}", peer);
        if let Err(e) = swarm.dial(peer) {
            println!("[LOCAL] Failed to dial peer {:?}", e);
        }
        swarm
            .behaviour_mut()
            .kad
            .add_address(&peer, multiaddr.clone());
        swarm.add_peer_address(peer, multiaddr);

        let state = state_arc.lock().unwrap();
        let is_bootstrap = state.is_bootstrap;
        let threshold = state.threshold;
        let bootstrap_username = state.username.clone();
        std::mem::drop(state);

        if is_bootstrap {
            let result: Vec<&PeerId> = swarm.connected_peers().collect();
            if result.len() > threshold {
                if let Err(e) = handle_username_update(state_arc.clone(), swarm, bootstrap_username)
                {
                    println!("[BOOTSTRAP] Error updating username in DHT: {:?}", e);
                }
            }
        }
    }

    fn remove_peer(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        peer: PeerId,
        multiaddr: Multiaddr,
    ) -> Result<(), Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();
        swarm.behaviour_mut().kad.remove_address(&peer, &multiaddr);

        let username_peer_id_map = state.username_to_peer_id.clone();
        for (k, v) in username_peer_id_map.iter() {
            if v.clone() == peer.clone() {
                swarm
                    .behaviour_mut()
                    .kad
                    .remove_record(&RecordKey::new(&format!("/peer_id/{}", k)));
                state.username_to_peer_id.remove(k);
            }
        }

        Ok(())
    }

    struct TauriState(
        Arc<Mutex<NodeState>>,
        tokio::sync::mpsc::Sender<TauriToRustCommand>,
    );

    #[tauri::command]
    fn get_peer_id(state: State<TauriState>) -> String {
        let node_state = state.0.lock().unwrap();
        node_state.peer_id.to_string()
    }

    #[tauri::command]
    fn get_peers(state: State<TauriState>) -> Vec<String> {
        let node_state = state.0.lock().unwrap();
        return Vec::from_iter(node_state.username_to_peer_id.keys().map(|v| v.to_string()));
    }

    #[tauri::command]
    fn get_threshold(state: State<TauriState>) -> i32 {
        let node_state = state.0.lock().unwrap();
        node_state.threshold.try_into().unwrap()
    }

    fn save_local_envelope(
        username: String,
        password: String,
        opaque_keypair: Keypair,
    ) -> Result<(), String> {
        let file_path = format!("tmp/{username}_login.envelope");
        if Path::new(&file_path).exists() {
            return Err("Encrypted envelope already exists".to_string());
        }
        if let Err(e) = fs::create_dir_all("tmp") {
            return Err(e.to_string());
        }
        let file = fs::File::create(file_path);
        if let Err(e) = file {
            return Err(e.to_string());
        }
        let envelope = LocalEnvelope {
            keypair: opaque_keypair.clone(),
            username,
        };
        let encrypted_envelope = envelope.clone().encrypt_w_password(password.clone());
        if let Err(e) = encrypted_envelope {
            return Err(e.to_string());
        }
        let serialized_envelope = serde_json::to_string(&encrypted_envelope.unwrap());
        if let Err(e) = serialized_envelope {
            return Err(e.to_string());
        }
        let result = file
            .unwrap()
            .write_all(serialized_envelope.unwrap().as_bytes());
        if let Err(e) = result {
            return Err(e.to_string());
        }
        Ok(())
    }

    #[tauri::command]
    fn tauri_save_local_envelope(state: State<TauriState>, password: String) -> Result<(), String> {
        let node_state = state.0.lock().unwrap();
        save_local_envelope(
            node_state.username.clone(),
            password,
            node_state.opaque_keypair.clone(),
        )
    }

    #[tauri::command]
    fn local_register(
        state: State<TauriState>,
        username: String,
        password: String,
        recovery_addresses: HashMap<String, i32>,
        threshold: usize,
    ) -> Result<(), String> {
        let mut node_state = state.0.lock().unwrap();
        node_state.username = username.clone();
        node_state.opaque_keypair = Keypair::new();
        // TODO
        /*save_local_envelope(
            username.clone(),
            password.clone(),
            node_state.opaque_keypair.clone(),
        )?;*/

        let tx_clone = state.1.clone();
        let username = node_state.username.clone();
        let password_clone = password.clone();
        tauri::async_runtime::spawn(async move {
            tx_clone
                .send(TauriToRustCommand::RegStart(
                    username,
                    password_clone,
                    recovery_addresses,
                    threshold,
                ))
                .await
                .unwrap();
        });
        Ok(())
    }

    #[tauri::command]
    fn local_login(
        state: State<TauriState>,
        username: String,
        password: String,
    ) -> Result<bool, String> {
        let mut node_state = state.0.lock().unwrap();
        let file_path = format!("tmp/{username}_login.envelope");
        if !Path::new(&file_path).exists() {
            return Err("Encrypted envelope does not exist".to_string());
        }
        let contents = std::fs::read_to_string(file_path);
        if let Err(e) = contents {
            return Err(e.to_string());
        }
        let encrypted_envelope: Result<LocalEncryptedEnvelope, _> =
            serde_json::from_str(&contents.unwrap());
        if let Err(e) = encrypted_envelope {
            return Err(e.to_string());
        }
        let envelope = encrypted_envelope.unwrap().decrypt_w_password(password);
        if let Err(e) = envelope {
            return Err(e.to_string());
        }
        let envelope = envelope.unwrap();
        if envelope.username != username {
            return Ok(false);
        }
        node_state.username = username;
        Ok(true)
    }

    #[tauri::command]
    fn save_notepad(state: State<TauriState>, notepad: String) -> Result<(), String> {
        let node_state = state.0.lock().unwrap();
        let mut hasher = Sha3_256::new();
        hasher.update(node_state.opaque_keypair.private_key);
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, notepad.as_bytes());
        if let Err(e) = ciphertext {
            return Err("Encryption of notepad failed: ".to_string() + &e.to_string());
        }
        let ciphertext = ciphertext.unwrap();
        let encrypted_notepad = EncryptedTauriNotepad {
            encrypted_contents: ciphertext,
            nonce: nonce_bytes,
        };
        let serialized_ciphertext = serde_json::to_string(&encrypted_notepad);
        if let Err(e) = serialized_ciphertext {
            return Err(e.to_string());
        }
        let file_path = format!("tmp/{}_notepad.txt", node_state.username);
        if let Err(e) = fs::create_dir_all("tmp") {
            return Err(e.to_string());
        }
        let file = fs::File::create(file_path);
        if let Err(e) = file {
            return Err(e.to_string());
        }
        let result = file
            .unwrap()
            .write_all(serialized_ciphertext.unwrap().as_bytes());
        if let Err(e) = result {
            return Err(e.to_string());
        }
        Ok(())
    }

    #[tauri::command]
    fn read_notepad(state: State<TauriState>) -> Result<String, String> {
        let node_state = state.0.lock().unwrap();
        let file_path = format!("tmp/{}_notepad.txt", node_state.username);
        if !Path::new(&file_path).exists() {
            return Ok("".to_string());
        }
        let contents = std::fs::read_to_string(file_path);
        if let Err(e) = contents {
            return Err(e.to_string());
        }
        let encrypted_notepad: Result<EncryptedTauriNotepad, _> =
            serde_json::from_str(&contents.unwrap());
        if let Err(e) = encrypted_notepad {
            return Err(e.to_string());
        }
        let encrypted_notepad = encrypted_notepad.unwrap();
        let mut hasher = Sha3_256::new();
        hasher.update(node_state.opaque_keypair.private_key);
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = Nonce::from_slice(&encrypted_notepad.nonce);

        let plaintext_bytes = cipher.decrypt(nonce, encrypted_notepad.encrypted_contents.as_ref());
        if let Err(e) = plaintext_bytes {
            return Err("Decryption failed: ".to_string() + &e.to_string());
        }
        let plaintext_bytes = plaintext_bytes.unwrap();
        let notepad = std::str::from_utf8(&plaintext_bytes);
        if let Err(e) = notepad {
            return Err(e.to_string());
        }
        Ok(notepad.unwrap().to_string())
    }

    #[tauri::command]
    fn set_username(state: State<TauriState>, username: String) {
        let mut node_state = state.0.lock().unwrap();
        node_state.username = username.clone();
        node_state.opaque_node.id = username;
    }

    #[tauri::command]
    fn local_recovery(
        state: State<TauriState>,
        username: String,
        password: String,
        recovery_nodes: HashMap<String, i32>,
    ) -> Result<(), String> {
        let mut node_state = state.0.lock().unwrap();
        node_state.username = username.clone();
        node_state.opaque_node.id = username.clone();
        let tx_clone = state.1.clone();
        tauri::async_runtime::spawn(async move {
            tx_clone
                .send(TauriToRustCommand::RecoveryStart(
                    username,
                    password,
                    recovery_nodes,
                ))
                .await
                .unwrap();
        });
        Ok(())
    }

    #[tauri::command]
    fn local_refresh(
        state: State<TauriState>,
        new_recovery_addresses: HashMap<String, i32>,
        new_threshold: i32,
    ) -> Result<(), String> {
        let tx_clone = state.1.clone();
        tauri::async_runtime::spawn(async move {
            tx_clone
                .send(TauriToRustCommand::RefreshStart(
                    new_recovery_addresses,
                    new_threshold,
                ))
                .await
                .unwrap();
        });
        Ok(())
    }

    fn handle_kad_inbound_request(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        record: Record,
    ) {
        let mut state = state_arc.lock().unwrap();

        let deserialized_record: KadRecord =
            serde_json::from_slice(record.value.as_slice()).unwrap();
        let query_id = swarm
            .behaviour_mut()
            .kad
            .get_record(RecordKey::new(&format!(
                "/pk/{}",
                deserialized_record.username
            )));

        println!(
            "[KAD] Received inbound request for {:?}, putting at query ID {:?}",
            record.clone().key,
            query_id
        );
        state.kad_filtering.insert(query_id, record.clone());
    }

    fn handle_kad_found_record(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        pk_record: PeerRecord,
        query_id: QueryId,
    ) {
        let mut state = state_arc.lock().unwrap();

        let kad_filtering = state.kad_filtering.clone();
        let actual_record = kad_filtering.get(&query_id).unwrap();
        let deserialized_pk_record: KadRecord =
            serde_json::from_slice(pk_record.record.value.as_slice()).unwrap();
        let deserialized_actual_record: KadRecord =
            serde_json::from_slice(actual_record.value.as_slice()).unwrap();
        // shouldn't be any other record type
        if let KadRecordType::Pk(public_key) = deserialized_pk_record.data {
            let mut signature_message = actual_record.key.to_vec();
            signature_message.extend(deserialized_actual_record.signed_data());
            if deserialized_actual_record
                .signature
                .verify(signature_message.as_slice(), public_key)
            {
                if let Err(e) = swarm
                    .behaviour_mut()
                    .kad
                    .store_mut()
                    .put(actual_record.clone())
                {
                    println!(
                        "[KAD] Found, could not store final record {:?}",
                        &e.to_string(),
                    );
                } else {
                    println!(
                        "[KAD] Found, stored final record {:?}",
                        actual_record.clone().key
                    );
                    state.kad_filtering.remove(&query_id);
                    match deserialized_actual_record.data {
                        KadRecordType::Pk(public_key) => {
                            state
                                .username_to_opaque_pkey
                                .insert(deserialized_actual_record.username.clone(), public_key);
                        }
                        KadRecordType::RecvAddr(recv_addrs, threshold) => {
                            state.username_to_index = recv_addrs;
                            state.threshold = threshold;
                        }
                        KadRecordType::PeerId(peer_id) => {
                            let username_peer_id_map = state.username_to_peer_id.clone();
                            for (k, v) in username_peer_id_map.iter() {
                                if v.clone() == peer_id.clone() {
                                    state.username_to_peer_id.remove(k);
                                }
                            }
                            state.username_to_peer_id.insert(
                                deserialized_actual_record.username.clone(),
                                actual_record.publisher.unwrap(),
                            );

                            let queued_msgs_option = state
                                .waiting_for_peer_id
                                .get(&deserialized_actual_record.username);
                            if let Some(queued_msgs) = queued_msgs_option {
                                for msg in queued_msgs.iter() {
                                    swarm
                                        .behaviour_mut()
                                        .request_response
                                        .send_request(&peer_id, msg.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn handle_kad_no_add_record(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        query_id: QueryId,
    ) {
        let mut state = state_arc.lock().unwrap();

        let kad_filtering = state.kad_filtering.clone();
        let actual_record = kad_filtering.get(&query_id).unwrap();
        if let Err(e) = swarm
            .behaviour_mut()
            .kad
            .store_mut()
            .put(actual_record.clone())
        {
            println!(
                "[KAD] DNF, could not store final record {:?}",
                &e.to_string(),
            );
        } else {
            println!(
                "[KAD] DNF, stored final record {:?}",
                actual_record.clone().key
            );
            state.kad_filtering.remove(&query_id);

            std::mem::drop(state);
            let deserialized_actual_record: KadRecord =
                serde_json::from_slice(actual_record.value.as_slice()).unwrap();
            handle_kad_data_store_emit(
                state_arc.clone(),
                swarm,
                deserialized_actual_record,
                actual_record.clone(),
            );
        }
    }

    tauri::async_runtime::set(tokio::runtime::Handle::current());
    tauri::Builder::default()
            .invoke_handler(tauri::generate_handler![
                get_peer_id,
                local_register,
                local_login,
                read_notepad,
                save_notepad,
                get_peers,
                get_threshold,
                set_username,
                local_recovery,
                local_refresh,
                tauri_save_local_envelope
            ])
            .manage(TauriState(Arc::clone(&state_arc), tx))
            .setup(move |app| {
                let main_window = app.get_webview_window("main").unwrap();
                if is_bootstrap {
                    main_window.hide()?;
                }

                pass_tauri_handle(state_arc.clone(), app.handle().clone());
                tauri::async_runtime::spawn(async move {
                    loop {
                        select! {
                            Some(res) = rx.recv() => match res {
                                TauriToRustCommand::RegStart(username, password, recovery_nodes, threshold) => {
                                    handle_username_update(state_arc.clone(), &mut swarm, username).unwrap();
                                    handle_reg_init(state_arc.clone(), &mut swarm, password, recovery_nodes, threshold).unwrap();
                                }
                                TauriToRustCommand::RecoveryStart(username, password, recovery_nodes) => {
                                    handle_username_update(state_arc.clone(), &mut swarm, username.clone()).unwrap();
                                    handle_recovery_init(state_arc.clone(), &mut swarm, username, password, recovery_nodes).unwrap();
                                }
                                TauriToRustCommand::RefreshStart(recovery_nodes, new_threshold) => {
                                    handle_refresh_init(state_arc.clone(), &mut swarm, recovery_nodes, new_threshold as usize).unwrap();
                                }
                            },
                            event = swarm.select_next_some() => match event {
                                SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                                    for (peer, multiaddr) in list {
                                        add_peer(state_arc.clone(), &mut swarm, peer, multiaddr);
                                    }
                                },
                                SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                                    for (peer, multiaddr) in list {
                                        remove_peer(state_arc.clone(), &mut swarm, peer, multiaddr).unwrap();
                                    }
                                },
                                SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, is_new_peer, .. })) => {
                                    println!("[KAD] Peer routing updated with peer {:?} ({:?})", peer, is_new_peer);
                                },
                                SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::InboundRequest { request })) => {
                                     if let InboundRequest::PutRecord { record, .. } = request.clone() {
                                        handle_kad_inbound_request(state_arc.clone(), &mut swarm, record.unwrap());
                                     }
                                },
                                SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result, step, .. })) => {
                                    if step.last {
                                        if let QueryResult::GetRecord(r) = result.clone() {
                                            match r {
                                                Ok(GetRecordOk::FoundRecord(r_ok)) => handle_kad_found_record(state_arc.clone(), &mut swarm, r_ok, id),
                                                Ok(GetRecordOk::FinishedWithNoAdditionalRecord{ .. }) => handle_kad_no_add_record(state_arc.clone(), &mut swarm, id),
                                                Err(_) => {},
                                            }
                                        }
                                        match result {
                                            kad::QueryResult::PutRecord(Ok(kad::PutRecordOk { key })) => {
                                                println!(
                                                    "[KAD] Successfully put record {:?}",
                                                    std::str::from_utf8(key.as_ref()).unwrap()
                                                );
                                            },
                                            kad::QueryResult::PutRecord(Err(err)) => {
                                                eprintln!("[KAD] Failed to put record: {err:?}");
                                            },
                                            _ => {}
                                        }
                                    }
                                },
                                SwarmEvent::Behaviour(P2PBehaviourEvent::RequestResponse(
                                    request_response::Event::Message { message, peer },
                                )) => match message {
                                    request_response::Message::Request { request, channel, .. } => {
                                        handle_request(state_arc.clone(), &mut swarm, peer, request, channel).unwrap();
                                    }
                                    request_response::Message::Response { response, .. } => {
                                        handle_response(state_arc.clone(), &mut swarm, peer, response).unwrap();
                                    }
                                },
                                SwarmEvent::NewListenAddr { address, .. } => {
                                    println!("[LOCAL] Node peer ID: {address}");
                                },
                                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                    println!("[LOCAL] Connection with {} established", peer_id);
                                },
                                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                                    println!("[LOCAL] Connection with {} closed because {}", peer_id, cause.unwrap());
                                },
                                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                                    println!("[LOCAL] Connection with {} closed because error {:?}", peer_id.unwrap(), error);
                                },
                                SwarmEvent::ListenerError { error, .. } => {
                                    println!("[LOCAL] Listener error {:?}", error);
                                },
                                _ => {}
                            }
                        }
                    }
                });

                Ok(())
            })
            .run(tauri::generate_context!())
            .expect("Error while running Tauri application");

    Ok(())
}
