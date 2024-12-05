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
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{gossipsub, identify, kad, mdns, PeerId, Swarm};
use libp2p::{
    gossipsub::TopicHash,
    kad::{store::MemoryStore, GetRecordOk, PeerRecord},
};
use libp2p::{
    gossipsub::{IdentTopic, Message},
    kad::QueryResult,
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
use std::env;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::num::NonZeroUsize;
use std::ops::Add;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};
use tauri::{Manager, State};
use tokio::{io, select, sync::mpsc};
use util::i32_to_scalar;

// --- state structs --- //

#[derive(Debug, Clone)]
struct NodeState {
    peer_id: PeerId,
    username: String,
    opaque_keypair: Keypair,
    libp2p_keypair_bytes: [u8; 64],
    threshold: usize,
    peer_id_to_index: HashMap<PeerId, i32>, // this node's recovery nodes' indices
    point_to_point_topics: HashMap<PeerId, IdentTopic>,
    tx: tokio::sync::mpsc::Sender<TauriToRustCommand>,
    acss_inputs: ACSSInputs,
    opaque_node: P2POpaqueNode,
    peer_recoveries: HashMap<PeerId, (ACSSNodeShare, i32)>, // the indices for nodes for which this node
    // is a recovery node
    phi_polynomials: Option<(Polynomial, Polynomial)>,
    registration_received: Option<HashMap<PeerId, RegStartResponse>>,
    recovery_received: Option<HashMap<PeerId, LoginStartResponse>>,
    reshare_received: Option<HashMap<PeerId, (ACSSNodeShare, ACSSNodeShare)>>,
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

#[derive(Serialize, Deserialize, Debug)]
struct OPRFRegInitMessage {
    inputs: ACSSInputs,
    reg_start_req: RegStartRequest,
    dealer_shares: HashMap<PeerId, ACSSDealerShare>,
    dealer_key: PublicKey,
    user_id: PeerId,
    node_index: i32,
    node_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct OPRFRegStartRespMessage {
    reg_start_resp: RegStartResponse,
    user_id: PeerId,
    node_index: i32,
    node_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct OPRFRegFinishReqMessage {
    reg_finish_req: RegFinishRequest,
    user_id: PeerId,
    node_index: i32,
    node_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct OPRFRecoveryStartReqMessage {
    recovery_start_req: LoginStartRequest,
    other_indices: HashSet<i32>,
    user_id: PeerId,
    node_index: i32,
    node_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct OPRFRecoveryStartRespMessage {
    recovery_start_resp: LoginStartResponse,
    user_id: PeerId,
    node_index: i32,
    node_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct DPSSRefreshInitMessage {
    new_recovery_addresses: HashMap<PeerId, i32>,
    new_threshold: usize,
    user_id: PeerId,
    node_index: i32,
    node_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct DPSSRefreshReshareMessage {
    inputs: ACSSInputs,
    dealer_shares: HashMap<PeerId, ACSSDealerShare>,
    dealer_shares_hat: HashMap<PeerId, ACSSDealerShare>,
    commitments: HashMap<Scalar, RistrettoPoint>,
    dealer_key: PublicKey,
    new_threshold: usize,
    user_id: PeerId,
    node_index: i32,
    node_id: PeerId,
}

#[derive(Serialize, Deserialize)]
enum BroadcastMessage {
    OPRFRegInitMessage(OPRFRegInitMessage),
    OPRFRegStartRespMessage(OPRFRegStartRespMessage),
    OPRFRegFinishReqMessage(OPRFRegFinishReqMessage),
    OPRFRecoveryStartReqMessage(OPRFRecoveryStartReqMessage),
    OPRFRecoveryStartRespMessage(OPRFRecoveryStartRespMessage),
    DPSSRefreshInitMessage(DPSSRefreshInitMessage),
    DPSSRefreshReshareMessage(DPSSRefreshReshareMessage),
}

#[derive(NetworkBehaviour)]
struct P2PBehaviour {
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

enum TauriToRustCommand {
    RegStart(
        libp2p::identity::ed25519::Keypair,
        String,
        String,
        HashMap<PeerId, i32>,
    ),
    RecoveryStart(String, String, HashMap<PeerId, i32>),
    RefreshStart(HashMap<PeerId, i32>, i32),
    NewSwarm(libp2p::identity::ed25519::Keypair, String),
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedTauriNotepad {
    encrypted_contents: Vec<u8>,
    nonce: [u8; 12],
}

fn new_swarm(
    keypair: libp2p::identity::ed25519::Keypair,
    username: String,
) -> Result<Swarm<P2PBehaviour>, Box<dyn Error>> {
    let libp2p_keypair = libp2p::identity::Keypair::from(keypair);
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(libp2p_keypair.clone())
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::tls::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let message_id_fn = |message: &gossipsub::Message| {
                let mut hasher = Sha3_256::new();
                hasher.update(message.data.clone());
                hasher.update(message.source.unwrap().to_bytes());
                let message_hash = hasher.finalize();
                gossipsub::MessageId::from(format!("{:X}", message_hash))
            };

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .mesh_outbound_min(0)
                .mesh_n_low(0)
                .mesh_n(1)
                .message_id_fn(message_id_fn)
                .build()
                .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let kad = kad::Behaviour::new(
                key.public().to_peer_id(),
                kad::store::MemoryStore::new(key.public().to_peer_id()),
            );

            let identify = identify::Behaviour::new(identify::Config::new(
                "/ipfs/id/1.0.0".to_string(),
                key.public(),
            ));

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;

            Ok(P2PBehaviour {
                gossipsub,
                kad,
                identify,
                mdns,
            })
        })?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(std::time::Duration::from_secs(u64::MAX))
        })
        .build();
    if &username != "" {
        swarm
            .behaviour_mut()
            .kad
            .get_record(libp2p::kad::RecordKey::new(&Vec::from(username.as_bytes())));
    }
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
        peer_id: PeerId::random(),        // temp
        peer_id_to_index: HashMap::new(), // temp
        username: "".to_string(),         // temp
        opaque_keypair: Keypair::new(),
        libp2p_keypair_bytes: [0u8; 64],
        point_to_point_topics: HashMap::new(),
        tx: tx.clone(),
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
        threshold: 1,
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
        let file_path = format!("tmp/bootstrap_0.envelope");
        if Path::new(&file_path).exists() {
            let parsed_index: i32 = args[2].parse()?;
            let file_path = format!("tmp/bootstrap_{}.envelope", parsed_index);
            let contents = std::fs::read_to_string(file_path);
            let bootstrap_node_state: BootstrapNodeState =
                serde_json::from_str(&contents.unwrap())?;

            state.username = format!("bootstrap{parsed_index}");
            bootstrap_username = state.username.clone();
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
                    bootstrap_username = state.username.clone();
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

    let mut swarm = new_swarm(bootstrap_keypair, bootstrap_username)?;

    fn handle_message(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        message: Message,
    ) -> Result<(), Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();
        if let Some(s) = message.source {
            if s == state.peer_id {
                return Ok(());
            }
        }
        let message_data: BroadcastMessage =
            serde_json::from_slice(message.data.as_slice()).unwrap();

        match message_data {
            BroadcastMessage::OPRFRegInitMessage(msg) => {
                handle_message_reg_init(&mut state, swarm, peer_id, msg)
            }
            BroadcastMessage::OPRFRegStartRespMessage(msg) => {
                handle_message_reg_start_resp(&mut state, swarm, peer_id, msg)
            }
            BroadcastMessage::OPRFRegFinishReqMessage(msg) => {
                handle_message_reg_finish_req(&mut state, swarm, peer_id, msg)?;
                update_peer_ids_kademlia_record(state_arc.clone(), swarm)
            }
            BroadcastMessage::OPRFRecoveryStartReqMessage(msg) => {
                handle_message_rec_start_req(&mut state, swarm, peer_id, msg)
            }
            BroadcastMessage::OPRFRecoveryStartRespMessage(msg) => {
                handle_message_rec_start_resp(&mut state, swarm, peer_id, msg)
            }
            BroadcastMessage::DPSSRefreshInitMessage(msg) => {
                handle_message_dpss_init(&mut state, swarm, peer_id, msg)
            }
            BroadcastMessage::DPSSRefreshReshareMessage(msg) => {
                handle_message_dpss_reshare(&mut state, swarm, peer_id, msg)?;
                update_peer_ids_kademlia_record(state_arc.clone(), swarm)
            }
        }
    }

    fn handle_reg_init(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        password: String,
        recovery_addresses: HashMap<PeerId, i32>,
    ) -> Result<NodeState, Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();

        let s = Scalar::random(&mut OsRng);
        let (acss_dealer_share, phi, phi_hat) = ACSS::share_dealer(
            state.acss_inputs.clone(),
            s,
            state.acss_inputs.degree,
            state.opaque_keypair.private_key,
        )?;
        state.phi_polynomials = Some((phi, phi_hat));
        state.registration_received = Some(HashMap::new());

        let reg_start_req = state.opaque_node.local_registration_start(password)?;

        for (address, index) in recovery_addresses.iter() {
            state
                .peer_id_to_index
                .insert(address.clone(), index.clone());
            let topic = state.point_to_point_topics.get(&address).unwrap().clone();

            let subscribed: HashSet<TopicHash> = swarm
                .behaviour_mut()
                .gossipsub
                .topics()
                .map(|x| x.clone())
                .collect();
            let connected_peers: HashSet<&PeerId> = swarm.connected_peers().collect();
            println!("[DEBUG] {:?} {:?} {:?}", topic, subscribed, connected_peers);

            let init_message =
                serde_json::to_vec(&BroadcastMessage::OPRFRegInitMessage(OPRFRegInitMessage {
                    inputs: state.acss_inputs.clone(),
                    reg_start_req: reg_start_req.clone(),
                    dealer_shares: acss_dealer_share
                        .iter()
                        .map(|(k, v)| (PeerId::from_str(k).unwrap(), v.clone()))
                        .collect(),
                    dealer_key: state.opaque_keypair.public_key,
                    user_id: state.peer_id,
                    node_index: index.clone(),
                    node_id: address.clone(),
                }))
                .unwrap();
            let message_id = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic.clone(), init_message);
            if let Err(e) = message_id {
                println!("[INIT] Publish error: {e:?}");
            } else {
                println!(
                    "[INIT] Sending ACSS share messages for user {}",
                    state.username
                );
            }
        }

        update_peer_ids(state_arc.clone())?;
        update_peer_ids_kademlia_record(state_arc.clone(), swarm)?;

        Ok(state.clone())
    }

    fn handle_message_reg_init(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        message: OPRFRegInitMessage,
    ) -> Result<(), Box<dyn Error>> {
        let node_share = ACSS::share(
            message.inputs.clone(),
            message.dealer_shares.get(&state.peer_id).unwrap().clone(),
            state.opaque_keypair.clone(),
            message.dealer_key,
        )?;

        state
            .peer_recoveries
            .insert(peer_id, (node_share.clone(), message.node_index));

        let topic = state
            .point_to_point_topics
            .get(&message.user_id)
            .unwrap()
            .clone();
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
        let reg_start_resp_message = serde_json::to_vec(
            &BroadcastMessage::OPRFRegStartRespMessage(OPRFRegStartRespMessage {
                reg_start_resp,
                user_id: message.user_id.clone(),
                node_index: message.node_index,
                node_id: state.peer_id,
            }),
        )
        .unwrap();
        if let Err(e) = swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), reg_start_resp_message)
        {
            println!("[REG INIT] Publish error: {e:?}");
        } else {
            println!(
                "[REG INIT] Published acknowledgement message for user at peer ID {}",
                message.user_id
            );
        }

        Ok(())
    }

    fn handle_message_reg_start_resp(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        message: OPRFRegStartRespMessage,
    ) -> Result<(), Box<dyn Error>> {
        if let None = state.registration_received {
            return Ok(());
        }

        let mut s = state.registration_received.take().unwrap();
        s.insert(peer_id, message.reg_start_resp);

        if s.len() < state.threshold {
            state.registration_received = Some(s);
            return Ok(());
        }

        let reg_finish_reqs = state.opaque_node.local_registration_finish(
            state.libp2p_keypair_bytes,
            s.values().map(|v| v.clone()).collect(),
            state.threshold,
        )?;
        for reg_finish_req in reg_finish_reqs.iter() {
            let index = state.peer_id_to_index.get(&peer_id).unwrap().clone();
            let reg_finish_req_message = serde_json::to_vec(
                &BroadcastMessage::OPRFRegFinishReqMessage(OPRFRegFinishReqMessage {
                    reg_finish_req: reg_finish_req.clone(),
                    user_id: state.peer_id,
                    node_index: index,
                    node_id: peer_id,
                }),
            )
            .unwrap();
            let topic = state
                .point_to_point_topics
                .get(&PeerId::from_str(&reg_finish_req.peer_id).unwrap())
                .unwrap()
                .clone();
            let message_id = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic.clone(), reg_finish_req_message);
            if let Err(e) = message_id {
                println!("[REG START RESP] Publish error: {e:?}");
            } else {
                println!(
                    "[REG START RESP] Sending reg start finish message for user {} at index {}",
                    state.username, index
                );
            }
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
            message.user_id
        );

        Ok(())
    }

    fn handle_recovery_init(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        username: String,
        password: String,
        recovery_addresses: HashMap<PeerId, i32>,
    ) -> Result<NodeState, Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();
        state.username = username;
        state.recovery_received = Some(HashMap::new());

        let recovery_start_req = state.opaque_node.local_login_start(password)?;

        let other_indices: HashSet<i32> = recovery_addresses
            .clone()
            .values()
            .map(|v| v.clone())
            .collect();
        for (address, index) in recovery_addresses.iter() {
            let topic = state.point_to_point_topics.get(&address).unwrap().clone();
            let login_start_req = serde_json::to_vec(
                &BroadcastMessage::OPRFRecoveryStartReqMessage(OPRFRecoveryStartReqMessage {
                    recovery_start_req: recovery_start_req.clone(),
                    other_indices: other_indices.clone(),
                    user_id: state.peer_id,
                    node_index: index.clone(),
                    node_id: address.clone(),
                }),
            )
            .unwrap();
            let message_id = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic.clone(), login_start_req);
            if let Err(e) = message_id {
                println!("[REC INIT] Publish error: {e:?}");
            } else {
                println!(
                    "[REC INIT] Sending initial req for user {} at index {}",
                    state.username, index
                );
            }
        }

        Ok(state.clone())
    }

    fn handle_message_rec_start_req(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        _peer_id: PeerId,
        message: OPRFRecoveryStartReqMessage,
    ) -> Result<(), Box<dyn Error>> {
        let rec_start_resp = state.opaque_node.peer_login_start(
            message.recovery_start_req,
            message.node_index,
            message.other_indices,
        )?;
        let rec_start_resp_message = serde_json::to_vec(
            &BroadcastMessage::OPRFRecoveryStartRespMessage(OPRFRecoveryStartRespMessage {
                recovery_start_resp: rec_start_resp,
                user_id: message.user_id.clone(),
                node_index: message.node_index,
                node_id: state.peer_id,
            }),
        )
        .unwrap();
        let topic = state
            .point_to_point_topics
            .get(&message.user_id)
            .unwrap()
            .clone();
        if let Err(e) = swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), rec_start_resp_message)
        {
            println!("[REC START REQ] Publish error: {e:?}");
        } else {
            println!(
                "[REC START REQ] Published acknowledgement message for user at peer ID {}",
                message.user_id
            );
        }

        Ok(())
    }

    fn handle_message_rec_start_resp(
        state: &mut NodeState,
        _swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        message: OPRFRecoveryStartRespMessage,
    ) -> Result<(), Box<dyn Error>> {
        if let None = state.recovery_received {
            return Ok(());
        }

        let mut s = state.recovery_received.take().unwrap();
        s.insert(peer_id, message.recovery_start_resp);

        if s.len() < state.threshold {
            state.recovery_received = Some(s);
            return Ok(());
        }

        let (opaque_keypair, libp2p_keypair_bytes) = state
            .opaque_node
            .local_login_finish(s.values().map(|v| v.clone()).collect())?;
        state.opaque_keypair = opaque_keypair.clone();
        state.libp2p_keypair_bytes = libp2p_keypair_bytes;

        let libp2p_keypair =
            libp2p::identity::ed25519::Keypair::try_from_bytes(&mut libp2p_keypair_bytes.clone())?;
        let new_peer_id =
            PeerId::from_public_key(&(libp2p::identity::PublicKey::from(libp2p_keypair.public())));
        update_with_peer_id(
            state,
            opaque_keypair,
            libp2p_keypair_bytes,
            state.tx.clone(),
            new_peer_id,
        )?;

        Ok(())
    }

    fn handle_refresh_init(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        new_recovery_addresses: HashMap<PeerId, i32>,
        new_threshold: usize,
    ) -> Result<NodeState, Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();
        if new_threshold + 1 > new_recovery_addresses.len() {
            return Err(Box::from(
                "Not enough recovery addresses for this threshold",
            ));
        }
        for (address, index) in state.peer_id_to_index.iter() {
            let topic = state.point_to_point_topics.get(&address).unwrap();
            let init_message = serde_json::to_vec(&BroadcastMessage::DPSSRefreshInitMessage(
                DPSSRefreshInitMessage {
                    new_recovery_addresses: new_recovery_addresses.clone(),
                    new_threshold,
                    user_id: state.peer_id,
                    node_index: index.clone(),
                    node_id: address.clone(),
                },
            ))
            .unwrap();
            let message_id = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic.clone(), init_message);
            if let Err(e) = message_id {
                println!("[DPSS INIT] Publish error: {e:?}");
            } else {
                println!(
                    "[DPSS INIT] Sending init message for user {}",
                    state.username
                );
            }
        }

        state.peer_id_to_index = new_recovery_addresses;

        Ok(state.clone())
    }

    fn handle_message_dpss_init(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        message: DPSSRefreshInitMessage,
    ) -> Result<(), Box<dyn Error>> {
        let (node_share, _) = state.peer_recoveries.get(&peer_id).unwrap();
        let (acss_dealer_share_s, _, _) = ACSS::share_dealer(
            state.acss_inputs.clone(),
            node_share.s_i_d,
            message.new_recovery_addresses.len() - 1,
            state.opaque_keypair.private_key,
        )?;

        let (acss_dealer_share_s_hat, _, _) = ACSS::share_dealer(
            state.acss_inputs.clone(),
            node_share.s_hat_i_d,
            message.new_recovery_addresses.len() - 1,
            state.opaque_keypair.private_key,
        )?;

        let old_commitments: HashMap<Scalar, RistrettoPoint> = state
            .peer_recoveries
            .iter()
            .map(|(_, v)| (i32_to_scalar(v.1), v.0.c_i.clone()))
            .collect();

        for (address, index) in message.new_recovery_addresses.iter() {
            let topic = state.point_to_point_topics.get(&address).unwrap().clone();
            let reshare_msg = serde_json::to_vec(&BroadcastMessage::DPSSRefreshReshareMessage(
                DPSSRefreshReshareMessage {
                    inputs: state.acss_inputs.clone(),
                    dealer_shares: acss_dealer_share_s
                        .iter()
                        .map(|(k, v)| (PeerId::from_str(k).unwrap(), v.clone()))
                        .collect(),
                    dealer_shares_hat: acss_dealer_share_s_hat
                        .iter()
                        .map(|(k, v)| (PeerId::from_str(k).unwrap(), v.clone()))
                        .collect(),
                    dealer_key: state.opaque_keypair.private_key,
                    new_threshold: message.new_threshold,
                    commitments: old_commitments.clone(),
                    user_id: state.peer_id,
                    node_index: index.clone(),
                    node_id: address.clone(),
                },
            ))
            .unwrap();
            let message_id = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic.clone(), reshare_msg);
            if let Err(e) = message_id {
                println!("[DPSS REFR INIT] Publish error: {e:?}");
            } else {
                println!(
                    "[DPSS REFR INIT] Sending initial ACSS reshares for user {} at index {}",
                    state.username, index
                );
            }
        }

        if !message.new_recovery_addresses.contains_key(&state.peer_id) {
            state.peer_recoveries.remove(&message.user_id);
        }

        Ok(())
    }

    fn handle_message_dpss_reshare(
        state: &mut NodeState,
        _swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        message: DPSSRefreshReshareMessage,
    ) -> Result<(), Box<dyn Error>> {
        let node_share = ACSS::share(
            message.inputs.clone(),
            message.dealer_shares.get(&state.peer_id).unwrap().clone(),
            state.opaque_keypair.clone(),
            message.dealer_key,
        )?;
        let node_share_hat = ACSS::share(
            message.inputs.clone(),
            message
                .dealer_shares_hat
                .get(&state.peer_id)
                .unwrap()
                .clone(),
            state.opaque_keypair.clone(),
            message.dealer_key,
        )?;

        let mut s: HashMap<PeerId, (ACSSNodeShare, ACSSNodeShare)>;
        if let None = state.reshare_received {
            s = HashMap::new();
        } else {
            s = state.reshare_received.take().unwrap();
        }

        s.insert(peer_id, (node_share, node_share_hat));

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
            peer_id,
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

    fn update_peer_ids(state_arc: Arc<Mutex<NodeState>>) -> Result<(), Box<dyn Error>> {
        let state = state_arc.lock().unwrap();
        let serialized_peers = serde_json::to_string(&(
            state.threshold,
            state.peer_id_to_index.clone(),
            state.peer_recoveries.clone(),
        ))?;
        let file_path = format!("tmp/{}_peers.list", state.username);
        let mut file = fs::File::create(file_path)?;
        file.write_all(serialized_peers.as_bytes())?;
        Ok(())
    }

    fn update_peer_ids_kademlia_record(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
    ) -> Result<(), Box<dyn Error>> {
        let state = state_arc.lock().unwrap();
        let serialized_peers =
            serde_json::to_vec(&(state.threshold, state.peer_id_to_index.clone()))?;
        let mut pk_record =
            kad::Record::new(Vec::from(state.username.as_bytes()), serialized_peers);
        pk_record.publisher = Some(*swarm.local_peer_id());
        pk_record.expires = Some(Instant::now().add(Duration::from_secs(86400)));

        swarm.behaviour_mut().kad.put_record(
            pk_record,
            kad::Quorum::N(NonZeroUsize::new(state.threshold).unwrap()),
        )?;

        Ok(())
    }

    fn add_peer(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        peer: PeerId,
    ) -> Result<(), Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();
        println!("[LOCAL] Routing updated with peer: {:?}", peer);
        if let Err(e) = swarm.dial(peer) {
            println!("[LOCAL] Failed to dial peer {:?}", e);
        }
        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
        if let None = state.point_to_point_topics.get(&peer) {
            let topic_name;
            if state.peer_id.to_string() < peer.to_string() {
                topic_name = format!("{}-{}", state.peer_id, peer);
            } else {
                topic_name = format!("{}-{}", peer, state.peer_id);
            }
            let topic = gossipsub::IdentTopic::new(topic_name);
            state.point_to_point_topics.insert(peer, topic.clone());
            swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
        }

        let subscribed: HashSet<TopicHash> = swarm
            .behaviour_mut()
            .gossipsub
            .topics()
            .map(|x| x.clone())
            .collect();
        println!("[DEBUG] [2] {:?}", subscribed);

        let connected_peers: HashSet<&PeerId> = swarm.connected_peers().collect();
        println!(
            "[DEBUG] [3] {:?} {:?}",
            swarm.is_connected(&peer),
            connected_peers
        );

        return Ok(());
    }

    fn remove_peer(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        peer: PeerId,
    ) -> Result<(), Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();
        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
        if let Some(topic) = state.point_to_point_topics.get(&peer) {
            swarm.behaviour_mut().gossipsub.unsubscribe(&topic)?;
            state.point_to_point_topics.remove(&peer);
        }
        Ok(())
    }

    fn resubscribe_topics(
        swarm: &mut Swarm<P2PBehaviour>,
        state_arc: Arc<Mutex<NodeState>>,
    ) -> Result<(), Box<dyn Error>> {
        let state = state_arc.lock().unwrap();
        for topic in state.point_to_point_topics.values() {
            swarm.behaviour_mut().gossipsub.subscribe(topic)?;
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
        return Vec::from_iter(
            node_state
                .point_to_point_topics
                .keys()
                .map(|v| v.to_string()),
        );
    }

    fn save_local_envelope(
        username: String,
        password: String,
        opaque_keypair: Keypair,
        libp2p_keypair_bytes: [u8; 64],
        peer_id: PeerId,
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
            libp2p_keypair_bytes,
            peer_public_key: (Scalar::ZERO * RISTRETTO_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
            peer_id: peer_id.to_string(),
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
            node_state.libp2p_keypair_bytes,
            node_state.peer_id,
        )
    }

    #[tauri::command]
    fn local_register(
        state: State<TauriState>,
        username: String,
        password: String,
        recovery_addresses: HashMap<String, i32>,
    ) -> Result<(), String> {
        let mut node_state = state.0.lock().unwrap();
        node_state.username = username.clone();
        node_state.opaque_keypair = Keypair::new();
        let libp2p_keypair = libp2p::identity::ed25519::Keypair::generate();
        save_local_envelope(
            username.clone(),
            password.clone(),
            node_state.opaque_keypair.clone(),
            libp2p_keypair.to_bytes(),
            node_state.peer_id,
        )?;

        let tx_clone = state.1.clone();
        let keypair = libp2p_keypair.clone();
        let username = node_state.username.clone();
        let password_clone = password.clone();
        let recovery_nodes: HashMap<PeerId, i32> = recovery_addresses
            .iter()
            .map(|(k, v)| (PeerId::from_str(k).unwrap(), v.clone()))
            .collect();
        tauri::async_runtime::spawn(async move {
            tx_clone
                .send(TauriToRustCommand::RegStart(
                    keypair,
                    username,
                    password_clone,
                    recovery_nodes,
                ))
                .await
                .unwrap();
        });
        Ok(())
    }

    fn update_with_peer_id(
        node_state: &mut NodeState,
        keypair: Keypair,
        libp2p_keypair_bytes: [u8; 64],
        tx: mpsc::Sender<TauriToRustCommand>,
        peer_id: PeerId,
    ) -> Result<(), String> {
        node_state.peer_id = peer_id;
        node_state.opaque_node.id = node_state.username.clone();
        println!(
            "[LOCAL] Username: {} + peer ID: {}",
            node_state.username, node_state.peer_id,
        );
        let libp2p_keypair =
            libp2p::identity::ed25519::Keypair::try_from_bytes(&mut libp2p_keypair_bytes.clone());
        if let Err(e) = libp2p_keypair {
            return Err(e.to_string());
        }
        node_state.opaque_keypair = keypair.clone();
        node_state.libp2p_keypair_bytes = libp2p_keypair_bytes;
        node_state.opaque_node.keypair = keypair;

        let mut refresh_username = "".to_string();
        if node_state.peer_id_to_index.len() == 0 {
            let file_path = format!("tmp/{}_peers.list", node_state.username);
            if Path::new(&file_path).exists() {
                let contents = std::fs::read_to_string(file_path);
                if let Err(e) = contents {
                    return Err(e.to_string());
                }
                let peers_list: Result<
                    (
                        usize,
                        HashMap<PeerId, i32>,
                        HashMap<PeerId, (ACSSNodeShare, i32)>,
                    ),
                    _,
                > = serde_json::from_str(&contents.unwrap());
                if let Err(e) = peers_list {
                    return Err(e.to_string());
                }
                let peers_list = peers_list.unwrap();
                node_state.threshold = peers_list.0;
                node_state.peer_id_to_index = peers_list.1;
                node_state.peer_recoveries = peers_list.2;
            } else {
                refresh_username = node_state.username.clone();
            }
        }

        if node_state.opaque_node.envelopes.len() == 0 {
            let file_path = format!("tmp/{}_envelopes.list", node_state.username);
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
                node_state.opaque_node.envelopes = envelopes_list.unwrap();
            }
        }

        tauri::async_runtime::spawn(async move {
            tx.send(TauriToRustCommand::NewSwarm(
                libp2p_keypair.unwrap(),
                refresh_username,
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
        let peer_id = PeerId::from_str(&envelope.peer_id);
        if let Err(e) = peer_id {
            return Err(e.to_string());
        } else {
            update_with_peer_id(
                &mut node_state,
                envelope.keypair,
                envelope.libp2p_keypair_bytes,
                state.1.clone(),
                peer_id.unwrap(),
            )?;
        }
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

    fn set_peer_ids(state_arc: Arc<Mutex<NodeState>>, result: PeerRecord) {
        let mut node_state = state_arc.lock().unwrap();
        let (threshold, peer_ids_map): (usize, HashMap<PeerId, i32>) =
            serde_json::from_slice(result.record.value.as_slice()).unwrap();
        node_state.peer_id_to_index = peer_ids_map;
        node_state.threshold = threshold;
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
        let recovery_nodes_map: HashMap<PeerId, i32> = recovery_nodes
            .iter()
            .map(|(k, v)| (PeerId::from_str(k).unwrap(), v.clone()))
            .collect();
        tauri::async_runtime::spawn(async move {
            tx_clone
                .send(TauriToRustCommand::RecoveryStart(
                    username,
                    password,
                    recovery_nodes_map,
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
        let recovery_nodes_map: HashMap<PeerId, i32> = new_recovery_addresses
            .iter()
            .map(|(k, v)| (PeerId::from_str(k).unwrap(), v.clone()))
            .collect();
        let tx_clone = state.1.clone();
        tauri::async_runtime::spawn(async move {
            tx_clone
                .send(TauriToRustCommand::RefreshStart(
                    recovery_nodes_map,
                    new_threshold,
                ))
                .await
                .unwrap();
        });
        Ok(())
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

                tauri::async_runtime::spawn(async move {
                    loop {
                        select! {
Some(res) = rx.recv() => match res {
    TauriToRustCommand::NewSwarm(keypair, username) => {
        swarm = new_swarm(keypair, username).unwrap();
        resubscribe_topics(&mut swarm, state_arc.clone()).unwrap();
    }
    TauriToRustCommand::RegStart(keypair, username, password, recovery_nodes) => {
        swarm = new_swarm(keypair, username).unwrap();
        resubscribe_topics(&mut swarm, state_arc.clone()).unwrap();
        handle_reg_init(state_arc.clone(), &mut swarm, password, recovery_nodes).unwrap();
    }
    TauriToRustCommand::RecoveryStart(username, password, recovery_nodes) => {
        handle_recovery_init(state_arc.clone(), &mut swarm, username, password, recovery_nodes).unwrap();
    }
    TauriToRustCommand::RefreshStart(recovery_nodes, new_threshold) => {
        handle_refresh_init(state_arc.clone(), &mut swarm, recovery_nodes, new_threshold as usize).unwrap();
    }
},
event = swarm.select_next_some() => match event {
    SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. })) => {
        add_peer(state_arc.clone(), &mut swarm, peer).unwrap();
    },
    SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::UnroutablePeer { peer })) => {
        remove_peer(state_arc.clone(), &mut swarm, peer).unwrap();
    },
    SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
        for (peer, _multiaddr) in list {
            add_peer(state_arc.clone(), &mut swarm, peer).unwrap();
        }
    },
    SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
        for (peer, _multiaddr) in list {
            remove_peer(state_arc.clone(), &mut swarm, peer).unwrap();
        }
    },
    SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {result, .. })) => {
        if let QueryResult::GetRecord(r) = result {
            if let Ok(GetRecordOk::FoundRecord(r_ok)) = r {
                set_peer_ids(state_arc.clone(), r_ok);
            }
        }
    },
    SwarmEvent::Behaviour(P2PBehaviourEvent::Gossipsub(gossipsub::Event::Message {
        propagation_source: peer_id,
        message_id: _,
        message,
    })) => {
        handle_message(state_arc.clone(), &mut swarm, peer_id, message).unwrap();
        update_peer_ids(state_arc.clone()).unwrap();
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
    SwarmEvent::Behaviour(P2PBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
        println!("[LOCAL] Subscribed to {} on {}", topic, peer_id);
    },
    SwarmEvent::Behaviour(P2PBehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic })) => {
        println!("[LOCAL] Unsubscribed from {} on {}", topic, peer_id);
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
