mod acss;
mod coin;
mod dkg;
mod dpss;
mod keypair;
mod local_envelope;
mod opaque;
mod oprf;
mod polynomial;
mod signature;
mod util;
mod zkp;

use acss::{ACSSDealerShare, ACSSInputs, ACSSNodeShare, ACSS};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{RistrettoPoint, Scalar};
use futures::prelude::*;
use itertools::Itertools;
use keypair::{Keypair, PublicKey};
use libp2p::gossipsub::{IdentTopic, Message, MessageId};
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{gossipsub, identify, kad, mdns, PeerId, Swarm};
use local_envelope::{LocalEncryptedEnvelope, LocalEnvelope};
use opaque::{
    EncryptedEnvelope, Envelope, LoginStartNodeRequest, P2POpaqueError, P2POpaqueNode,
    RegFinishRequest, RegStartNodeRequest,
};
use oprf::{OPRFClient, OPRFServer};
use polynomial::Polynomial;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::Write;
use std::ops::Index;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{Manager, State};
use tokio::{io, io::AsyncBufReadExt, io::AsyncReadExt, select, sync::mpsc};
use tracing_subscriber::EnvFilter;
use util::i32_to_scalar;

// --- state structs --- //

#[derive(Debug, Clone)]
struct NodeState {
    peer_id: PeerId,
    index: i32,
    opaque_keypair: Keypair,
    libp2p_keypair_bytes: [u8; 64],
    known_peer_ids: HashSet<PeerId>,
    peer_id_to_index: HashMap<PeerId, i32>, // this node's recovery nodes' indices
    broadcast_topic: IdentTopic,            // for broadcasting
    broadcast_topics: HashMap<PeerId, IdentTopic>, // subscribe to these two
    point_to_point_topics: HashMap<PeerId, IdentTopic>,
    acss_inputs: ACSSInputs,
    opaque_node: P2POpaqueNode,
    peer_recoveries: HashMap<PeerId, (ACSSNodeShare, i32)>, // the indices for nodes for which this node
    // is a recovery node
    phi_polynomials: Option<(Polynomial, Polynomial)>,
}

// --- message structs --- //

#[derive(Serialize, Deserialize, Debug)]
struct IdIndexMessage {
    index: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct OPRFRegInitMessage {
    inputs: ACSSInputs,
    blinded_point: RistrettoPoint,
    dealer_shares: HashMap<PeerId, ACSSDealerShare>,
    dealer_key: PublicKey,
    user_index: i32,
    user_id: PeerId,
    node_index: i32,
    node_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct OPRFRegStartRespMessage {
    blind_evaluation: RistrettoPoint,
    user_index: i32,
    user_id: PeerId,
    node_index: i32,
    node_id: PeerId,
}

#[derive(Serialize, Deserialize)]
enum BroadcastMessage {
    IdIndexMessage(IdIndexMessage),
    OPRFRegInitMessage(OPRFRegInitMessage),
}

#[derive(NetworkBehaviour)]
struct P2PBehaviour {
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

enum TauriToRustCommand {
    NewSwarm(libp2p::identity::ed25519::Keypair),
    AddPeer(String),
    RemovePeer(String),
    BroadcastMessage(BroadcastMessage),
    SendMessageToPeer(BroadcastMessage, PeerId),
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedTauriNotepad {
    encrypted_contents: Vec<u8>,
    nonce: [u8; 12],
}

/* // from IPFS network
const BOOTNODES: [&str; 4] = [
    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];*/
fn new_swarm(
    keypair: libp2p::identity::ed25519::Keypair,
) -> Result<Swarm<P2PBehaviour>, Box<dyn Error>> {
    let mut swarm =
        libp2p::SwarmBuilder::with_existing_identity(libp2p::identity::Keypair::from(keypair))
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

                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )?;

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
    swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Server));
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    Ok(swarm)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let state = NodeState {
        peer_id: PeerId::random(),        // temp
        known_peer_ids: HashSet::new(),   // temp
        peer_id_to_index: HashMap::new(), // temp
        index: 0,
        opaque_keypair: Keypair::new(),
        libp2p_keypair_bytes: [0u8; 64],
        broadcast_topic: IdentTopic::new("temp"),
        broadcast_topics: HashMap::new(),
        point_to_point_topics: HashMap::new(),
        acss_inputs: ACSSInputs {
            h_point: Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT,
            degree: 1,
            peer_public_keys: HashMap::new(),
        },
        opaque_node: P2POpaqueNode::new("".to_string()),
        peer_recoveries: HashMap::new(),
        phi_polynomials: None,
    };
    let state_arc = Arc::new(Mutex::new(state));
    let (tx, mut rx) = mpsc::channel::<TauriToRustCommand>(32);

    let max_malicious = 1;
    let threshold = 3;

    let mut swarm = new_swarm(libp2p::identity::ed25519::Keypair::generate())?;
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    // the bootstrap nodes aren't listening on this topic, need to run own nodes
    /*let bootaddr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io")?;
    for peer in &BOOTNODES {
        swarm
            .behaviour_mut()
            .kad
            .add_address(&PeerId::from_str(peer)?, bootaddr.clone());
    }
    swarm.behaviour_mut().kad.bootstrap()?;*/

    {
        let mut state = state_arc.lock().unwrap();
        if let Some(index_val) = std::env::args().nth(1) {
            let int = index_val.to_string().parse::<i32>().unwrap();
            state.index = int;
        }
    }

    fn handle_message(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        max_malicious: usize,
        threshold: usize,
        peer_id: PeerId,
        id: MessageId,
        message: Message,
    ) -> Result<(), Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();
        let message_data: BroadcastMessage =
            serde_json::from_slice(message.data.as_slice()).unwrap();

        match message_data {
            BroadcastMessage::IdIndexMessage(msg) => {
                state.peer_id_to_index.insert(peer_id, msg.index);
                Ok(())
            }
            BroadcastMessage::OPRFRegInitMessage(msg) => {
                handle_message_reg_init(&mut state, swarm, peer_id, msg)
            }
        }
    }

    fn handle_init(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        password: String,
        node_index: i32,
        node_id: PeerId,
    ) -> Result<NodeState, Box<dyn Error>> {
        for peer_id in state.known_peer_ids.iter() {
            let topic = state.point_to_point_topics.get(&peer_id).unwrap();
            let index_message = serde_json::to_vec(&IdIndexMessage { index: state.index }).unwrap();
            let message_id = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic.clone(), index_message);
            if let Err(e) = message_id {
                println!("Publish error: {e:?}");
            } else {
                println!("[INIT] Sending peer ID/index setup message");
            }
        }

        let s = Scalar::random(&mut OsRng);
        let (acss_dealer_share, phi, phi_hat) = ACSS::share_dealer(
            state.acss_inputs.clone(),
            s,
            state.acss_inputs.degree,
            state.opaque_keypair.private_key,
        )?;
        state.phi_polynomials = Some((phi, phi_hat));

        let reg_start_req = state.opaque_node.local_registration_start(password)?;

        let init_message = serde_json::to_vec(&OPRFRegInitMessage {
            inputs: state.acss_inputs.clone(),
            blinded_point: reg_start_req.blinded_pwd,
            dealer_shares: acss_dealer_share
                .iter()
                .map(|(k, v)| (PeerId::from_str(k).unwrap(), v.clone()))
                .collect(),
            dealer_key: state.opaque_keypair.public_key,
            user_index: state.index,
            user_id: state.peer_id,
            node_index,
            node_id,
        })
        .unwrap();
        let message_id = swarm
            .behaviour_mut()
            .gossipsub
            .publish(state.broadcast_topic.clone(), init_message);
        if let Err(e) = message_id {
            println!("Publish error: {e:?}");
        } else {
            println!("[INIT] Sending ACSS share messages for index {node_index}");
        }

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
            .map(|share| i32_to_scalar(share.index.try_into().unwrap()))
            .collect();
        let reg_start_resp_message = serde_json::to_vec(&OPRFRegStartRespMessage {
            blind_evaluation: OPRFServer::blind_evaluate(
                message.blinded_point,
                node_share.s_i_d,
                i32_to_scalar(message.user_index),
                other_indices,
            ),
            user_index: message.node_index,
            user_id: message.node_id,
            node_index: state.index,
            node_id: state.peer_id,
        })
        .unwrap();
        if let Err(e) = swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), reg_start_resp_message)
        {
            println!("Publish error: {e:?}");
        } else {
            println!("[REG INIT] Published acknowledgement message");
        }

        Ok(())
    }

    fn update_peer_ids(state_arc: Arc<Mutex<NodeState>>) -> Result<(), Box<dyn Error>> {
        let state = state_arc.lock().unwrap();
        let serialized_peers = serde_json::to_string(&state.known_peer_ids)?;
        let file_path = "tmp/peers.list".to_string();
        let mut file = fs::File::create(file_path)?;
        file.write_all(serialized_peers.as_bytes())?;
        Ok(())
    }

    fn add_peer(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        peer: PeerId,
    ) -> Result<(), Box<dyn Error>> {
        let mut state = state_arc.lock().unwrap();
        println!("Routing updated with peer: {:?}", peer);
        state.known_peer_ids.insert(peer);
        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
        let subscribe_handle = gossipsub::IdentTopic::new(format!("{peer}"));
        state
            .broadcast_topics
            .insert(peer, subscribe_handle.clone());
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&subscribe_handle)?;
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
        if let Some(topic) = state.broadcast_topics.get(&peer) {
            swarm.behaviour_mut().gossipsub.unsubscribe(&topic)?;
            state.broadcast_topics.remove(&peer);
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
    fn get_peers(state: State<TauriState>) -> Vec<PeerId> {
        let node_state = state.0.lock().unwrap();
        return Vec::from_iter(node_state.known_peer_ids.clone());
    }

    #[tauri::command]
    fn add_peer_tauri(state: State<TauriState>, peer: String) -> Result<(), String> {
        let tx_clone = state.1.clone();
        tokio::spawn(async move {
            tx_clone
                .send(TauriToRustCommand::AddPeer(peer))
                .await
                .unwrap();
        });
        Ok(())
    }

    #[tauri::command]
    fn remove_peer_tauri(state: State<TauriState>, peer: String) -> Result<(), String> {
        let tx_clone = state.1.clone();
        tokio::spawn(async move {
            tx_clone
                .send(TauriToRustCommand::RemovePeer(peer))
                .await
                .unwrap();
        });
        Ok(())
    }

    #[tauri::command]
    fn local_register(state: State<TauriState>, password: String) -> Result<(), String> {
        let mut node_state = state.0.lock().unwrap();
        let file_path = "tmp/login.envelope".to_string();
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
        node_state.opaque_keypair = Keypair::new();
        let libp2p_keypair = libp2p::identity::ed25519::Keypair::generate();
        let envelope = LocalEnvelope {
            keypair: node_state.opaque_keypair.clone(),
            libp2p_keypair_bytes: libp2p_keypair.to_bytes(),
            peer_public_key: (Scalar::ZERO * RISTRETTO_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
            peer_id: node_state.peer_id.to_string(),
        };
        let encrypted_envelope = envelope.clone().encrypt_w_password(password);
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
        let tx_clone = state.1.clone();
        let keypair = libp2p_keypair.clone();
        tokio::spawn(async move {
            tx_clone
                .send(TauriToRustCommand::NewSwarm(keypair))
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
        node_state.opaque_node.id = node_state.peer_id.to_string();
        node_state.known_peer_ids = HashSet::from([node_state.peer_id]);
        node_state.peer_id_to_index = HashMap::from([(node_state.peer_id, node_state.index)]);
        node_state.broadcast_topic = IdentTopic::new(format!("{}", node_state.peer_id));
        println!(
            "Peer ID is {} + index is {}",
            node_state.peer_id, node_state.index
        );
        let libp2p_keypair =
            libp2p::identity::ed25519::Keypair::try_from_bytes(&mut libp2p_keypair_bytes.clone());
        if let Err(e) = libp2p_keypair {
            return Err(e.to_string());
        }
        node_state.opaque_keypair = keypair.clone();
        node_state.libp2p_keypair_bytes = libp2p_keypair_bytes;
        node_state.opaque_node.keypair = keypair;

        if node_state.known_peer_ids.len() == 0 {
            let file_path = "tmp/peers.list".to_string();
            if Path::new(&file_path).exists() {
                let contents = std::fs::read_to_string(file_path);
                if let Err(e) = contents {
                    return Err(e.to_string());
                }
                let peers_list: Result<HashSet<PeerId>, _> =
                    serde_json::from_str(&contents.unwrap());
                if let Err(e) = peers_list {
                    return Err(e.to_string());
                }
                node_state.known_peer_ids = peers_list.unwrap();
            }
        }

        if node_state.opaque_node.envelopes.len() == 0 {
            let file_path = "tmp/envelopes.list".to_string();
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

        tokio::spawn(async move {
            tx.send(TauriToRustCommand::NewSwarm(libp2p_keypair.unwrap()))
                .await
                .unwrap();
        });
        Ok(())
    }

    #[tauri::command]
    fn local_login(state: State<TauriState>, password: String) -> Result<bool, String> {
        let mut node_state = state.0.lock().unwrap();
        let file_path = "tmp/login.envelope".to_string();
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
        let file_path = "tmp/notepad.txt".to_string();
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
        let file_path = "tmp/notepad.txt".to_string();
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
        let node_state = state.0.lock().unwrap();
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
    fn local_login_start(state: State<TauriState>, password: String) -> Result<String, String> {
        let mut node_state = state.0.lock().unwrap();
        let result = node_state.opaque_node.local_login_start(password);
        if let Err(e) = result {
            return Err(e.to_string());
        }
        let result = result.unwrap();
        let serialized = serde_json::to_string(&result);
        if let Err(e) = serialized {
            return Err(e.to_string());
        }
        return Ok(serialized.unwrap());
    }

    #[tauri::command]
    fn peer_login_start(state: State<TauriState>, peer_req: String) -> Result<String, String> {
        let login_start_node_req = serde_json::from_str(&peer_req);
        if let Err(e) = login_start_node_req {
            return Err(e.to_string());
        }
        let login_start_node_req: LoginStartNodeRequest = login_start_node_req.unwrap();
        let node_state = state.0.lock().unwrap();
        let result = node_state
            .opaque_node
            .peer_login_start(login_start_node_req);
        if let Err(e) = result {
            return Err(e.to_string());
        }
        let result = result.unwrap();
        let serialized = serde_json::to_string(&result);
        if let Err(e) = serialized {
            return Err(e.to_string());
        }
        return Ok(serialized.unwrap());
    }

    #[tauri::command]
    fn local_login_finish(
        state: State<TauriState>,
        password: String,
        peer_resp: Vec<String>,
    ) -> Result<(), String> {
        let mut result = Vec::new();
        for peer_resp in peer_resp.iter() {
            let deserialized_peer_resp = serde_json::from_str(&peer_resp);
            if let Err(e) = deserialized_peer_resp {
                return Err(e.to_string());
            }
            result.push(deserialized_peer_resp.unwrap());
        }

        let mut node_state = state.0.lock().unwrap();
        let result = node_state.opaque_node.local_login_finish(
            password,
            node_state.libp2p_keypair_bytes.clone(),
            result,
        );
        if let Err(e) = result {
            return Err(e.to_string());
        }
        let result = result.unwrap();

        node_state.opaque_keypair = result.0.clone();
        let libp2p_keypair =
            libp2p::identity::ed25519::Keypair::try_from_bytes(&mut result.1.clone());
        if let Err(e) = libp2p_keypair {
            return Err(e.to_string());
        }

        let peer_id = PeerId::from_public_key(
            &libp2p::identity::Keypair::from(libp2p_keypair.unwrap()).public(),
        );

        update_with_peer_id(
            &mut node_state,
            result.0,
            result.1,
            state.1.clone(),
            peer_id,
        )?;

        Ok(())
    }

    #[tauri::command]
    fn local_registration_start(
        state: State<TauriState>,
        password: String,
    ) -> Result<String, String> {
        let mut node_state = state.0.lock().unwrap();
        let result = node_state.opaque_node.local_registration_start(password);
        if let Err(e) = result {
            return Err(e.to_string());
        }
        let result = result.unwrap();
        let serialized = serde_json::to_string(&result);
        if let Err(e) = serialized {
            return Err(e.to_string());
        }
        return Ok(serialized.unwrap());
    }

    #[tauri::command]
    fn peer_registration_start(
        state: State<TauriState>,
        peer_req: String,
    ) -> Result<String, String> {
        let reg_start_node_req = serde_json::from_str(&peer_req);
        if let Err(e) = reg_start_node_req {
            return Err(e.to_string());
        }
        let reg_start_node_req: RegStartNodeRequest = reg_start_node_req.unwrap();
        let mut node_state = state.0.lock().unwrap();
        let result = node_state
            .opaque_node
            .peer_registration_start(reg_start_node_req);
        if let Err(e) = result {
            return Err(e.to_string());
        }
        let result = result.unwrap();
        let serialized = serde_json::to_string(&result);
        if let Err(e) = serialized {
            return Err(e.to_string());
        }
        return Ok(serialized.unwrap());
    }

    #[tauri::command]
    fn local_registration_finish(
        state: State<TauriState>,
        password: String,
        peer_resp: String,
    ) -> Result<String, String> {
        let deserialized_peer_resp = serde_json::from_str(&peer_resp);
        if let Err(e) = deserialized_peer_resp {
            return Err(e.to_string());
        }

        let mut node_state = state.0.lock().unwrap();
        let libp2p_keypair_bytes = node_state.libp2p_keypair_bytes.clone();
        let result = node_state.opaque_node.local_registration_finish(
            password,
            libp2p_keypair_bytes,
            deserialized_peer_resp.unwrap(),
        );
        if let Err(e) = result {
            return Err(e.to_string());
        }
        let result = result.unwrap();
        let serialized = serde_json::to_string(&result);
        if let Err(e) = serialized {
            return Err(e.to_string());
        }
        return Ok(serialized.unwrap());
    }

    #[tauri::command]
    fn peer_registration_finish(
        state: State<TauriState>,
        peer_req: String,
    ) -> Result<String, String> {
        let reg_finish_req = serde_json::from_str(&peer_req);
        if let Err(e) = reg_finish_req {
            return Err(e.to_string());
        }
        let reg_finish_req: RegFinishRequest = reg_finish_req.unwrap();
        let mut node_state = state.0.lock().unwrap();
        let result = node_state
            .opaque_node
            .peer_registration_finish(reg_finish_req);
        if let Err(e) = result {
            return Err(e.to_string());
        }

        let node_state = state.0.lock().unwrap();
        let serialized_envelopes = serde_json::to_string(&node_state.opaque_node.envelopes);
        if let Err(e) = serialized_envelopes {
            return Err(e.to_string());
        }
        let file_path = "tmp/envelopes.list".to_string();
        let file = fs::File::create(file_path);
        if let Err(e) = file {
            return Err(e.to_string());
        }
        let mut file = file.unwrap();
        let file_result = file.write_all(serialized_envelopes.unwrap().as_bytes());
        if let Err(e) = file_result {
            return Err(e.to_string());
        }

        let result = result.unwrap();
        let serialized = serde_json::to_string(&result);
        if let Err(e) = serialized {
            return Err(e.to_string());
        }
        return Ok(serialized.unwrap());
    }

    fn tauri_broadcast_message(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        message: BroadcastMessage,
    ) -> Result<(), Box<dyn Error>> {
        let serialized_msg = serde_json::to_vec(&message)?;
        let state = state_arc.lock().unwrap();
        if let Err(e) = swarm
            .behaviour_mut()
            .gossipsub
            .publish(state.broadcast_topic.clone(), serialized_msg)
        {
            return Err(Box::new(e));
        }
        Ok(())
    }

    fn tauri_send_message_to_peer(
        state_arc: Arc<Mutex<NodeState>>,
        swarm: &mut Swarm<P2PBehaviour>,
        message: BroadcastMessage,
        peer_id: PeerId,
    ) -> Result<(), Box<dyn Error>> {
        let serialized_msg = serde_json::to_vec(&message)?;
        let state = state_arc.lock().unwrap();
        let topic = state.point_to_point_topics.get(&peer_id).unwrap();
        if let Err(e) = swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), serialized_msg)
        {
            return Err(Box::new(e));
        }
        Ok(())
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_peer_id,
            local_register,
            local_login,
            read_notepad,
            save_notepad,
            local_login_start,
            peer_login_start,
            local_login_finish,
            local_registration_start,
            peer_registration_start,
            local_registration_finish,
            peer_registration_finish,
            get_peers,
            add_peer_tauri,
            remove_peer_tauri,
        ])
        .manage(TauriState(Arc::clone(&state_arc), tx))
        .run(tauri::generate_context!())
        .expect("Error while running Tauri application");

    loop {
        select! {
            /*Ok(Some(line)) = stdin.next_line() => {
                handle_stdin(&mut state, &mut swarm, line);
            }*/
            Some(res) = rx.recv() => match res {
                TauriToRustCommand::NewSwarm(keypair) => {
                    swarm = new_swarm(keypair)?;
                }
                TauriToRustCommand::AddPeer(peer) => {
                    let peer_id = PeerId::from_str(&peer)?;
                    add_peer(state_arc.clone(), &mut swarm, peer_id)?;
                    update_peer_ids(state_arc.clone())?;
                }
                TauriToRustCommand::RemovePeer(peer) => {
                    let peer_id = PeerId::from_str(&peer)?;
                    remove_peer(state_arc.clone(), &mut swarm, peer_id)?;
                    update_peer_ids(state_arc.clone())?;
                },
                TauriToRustCommand::BroadcastMessage(msg) => {
                    tauri_broadcast_message(state_arc.clone(), &mut swarm, msg)?;
                }
                TauriToRustCommand::SendMessageToPeer(msg, peer_id) => {
                    tauri_send_message_to_peer(state_arc.clone(), &mut swarm, msg, peer_id)?;
                }
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. })) => {
                    add_peer(state_arc.clone(), &mut swarm, peer)?;
                    update_peer_ids(state_arc.clone())?;
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::UnroutablePeer { peer })) => {
                    remove_peer(state_arc.clone(), &mut swarm, peer)?;
                    update_peer_ids(state_arc.clone())?;
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer, _multiaddr) in list {
                        add_peer(state_arc.clone(), &mut swarm, peer)?;
                    }
                    update_peer_ids(state_arc.clone())?;
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer, _multiaddr) in list {
                        remove_peer(state_arc.clone(), &mut swarm, peer)?;
                    }
                    update_peer_ids(state_arc.clone())?;
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => {
                    handle_message(state_arc.clone(), &mut swarm, max_malicious, threshold, peer_id, id, message)?;
                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                }
                _ => {}
            }
        }
    }
}
