mod acss;
mod coin;
mod dkg;
mod dpss;
mod keypair;
mod opaque;
mod oprf;
mod polynomial;
mod signature;
mod util;
mod zkp;

use acss::{ACSSDealerShare, ACSSInputs, ACSSNodeShare, ACSS};
use coin::Coin;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{RistrettoPoint, Scalar};
use dkg::{DKGKeyDerivation, DKG};
use futures::prelude::*;
use itertools::Itertools;
use keypair::{Keypair, PublicKey};
use libp2p::gossipsub::{IdentTopic, Message, MessageId};
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{gossipsub, identify, kad, mdns, PeerId, Swarm};
use polynomial::Polynomial;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ops::Index;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::State;
use tokio::{io, io::AsyncBufReadExt, select};
use tracing_subscriber::EnvFilter;
use util::i32_to_scalar;

// --- state structs --- //

#[derive(Debug, Clone)]
struct NodeState {
    peer_id: PeerId,
    index: i32,
    opaque_keypair: Keypair,
    known_peer_ids: HashSet<PeerId>,
    peer_id_to_index: HashMap<PeerId, i32>,
    broadcast_topic: IdentTopic,                   // for broadcasting
    broadcast_topics: HashMap<PeerId, IdentTopic>, // subscribe to these two
    point_to_point_topics: HashMap<PeerId, IdentTopic>,
    bv_broadcast_states: HashMap<i32, BVBroadcastNodeState>, // wrt → state
    sbv_broadcast_states: HashMap<i32, SBVBroadcastNodeState>,
    aba_states: HashMap<i32, ABANodeState>,
    dkg_states: HashMap<i32, DKGNodeState>,
    acss_inputs: ACSSInputs,
}

#[derive(Debug, Clone)]
struct BVBroadcastNodeState {
    bin_values: HashSet<bool>,
    has_second_broadcasted: bool,
    received_from: HashMap<bool, HashSet<i32>>,
}

impl BVBroadcastNodeState {
    fn new() -> Self {
        BVBroadcastNodeState {
            bin_values: HashSet::new(),
            has_second_broadcasted: false,
            received_from: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct SBVBroadcastNodeState {
    bin_values: HashSet<bool>,
    view: Option<HashSet<bool>>,
    received_from: HashMap<bool, HashSet<i32>>,
}

impl SBVBroadcastNodeState {
    fn new() -> Self {
        SBVBroadcastNodeState {
            bin_values: HashSet::new(),
            view: None,
            received_from: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ABANodeStateViewNum {
    Zero,
    One,
    Two,
}

#[derive(Debug, Clone)]
struct ABANodeState {
    round_num: i32,
    est: Option<bool>,
    views: HashMap<(bool, i32), HashSet<bool>>,
    received_from: HashMap<bool, HashSet<i32>>,
    sbv_broadcast_bin_values_1: HashSet<bool>,
    final_value: Option<bool>,
    round_phase: ABANodeStateViewNum,
}

impl ABANodeState {
    fn new() -> Self {
        ABANodeState {
            round_num: 0,
            est: None,
            views: HashMap::new(),
            final_value: None,
            received_from: HashMap::new(),
            sbv_broadcast_bin_values_1: HashSet::new(),
            round_phase: ABANodeStateViewNum::Zero,
        }
    }
}

#[derive(Debug, Clone)]
struct DKGNodeState {
    secret_share_a: Option<ACSSNodeShare>,
    secret_share_b: Option<ACSSNodeShare>,
    s_finished: HashMap<i32, Vec<RistrettoPoint>>,
    t_finished: HashSet<i32>,
    phi_a: Option<Polynomial>,
    phi_hat_a: Option<Polynomial>,
    phi_b: Option<Polynomial>,
    phi_hat_b: Option<Polynomial>,
    z_shares: Option<Vec<Scalar>>,
    z_hat_shares: Option<Vec<Scalar>>,
    k: Option<HashMap<i32, Scalar>>,
    r: Option<HashMap<i32, Scalar>>,
    h: Option<HashMap<i32, DKGKeyDerivation>>,
    z_i: Option<Scalar>,
    evaluation_points: Option<HashMap<Scalar, RistrettoPoint>>,
    combined_comm_vec: Option<Vec<RistrettoPoint>>,
}

impl DKGNodeState {
    fn new() -> Self {
        DKGNodeState {
            secret_share_a: None,
            secret_share_b: None,
            s_finished: HashMap::new(),
            t_finished: HashSet::new(),
            phi_a: None,
            phi_b: None,
            phi_hat_a: None,
            phi_hat_b: None,
            z_shares: None,
            z_hat_shares: None,
            k: None,
            r: None,
            h: None,
            z_i: None,
            evaluation_points: None,
            combined_comm_vec: None,
        }
    }
}

// --- message structs --- //

#[derive(Serialize, Deserialize, Debug)]
struct IdIndexMessage {
    index: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct BVBroadcastMessage {
    proposed_value: bool,
    current_index: i32,
    current_id: PeerId,
    wrt_index: i32,
    wrt_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct SBVBroadcastMessage {
    w: bool,
    current_index: i32,
    current_id: PeerId,
    wrt_index: i32,
    wrt_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct ABANewRoundMessage {
    v: bool,
    round_num: i32,
    agg_poly_comm: Option<Vec<RistrettoPoint>>,
    current_index: i32,
    current_id: PeerId,
    wrt_index: i32,
    wrt_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct ABASBVReturnMessage {
    view: HashSet<bool>,
    bin_values: HashSet<bool>,
    current_index: i32,
    current_id: PeerId,
    wrt_index: i32,
    wrt_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct ABAAuxsetMessage {
    view: HashSet<bool>,
    current_index: i32,
    current_id: PeerId,
    wrt_index: i32,
    wrt_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct ACSSShareMessage {
    inputs: ACSSInputs,
    dealer_shares_a: HashMap<PeerId, ACSSDealerShare>,
    dealer_shares_b: HashMap<PeerId, ACSSDealerShare>,
    dealer_key: PublicKey,
    current_index: i32,
    current_id: PeerId,
    wrt_index: i32,
    wrt_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct ACSSAckMessage {
    poly_comm: Vec<RistrettoPoint>,
    current_index: i32,
    current_id: PeerId,
    wrt_index: i32,
    wrt_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct DKGAgreementMessage {
    current_index: i32,
    current_id: PeerId,
    wrt_index: i32,
    wrt_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct DKGRandExtMessage {
    z_share: Scalar,
    z_hat_share: Scalar,
    current_index: i32,
    current_id: PeerId,
    wrt_index: i32,
    wrt_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct DKGDerivationMessage {
    derivation: DKGKeyDerivation,
    current_index: i32,
    current_id: PeerId,
    wrt_index: i32,
    wrt_id: PeerId,
}

#[derive(Serialize, Deserialize)]
enum BroadcastMessage {
    IdIndexMessage(IdIndexMessage),
    BVBroadcastMessage(BVBroadcastMessage),
    SBVBroadcastMessage(SBVBroadcastMessage),
    ABANewRoundMessage(ABANewRoundMessage),
    ABASBVReturnMessage(ABASBVReturnMessage),
    ABAAuxsetMessage(ABAAuxsetMessage),
    ACSSShareMessage(ACSSShareMessage),
    ACSSAckMessage(ACSSAckMessage),
    DKGAgreementMessage(DKGAgreementMessage),
    DKGRandExtMessage(DKGRandExtMessage),
    DKGDerivationMessage(DKGDerivationMessage),
}

#[derive(NetworkBehaviour)]
struct P2PBehaviour {
    gossipsub: gossipsub::Behaviour,
    kad: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

/* // from IPFS network
const BOOTNODES: [&str; 4] = [
    "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
    "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
    "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
];*/

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
        broadcast_topic: IdentTopic::new("temp"),
        broadcast_topics: HashMap::new(),
        point_to_point_topics: HashMap::new(),
        bv_broadcast_states: HashMap::new(),
        sbv_broadcast_states: HashMap::new(),
        aba_states: HashMap::new(),
        dkg_states: HashMap::new(),
        acss_inputs: ACSSInputs {
            h_point: Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT,
            degree: 1,
            peer_public_keys: HashMap::new(),
        },
    };
    let state_arc = Arc::new(Mutex::new(state));

    let max_malicious = 1;
    let threshold = 3;

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
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

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;

            let mut state = state_arc.lock().unwrap();
            if let Some(index_val) = std::env::args().nth(1) {
                let int = index_val.to_string().parse::<i32>().unwrap();
                state.index = int;
            }
            state.peer_id = key.public().to_peer_id();
            state.known_peer_ids = HashSet::from([state.peer_id]);
            state.peer_id_to_index = HashMap::from([(state.peer_id, state.index)]);
            state.broadcast_topic = IdentTopic::new(format!("{}", state.peer_id));
            println!("Peer ID is {} + index is {}", state.peer_id, state.index);

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

    let mut stdin = io::BufReader::new(io::stdin()).lines();
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // the bootstrap nodes aren't listening on this topic, need to run own nodes
    /*let bootaddr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io")?;
    for peer in &BOOTNODES {
        swarm
            .behaviour_mut()
            .kad
            .add_address(&PeerId::from_str(peer)?, bootaddr.clone());
    }
    swarm.behaviour_mut().kad.bootstrap()?;*/

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
            BroadcastMessage::BVBroadcastMessage(msg) => {
                handle_message_bv(&mut state, swarm, max_malicious, peer_id, msg)
            }
            BroadcastMessage::SBVBroadcastMessage(msg) => {
                handle_message_sbv(&mut state, swarm, max_malicious, peer_id, msg)
            }
            BroadcastMessage::ABANewRoundMessage(msg) => {
                handle_message_aba_new_round(&mut state, swarm, peer_id, msg)
            }
            BroadcastMessage::ABASBVReturnMessage(msg) => {
                handle_message_aba_sbv_return(&mut state, swarm, peer_id, msg)
            }
            BroadcastMessage::ABAAuxsetMessage(msg) => {
                handle_message_aba_auxset(&mut state, swarm, max_malicious, peer_id, msg)
            }
            BroadcastMessage::ACSSShareMessage(msg) => {
                handle_message_acss_share(&mut state, swarm, peer_id, msg)
            }
            BroadcastMessage::ACSSAckMessage(msg) => {
                handle_message_acss_ack(&mut state, swarm, max_malicious, peer_id, msg)
            }
            BroadcastMessage::DKGAgreementMessage(msg) => handle_message_dkg_agreement(
                &mut state,
                swarm,
                max_malicious,
                threshold,
                peer_id,
                msg,
            ),
            BroadcastMessage::DKGRandExtMessage(msg) => {
                handle_message_dkg_rand_ext(&mut state, swarm, threshold, peer_id, msg)
            }
            BroadcastMessage::DKGDerivationMessage(msg) => {
                handle_message_dkg_derivation(&mut state, swarm, threshold, peer_id, msg)
            }
        }
    }

    fn handle_message_bv(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        max_malicious: usize,
        peer_id: PeerId,
        message: BVBroadcastMessage,
    ) -> Result<(), Box<dyn Error>> {
        let mut bv_state = state
            .bv_broadcast_states
            .entry(message.wrt_index)
            .or_insert(BVBroadcastNodeState::new())
            .clone();
        bv_state
            .received_from
            .entry(message.proposed_value)
            .or_insert_with(HashSet::new)
            .insert(message.current_index);
        let num_responses = bv_state
            .received_from
            .get(&message.proposed_value)
            .unwrap()
            .len();

        println!(
            "[BV] Got message: '{message:?}' from peer: {peer_id}. Have {} responses.",
            num_responses
        );

        if num_responses >= (max_malicious + 1) && !bv_state.has_second_broadcasted {
            println!(
                "Rebroadcasting {} wrt {} to final set.",
                message.proposed_value, message.wrt_index
            );
            let init_message = serde_json::to_vec(&BVBroadcastMessage {
                proposed_value: message.proposed_value,
                current_index: state.index,
                current_id: state.peer_id,
                wrt_index: message.wrt_index,
                wrt_id: message.wrt_id,
            })
            .unwrap();
            if let Err(e) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(state.broadcast_topic.clone(), init_message)
            {
                println!("Publish error: {e:?}");
            } else {
                bv_state.has_second_broadcasted = true;
            }
            bv_state.has_second_broadcasted = true;
        }
        if num_responses >= (2 * max_malicious + 1) && bv_state.has_second_broadcasted {
            println!(
                "Added '{}' to final set wrt {}.",
                message.proposed_value, message.wrt_index
            );
            bv_state.bin_values.insert(message.proposed_value);

            println!(
                "Broadcasting SBV message {} wrt {}.",
                message.proposed_value, message.wrt_index
            );
            let sbv_message = serde_json::to_vec(&SBVBroadcastMessage {
                w: message.proposed_value,
                current_index: state.index,
                current_id: state.peer_id,
                wrt_index: message.wrt_index,
                wrt_id: message.wrt_id,
            })
            .unwrap();
            if let Err(e) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(state.broadcast_topic.clone(), sbv_message)
            {
                println!("Publish error: {e:?}");
            }
        }

        state
            .bv_broadcast_states
            .insert(message.wrt_index, bv_state);

        Ok(())
    }

    fn handle_message_sbv(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        max_malicious: usize,
        peer_id: PeerId,
        message: SBVBroadcastMessage,
    ) -> Result<(), Box<dyn Error>> {
        let mut sbv_state = state
            .sbv_broadcast_states
            .entry(message.wrt_index)
            .or_insert(SBVBroadcastNodeState::new())
            .clone();
        sbv_state
            .received_from
            .entry(message.w)
            .or_insert_with(HashSet::new)
            .insert(message.current_index);
        let num_responses = sbv_state.received_from.get(&message.w).unwrap().len();

        println!(
            "[SBV] Got message: '{message:?}' from peer: {peer_id}. Have {} responses.",
            num_responses
        );

        let mut final_view_modified = false;
        for (val, responses) in sbv_state.received_from.iter() {
            if responses.len() >= state.known_peer_ids.len() - max_malicious {}
            println!("Added '{}' to final view wrt {}.", val, message.wrt_index);
            if let None = sbv_state.view {
                sbv_state.view = Some(HashSet::new());
            }
            sbv_state.view.as_mut().unwrap().insert(val.clone());
            final_view_modified = true;
        }

        if final_view_modified {
            let sbv_state = sbv_state.clone();
            let aba_state = state
                .aba_states
                .entry(message.wrt_index)
                .or_insert(ABANodeState::new())
                .clone();
            println!(
                "Broadcasting ABA SBV return round {} w view {:?} wrt {}.",
                aba_state.round_num,
                sbv_state.view.as_ref().unwrap(),
                message.wrt_index
            );
            let aba_sbv_return_message = serde_json::to_vec(&ABASBVReturnMessage {
                view: sbv_state.view.unwrap(),
                bin_values: sbv_state.bin_values,
                current_index: state.index,
                current_id: state.peer_id,
                wrt_index: message.wrt_index,
                wrt_id: message.wrt_id,
            })
            .unwrap();

            if let Err(e) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(state.broadcast_topic.clone(), aba_sbv_return_message)
            {
                println!("Publish error: {e:?}");
            }
        }

        state
            .sbv_broadcast_states
            .insert(message.wrt_index, sbv_state);

        Ok(())
    }

    fn handle_message_aba_new_round(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        message: ABANewRoundMessage,
    ) -> Result<(), Box<dyn Error>> {
        let dkg_state = state
            .dkg_states
            .entry(message.wrt_index)
            .or_insert(DKGNodeState::new())
            .clone();
        let agg_comm_at_index: RistrettoPoint = dkg_state
            .s_finished
            .values()
            .map(|v| v[state.index as usize])
            .sum();

        if message.agg_poly_comm.is_some()
            && agg_comm_at_index == message.agg_poly_comm.unwrap()[state.index as usize]
        {
            println!(
                "Could not verify aggregated commitment at index {}",
                state.index
            );
            return Ok(());
        }

        let mut aba_state = state
            .aba_states
            .entry(message.wrt_index)
            .or_insert(ABANodeState::new())
            .clone();

        aba_state.round_num += 1;
        if let None = aba_state.est {
            aba_state.est = Some(message.v);
        }
        aba_state.received_from = HashMap::new();
        aba_state.round_phase = ABANodeStateViewNum::Zero;

        println!(
            "Broadcasting ABA new round {} w message {} wrt {}.",
            aba_state.round_num, message.v, message.wrt_index
        );
        let sbv_message = serde_json::to_vec(&SBVBroadcastMessage {
            w: aba_state.est.unwrap(),
            current_index: state.index,
            current_id: state.peer_id,
            wrt_index: message.wrt_index,
            wrt_id: message.wrt_id,
        })
        .unwrap();
        if let Err(e) = swarm
            .behaviour_mut()
            .gossipsub
            .publish(state.broadcast_topic.clone(), sbv_message)
        {
            println!("Publish error: {e:?}");
        }

        state.aba_states.insert(message.wrt_index, aba_state);

        Ok(())
    }

    fn handle_message_aba_sbv_return(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        message: ABASBVReturnMessage,
    ) -> Result<(), Box<dyn Error>> {
        let mut aba_state = state
            .aba_states
            .entry(message.wrt_index)
            .or_insert(ABANodeState::new())
            .clone();

        aba_state.sbv_broadcast_bin_values_1 = message.bin_values;

        if aba_state.round_phase == ABANodeStateViewNum::Two {
            let mut should_continue = true;
            if message.view.len() == 1 {
                let final_value = message.view.iter().next();
                if let Some(fv) = final_value {
                    println!(
                        "Decided on final value {fv} for ABA wrt {}",
                        message.wrt_index
                    );
                    aba_state.final_value = Some(fv.clone());
                    aba_state.est = Some(fv.clone());
                    should_continue = false;

                    let topic = state
                        .point_to_point_topics
                        .get(&message.current_id)
                        .unwrap()
                        .clone();
                    let dkg_agreement_msg = serde_json::to_vec(&DKGAgreementMessage {
                        current_index: state.index,
                        current_id: state.peer_id,
                        wrt_index: message.wrt_index,
                        wrt_id: message.wrt_id,
                    })
                    .unwrap();
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(topic.clone(), dkg_agreement_msg)
                    {
                        println!("Publish error: {e:?}");
                    } else {
                        println!("[ACSS] Published acknowledgement message");
                    }
                } else {
                    let dkg_state = state
                        .dkg_states
                        .entry(message.wrt_index)
                        .or_insert(DKGNodeState::new())
                        .clone();
                    aba_state.est = Some(Coin::get_value(
                        state.opaque_keypair.clone(),
                        message.wrt_index,
                        aba_state.round_num as usize,
                        dkg_state.combined_comm_vec.unwrap(),
                    ));
                }
            } else {
                aba_state.est = Some(true); // if the other value is false, then v must be true
            }

            if should_continue {
                let new_round_message = serde_json::to_vec(&ABANewRoundMessage {
                    v: aba_state.est.unwrap(),
                    round_num: aba_state.round_num,
                    agg_poly_comm: None,
                    current_index: state.index,
                    current_id: state.peer_id,
                    wrt_index: message.wrt_index,
                    wrt_id: message.wrt_id,
                })
                .unwrap();
                let message_id = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(state.broadcast_topic.clone(), new_round_message);
                if let Err(e) = message_id {
                    println!("Publish error: {e:?}");
                } else {
                    println!(
                        "Moving to next ABA round for node index {}",
                        message.wrt_index
                    );
                }
            }
        } else {
            let auxset_message = serde_json::to_vec(&ABAAuxsetMessage {
                view: message.view,
                current_index: state.index,
                current_id: state.peer_id,
                wrt_index: message.wrt_index,
                wrt_id: message.wrt_id,
            })
            .unwrap();
            let message_id = swarm
                .behaviour_mut()
                .gossipsub
                .publish(state.broadcast_topic.clone(), auxset_message);
            if let Err(e) = message_id {
                println!("Publish error: {e:?}");
            } else {
                println!(
                    "Moving to final ABA phase in round {} for node index {}",
                    aba_state.round_num, message.wrt_index
                );
                aba_state.round_phase = ABANodeStateViewNum::One;
            }
        }

        state.aba_states.insert(message.wrt_index, aba_state);

        Ok(())
    }

    fn handle_message_aba_auxset(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        max_malicious: usize,
        peer_id: PeerId,
        message: ABAAuxsetMessage,
    ) -> Result<(), Box<dyn Error>> {
        let mut aba_state = state
            .aba_states
            .entry(message.wrt_index)
            .or_insert(ABANodeState::new())
            .clone();
        for element in message.view.iter() {
            aba_state
                .received_from
                .entry(element.clone())
                .or_insert_with(HashSet::new)
                .insert(message.current_index);
        }

        println!("[ABA AUXSET] Got message: '{message:?}' from peer: {peer_id}.",);

        let mut view = HashSet::new();
        for (val, responses) in aba_state.received_from.iter() {
            if responses.len() >= state.known_peer_ids.len() - max_malicious
                && aba_state.sbv_broadcast_bin_values_1.contains(val)
            {
                println!("Added '{}' to final view wrt {}.", val, message.wrt_index);
                view.insert(val.clone());
            }
        }

        if view.len() > 0 {
            println!("Moving to ABA phase 1 decision wrt {}.", message.wrt_index);
            if view.len() == 1 {
                aba_state.est = Some(view.iter().next().unwrap().clone());
            } else {
                aba_state.est = Some(false);
            }
            let bv_message = serde_json::to_vec(&BVBroadcastMessage {
                proposed_value: aba_state.est.unwrap(),
                current_index: state.index,
                current_id: state.peer_id,
                wrt_index: message.wrt_index,
                wrt_id: message.wrt_id,
            })
            .unwrap();
            if let Err(e) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(state.broadcast_topic.clone(), bv_message)
            {
                println!("Publish error: {e:?}");
            } else {
                aba_state.round_phase = ABANodeStateViewNum::Two;
            }
        }

        state.aba_states.insert(message.wrt_index, aba_state);

        Ok(())
    }

    fn handle_message_acss_share(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        message: ACSSShareMessage,
    ) -> Result<(), Box<dyn Error>> {
        let node_share_a = ACSS::share(
            message.inputs.clone(),
            message.dealer_shares_a.get(&state.peer_id).unwrap().clone(),
            state.opaque_keypair.clone(),
            message.dealer_key,
        )?;
        let node_share_b = ACSS::share(
            message.inputs,
            message.dealer_shares_b.get(&state.peer_id).unwrap().clone(),
            state.opaque_keypair.clone(),
            message.dealer_key,
        )?;

        let mut dkg_state = state
            .dkg_states
            .entry(message.wrt_index)
            .or_insert(DKGNodeState::new())
            .clone();
        dkg_state.secret_share_a = Some(node_share_a);
        dkg_state.secret_share_b = Some(node_share_b);

        let topic = state
            .point_to_point_topics
            .get(&message.current_id)
            .unwrap()
            .clone();
        let mut combined_comm_vec = message
            .dealer_shares_a
            .get(&state.peer_id)
            .unwrap()
            .clone()
            .poly_c_i
            .clone();
        combined_comm_vec.extend(
            message
                .dealer_shares_b
                .get(&state.peer_id)
                .unwrap()
                .clone()
                .poly_c_i,
        );
        dkg_state.combined_comm_vec = Some(combined_comm_vec.clone());
        let acss_share_message = serde_json::to_vec(&ACSSAckMessage {
            poly_comm: combined_comm_vec,
            current_index: state.index,
            current_id: state.peer_id,
            wrt_index: message.wrt_index,
            wrt_id: message.wrt_id,
        })
        .unwrap();
        if let Err(e) = swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), acss_share_message)
        {
            println!("Publish error: {e:?}");
        } else {
            println!("[ACSS] Published acknowledgement message");
        }

        state.dkg_states.insert(message.wrt_index, dkg_state);

        Ok(())
    }

    fn handle_message_acss_ack(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        max_malicious: usize,
        peer_id: PeerId,
        message: ACSSAckMessage,
    ) -> Result<(), Box<dyn Error>> {
        let mut dkg_state = state
            .dkg_states
            .entry(message.wrt_index)
            .or_insert(DKGNodeState::new())
            .clone();
        dkg_state
            .s_finished
            .insert(message.current_index, message.poly_comm);
        state
            .dkg_states
            .insert(message.wrt_index, dkg_state.clone());

        let wrt_index = state.peer_id_to_index.get(&peer_id).unwrap().clone();
        if dkg_state.s_finished.len() >= state.known_peer_ids.len() - max_malicious {
            for wrt_id in state.known_peer_ids.iter() {
                let mut agg_poly_comm = vec![
                    RISTRETTO_BASEPOINT_POINT * Scalar::ZERO;
                    dkg_state.phi_a.as_ref().unwrap().coeffs.len()
                ];
                for comm_vector in dkg_state.s_finished.values() {
                    for (result_elem, &vec_elem) in agg_poly_comm.iter_mut().zip(comm_vector.iter())
                    {
                        *result_elem += vec_elem;
                    }
                }
                let topic = state.point_to_point_topics.get(&wrt_id).unwrap();
                let aba_init_message = serde_json::to_vec(&ABANewRoundMessage {
                    v: true,
                    round_num: 0,
                    agg_poly_comm: Some(agg_poly_comm),
                    current_index: state.index,
                    current_id: state.peer_id,
                    wrt_index,
                    wrt_id: peer_id.clone(),
                })
                .unwrap();
                let message_id = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), aba_init_message);
                if let Err(e) = message_id {
                    println!("Publish error: {e:?}");
                } else {
                    println!("[DKG] Sending MVBA proposal message to index {wrt_index}");
                }
            }
        }

        Ok(())
    }

    fn handle_message_dkg_agreement(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        max_malicious: usize,
        threshold: usize,
        peer_id: PeerId,
        message: DKGAgreementMessage,
    ) -> Result<(), Box<dyn Error>> {
        let mut dkg_state = state
            .dkg_states
            .entry(message.wrt_index)
            .or_insert(DKGNodeState::new())
            .clone();
        let peer_index = state.peer_id_to_index.get(&peer_id).unwrap().clone();
        dkg_state.t_finished.insert(peer_index);
        state
            .dkg_states
            .insert(message.wrt_index, dkg_state.clone());

        if dkg_state.t_finished.len() >= state.known_peer_ids.len() - max_malicious {
            let agreements = DKG::agreement_vec(
                dkg_state
                    .t_finished
                    .iter()
                    .map(|int| i32_to_scalar(int.clone()))
                    .collect(),
                dkg_state.phi_a.as_ref().unwrap().clone(),
                dkg_state.phi_hat_a.as_ref().unwrap().clone(),
                dkg_state.phi_b.as_ref().unwrap().clone(),
                dkg_state.phi_hat_b.as_ref().unwrap().clone(),
                state.acss_inputs.h_point,
                state.known_peer_ids.len(),
            );

            let (z_shares, z_hat_shares) =
                DKG::randomness_extraction(threshold, agreements, state.known_peer_ids.len());
            dkg_state.z_shares = Some(z_shares.clone());
            dkg_state.z_hat_shares = Some(z_hat_shares.clone());
            state
                .dkg_states
                .insert(message.wrt_index, dkg_state.clone());

            for wrt_id in state.known_peer_ids.iter() {
                let topic = state.point_to_point_topics.get(&wrt_id).unwrap();
                let wrt_index = state.peer_id_to_index.get(wrt_id).unwrap().clone();
                let init_message = serde_json::to_vec(&DKGRandExtMessage {
                    z_share: z_shares[wrt_index as usize],
                    z_hat_share: z_hat_shares[wrt_index as usize],
                    current_index: state.index,
                    current_id: state.peer_id,
                    wrt_index,
                    wrt_id: wrt_id.clone(),
                })
                .unwrap();
                let message_id = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), init_message);
                if let Err(e) = message_id {
                    println!("Publish error: {e:?}");
                } else {
                    println!("[DKG] Sending RANDEX message to index {wrt_index}");
                }
            }
        }

        Ok(())
    }

    fn handle_message_dkg_rand_ext(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        threshold: usize,
        peer_id: PeerId,
        message: DKGRandExtMessage,
    ) -> Result<(), Box<dyn Error>> {
        let mut dkg_state = state
            .dkg_states
            .entry(message.wrt_index)
            .or_insert(DKGNodeState::new())
            .clone();
        dkg_state
            .k
            .as_mut()
            .or(Some(&mut HashMap::<i32, Scalar>::new()))
            .unwrap()
            .insert(message.wrt_index, message.z_share);
        dkg_state
            .r
            .as_mut()
            .or(Some(&mut HashMap::<i32, Scalar>::new()))
            .unwrap()
            .insert(message.wrt_index, message.z_hat_share);

        if dkg_state.k.as_ref().unwrap().len() > threshold {
            let execution_result = dkg_state
                .k
                .as_ref()
                .unwrap()
                .iter()
                .map(|(k, v)| (i32_to_scalar(k.clone()), v.clone()))
                .collect();
            let execution_hat_result = dkg_state
                .r
                .as_ref()
                .unwrap()
                .iter()
                .map(|(k, v)| (i32_to_scalar(k.clone()), v.clone()))
                .collect();
            let (z_i, z_hat_i) = DKG::pre_key_derivation(
                state.index as usize,
                execution_result,
                execution_hat_result,
            );
            dkg_state.z_i = Some(z_i);
            let derivation =
                DKG::pre_key_derivation_public(z_i, z_hat_i, state.acss_inputs.h_point);

            let dkg_derivation_msg = serde_json::to_vec(&DKGDerivationMessage {
                derivation,
                current_index: state.index,
                current_id: state.peer_id,
                wrt_index: message.wrt_index,
                wrt_id: message.wrt_id,
            })
            .unwrap();
            if let Err(e) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(state.broadcast_topic.clone(), dkg_derivation_msg)
            {
                println!("Publish error: {e:?}");
            } else {
                println!("[DKG] Published key derivation message");
            }
        }

        state.dkg_states.insert(message.wrt_index, dkg_state);

        Ok(())
    }

    fn handle_message_dkg_derivation(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        threshold: usize,
        peer_id: PeerId,
        message: DKGDerivationMessage,
    ) -> Result<(), Box<dyn Error>> {
        if !message
            .derivation
            .zkp
            .verify(RISTRETTO_BASEPOINT_POINT, message.derivation.g_z_i)
            || !message
                .derivation
                .zkp_hat
                .verify(state.acss_inputs.h_point, message.derivation.h_z_hat_i)
        {
            return Ok(()); // break early
        }
        let mut dkg_state = state
            .dkg_states
            .entry(message.wrt_index)
            .or_insert(DKGNodeState::new())
            .clone();
        dkg_state
            .h
            .as_mut()
            .or(Some(&mut HashMap::<i32, DKGKeyDerivation>::new()))
            .unwrap()
            .insert(message.wrt_index, message.derivation);

        let h_scalar_to_scalar_map = dkg_state
            .h
            .as_ref()
            .unwrap()
            .iter()
            .map(|(k, v)| (i32_to_scalar(k.clone()), v.clone()))
            .collect();
        if dkg_state.h.as_ref().unwrap().len() > threshold {
            let evaluation_points =
                DKG::key_derivation(state.known_peer_ids.len(), h_scalar_to_scalar_map).unwrap();
            dkg_state.evaluation_points = Some(evaluation_points);

            println!("[DKG] Derived key share");
        }

        state.dkg_states.insert(message.wrt_index, dkg_state);

        Ok(())
    }

    fn handle_stdin(state: &mut NodeState, swarm: &mut Swarm<P2PBehaviour>, line: String) {
        let parts: Vec<&str> = line.split_whitespace().collect(); // index + proposal +
                                                                  // index_peer_id
        let proposal = parts[1].parse::<i32>().unwrap();
        let at_index = parts[0].parse::<i32>().unwrap();
        let at_id = PeerId::from_str(parts[2]).unwrap();

        let init_message = serde_json::to_vec(&ABANewRoundMessage {
            v: proposal != 0,
            round_num: 0,
            agg_poly_comm: None,
            current_index: state.index,
            current_id: state.peer_id,
            wrt_index: at_index,
            wrt_id: at_id,
        })
        .unwrap();

        let message_id = swarm
            .behaviour_mut()
            .gossipsub
            .publish(state.broadcast_topic.clone(), init_message);
        if let Err(e) = message_id {
            println!("Publish error: {e:?}");
        } else {
            println!("Proposing {proposal} (first broadcast) for node index {at_index}");
        }
    }

    fn handle_init(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        wrt_index: i32,
        wrt_id: PeerId,
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

        let (a, b) = DKG::share();
        let (a_acss_dealer_share, phi_a, phi_hat_a) = ACSS::share_dealer(
            state.acss_inputs.clone(),
            a,
            state.acss_inputs.degree,
            state.opaque_keypair.private_key,
        )?;
        let (b_acss_dealer_share, phi_b, phi_hat_b) = ACSS::share_dealer(
            state.acss_inputs.clone(),
            b,
            state.acss_inputs.degree,
            state.opaque_keypair.private_key,
        )?;

        let mut dkg_state = state
            .dkg_states
            .entry(wrt_index)
            .or_insert(DKGNodeState::new())
            .clone();
        dkg_state.phi_a = Some(phi_a);
        dkg_state.phi_b = Some(phi_b);
        dkg_state.phi_hat_a = Some(phi_hat_a);
        dkg_state.phi_hat_b = Some(phi_hat_b);
        state.dkg_states.insert(wrt_index, dkg_state.clone());

        let init_message = serde_json::to_vec(&ACSSShareMessage {
            inputs: state.acss_inputs.clone(),
            dealer_shares_a: a_acss_dealer_share
                .iter()
                .map(|(k, v)| (PeerId::from_str(k).unwrap(), v.clone()))
                .collect(),
            dealer_shares_b: b_acss_dealer_share
                .iter()
                .map(|(k, v)| (PeerId::from_str(k).unwrap(), v.clone()))
                .collect(),
            dealer_key: state.opaque_keypair.public_key,
            current_index: state.index,
            current_id: state.peer_id,
            wrt_index,
            wrt_id,
        })
        .unwrap();
        let message_id = swarm
            .behaviour_mut()
            .gossipsub
            .publish(state.broadcast_topic.clone(), init_message);
        if let Err(e) = message_id {
            println!("Publish error: {e:?}");
        } else {
            println!("Sending ACSS share messages for index {wrt_index}");
        }

        Ok(state.clone())
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

    struct TauriState(Arc<Mutex<NodeState>>);

    #[tauri::command]
    fn get_peer_id(state: State<TauriState>) -> String {
        let node_state = state.0.lock().unwrap();
        node_state.peer_id.to_string()
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_peer_id])
        .manage(TauriState(Arc::clone(&state_arc)))
        .run(tauri::generate_context!())
        .expect("Error while running Tauri application");

    loop {
        select! {
            /*Ok(Some(line)) = stdin.next_line() => {
                handle_stdin(&mut state, &mut swarm, line);
            }*/
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. })) => {
                    add_peer(state_arc.clone(), &mut swarm, peer)?;
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::UnroutablePeer { peer })) => {
                    remove_peer(state_arc.clone(), &mut swarm, peer)?;
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer, _multiaddr) in list {
                        add_peer(state_arc.clone(), &mut swarm, peer)?;
                    }
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer, _multiaddr) in list {
                        remove_peer(state_arc.clone(), &mut swarm, peer)?;
                    }
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
