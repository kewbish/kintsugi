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
use dkg::DKG;
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
use std::str::FromStr;
use std::time::Duration;
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
    // hashmap of (current, wrt)
    broadcast_topics: HashMap<(PeerId, PeerId), IdentTopic>,
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
    s_finished: HashSet<i32>,
    phi_a: Option<Polynomial>,
    phi_hat_a: Option<Polynomial>,
    phi_b: Option<Polynomial>,
    phi_hat_b: Option<Polynomial>,
    z_shares: Option<Vec<Scalar>>,
    z_hat_shares: Option<Vec<Scalar>>,
}

impl DKGNodeState {
    fn new() -> Self {
        DKGNodeState {
            secret_share_a: None,
            secret_share_b: None,
            s_finished: HashSet::new(),
            phi_a: None,
            phi_b: None,
            phi_hat_a: None,
            phi_hat_b: None,
            z_shares: None,
            z_hat_shares: None,
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
    dealer_share_a: ACSSDealerShare,
    dealer_share_b: ACSSDealerShare,
    dealer_key: PublicKey,
    current_index: i32,
    current_id: PeerId,
    wrt_index: i32,
    wrt_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct ACSSAckMessage {
    current_index: i32,
    current_id: PeerId,
    wrt_index: i32,
    wrt_id: PeerId,
}

#[derive(Serialize, Deserialize, Debug)]
struct DKGAgreementMessage {
    t: HashSet<i32>, // TODO - should be taking this once ABAs are completed
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

    let mut state = NodeState {
        peer_id: PeerId::random(),        // temp
        known_peer_ids: HashSet::new(),   // temp
        peer_id_to_index: HashMap::new(), // temp
        index: 0,
        opaque_keypair: Keypair::new(),
        broadcast_topics: HashMap::new(),
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

            state.peer_id = key.public().to_peer_id();
            state.known_peer_ids = HashSet::from([state.peer_id]);
            state.peer_id_to_index = HashMap::from([(state.peer_id, state.index)]);

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

    if let Some(index_val) = std::env::args().nth(1) {
        let int = index_val.to_string().parse::<i32>().unwrap();
        state.index = int;
    }

    fn handle_message(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        max_malicious: usize,
        threshold: usize,
        peer_id: PeerId,
        id: MessageId,
        message: Message,
    ) -> Result<NodeState, Box<dyn Error>> {
        let message_data: BroadcastMessage =
            serde_json::from_slice(message.data.as_slice()).unwrap();

        match message_data {
            BroadcastMessage::IdIndexMessage(msg) => {
                state.peer_id_to_index.insert(peer_id, msg.index);
                Ok(state.clone())
            }
            BroadcastMessage::BVBroadcastMessage(msg) => {
                handle_message_bv(state, swarm, max_malicious, peer_id, msg)
            }
            BroadcastMessage::SBVBroadcastMessage(msg) => {
                handle_message_sbv(state, swarm, max_malicious, peer_id, msg)
            }
            BroadcastMessage::ABANewRoundMessage(msg) => {
                handle_message_aba_new_round(state, swarm, peer_id, msg)
            }
            BroadcastMessage::ABASBVReturnMessage(msg) => {
                handle_message_aba_sbv_return(state, swarm, peer_id, msg)
            }
            BroadcastMessage::ABAAuxsetMessage(msg) => {
                handle_message_aba_auxset(state, swarm, max_malicious, peer_id, msg)
            }
            BroadcastMessage::ACSSShareMessage(msg) => {
                handle_message_acss_share(state, swarm, peer_id, msg)
            }
            BroadcastMessage::ACSSAckMessage(msg) => {
                handle_message_acss_ack(state, swarm, max_malicious, peer_id, msg)
            }
            BroadcastMessage::DKGAgreementMessage(msg) => {
                handle_message_dkg_agreement(state, swarm, threshold, peer_id, msg)
            }
        }
    }

    fn handle_message_bv(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        max_malicious: usize,
        peer_id: PeerId,
        message: BVBroadcastMessage,
    ) -> Result<NodeState, Box<dyn Error>> {
        let topic = state
            .broadcast_topics
            .get(&(state.peer_id, peer_id))
            .unwrap()
            .clone();
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
                .publish(topic.clone(), init_message)
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
                .publish(topic.clone(), sbv_message)
            {
                println!("Publish error: {e:?}");
            }
        }

        state
            .bv_broadcast_states
            .insert(message.wrt_index, bv_state);

        Ok(state.clone())
    }

    fn handle_message_sbv(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        max_malicious: usize,
        peer_id: PeerId,
        message: SBVBroadcastMessage,
    ) -> Result<NodeState, Box<dyn Error>> {
        let topic = state
            .broadcast_topics
            .get(&(state.peer_id, peer_id))
            .unwrap()
            .clone();
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
                .publish(topic.clone(), aba_sbv_return_message)
            {
                println!("Publish error: {e:?}");
            }
        }

        state
            .sbv_broadcast_states
            .insert(message.wrt_index, sbv_state);

        Ok(state.clone())
    }

    fn handle_message_aba_new_round(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        message: ABANewRoundMessage,
    ) -> Result<NodeState, Box<dyn Error>> {
        let topic = state
            .broadcast_topics
            .get(&(state.peer_id, peer_id))
            .unwrap()
            .clone();
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
            .publish(topic.clone(), sbv_message)
        {
            println!("Publish error: {e:?}");
        }

        state.aba_states.insert(message.wrt_index, aba_state);

        Ok(state.clone())
    }

    fn handle_message_aba_sbv_return(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        message: ABASBVReturnMessage,
    ) -> Result<NodeState, Box<dyn Error>> {
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
                } else {
                    aba_state.est = Some(Coin::get_value(
                        state.opaque_keypair.clone(),
                        message.wrt_index,
                        aba_state.round_num as usize,
                    ));
                }
            } else {
                aba_state.est = Some(true); // if the other value is false, then v must be true
            }

            if should_continue {
                let new_round_message = serde_json::to_vec(&ABANewRoundMessage {
                    v: aba_state.est.unwrap(),
                    round_num: aba_state.round_num,
                    current_index: state.index,
                    current_id: state.peer_id,
                    wrt_index: message.wrt_index,
                    wrt_id: message.wrt_id,
                })
                .unwrap();
                let topic = state
                    .broadcast_topics
                    .get(&(state.peer_id, peer_id))
                    .unwrap();
                let message_id = swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), new_round_message);
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
            let topic = state
                .broadcast_topics
                .get(&(state.peer_id, peer_id))
                .unwrap();
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
                .publish(topic.clone(), auxset_message);
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

        Ok(state.clone())
    }

    fn handle_message_aba_auxset(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        max_malicious: usize,
        peer_id: PeerId,
        message: ABAAuxsetMessage,
    ) -> Result<NodeState, Box<dyn Error>> {
        let topic = state
            .broadcast_topics
            .get(&(state.peer_id, peer_id))
            .unwrap()
            .clone();
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
                .publish(topic.clone(), bv_message)
            {
                println!("Publish error: {e:?}");
            } else {
                aba_state.round_phase = ABANodeStateViewNum::Two;
            }
        }

        state.aba_states.insert(message.wrt_index, aba_state);

        Ok(state.clone())
    }

    fn handle_message_acss_share(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        peer_id: PeerId,
        message: ACSSShareMessage,
    ) -> Result<NodeState, Box<dyn Error>> {
        let node_share_a = ACSS::share(
            message.inputs.clone(),
            message.dealer_share_a,
            state.opaque_keypair.clone(),
            message.dealer_key,
        )?;
        let node_share_b = ACSS::share(
            message.inputs,
            message.dealer_share_b,
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
            .broadcast_topics
            .get(&(state.peer_id, peer_id))
            .unwrap()
            .clone();
        let acss_share_message = serde_json::to_vec(&ACSSAckMessage {
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

        Ok(state.clone())
    }

    fn handle_message_acss_ack(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        max_malicious: usize,
        peer_id: PeerId,
        message: ACSSAckMessage,
    ) -> Result<NodeState, Box<dyn Error>> {
        let mut dkg_state = state
            .dkg_states
            .entry(message.wrt_index)
            .or_insert(DKGNodeState::new())
            .clone();
        dkg_state.s_finished.insert(message.current_index);
        state
            .dkg_states
            .insert(message.wrt_index, dkg_state.clone());

        if dkg_state.s_finished.len() >= state.known_peer_ids.len() - max_malicious {
            // TODO - initialize the n ABA instances
        }

        Ok(state.clone())
    }

    fn handle_message_dkg_agreement(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        threshold: usize,
        peer_id: PeerId,
        message: DKGAgreementMessage,
    ) -> Result<NodeState, Box<dyn Error>> {
        let mut dkg_state = state
            .dkg_states
            .entry(message.wrt_index)
            .or_insert(DKGNodeState::new())
            .clone();
        let agreements = DKG::agreement_vec(
            message
                .t
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
            let topic = state
                .broadcast_topics
                .get(&(state.peer_id, wrt_id.clone()))
                .unwrap();
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

        Ok(state.clone())
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
            current_index: state.index,
            current_id: state.peer_id,
            wrt_index: at_index,
            wrt_id: at_id,
        })
        .unwrap();

        let topic = state.broadcast_topics.get(&(state.peer_id, at_id)).unwrap();
        let message_id = swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), init_message);
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
            let topic = state
                .broadcast_topics
                .get(&(state.peer_id, peer_id.clone()))
                .unwrap();
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

        let topic = state
            .broadcast_topics
            .get(&(state.peer_id, wrt_id))
            .unwrap();
        let init_message = serde_json::to_vec(&ACSSShareMessage {
            inputs: state.acss_inputs.clone(),
            dealer_share_a: a_acss_dealer_share
                .get(&wrt_id.to_string())
                .unwrap()
                .clone(),
            dealer_share_b: b_acss_dealer_share
                .get(&wrt_id.to_string())
                .unwrap()
                .clone(),
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
            .publish(topic.clone(), init_message);
        if let Err(e) = message_id {
            println!("Publish error: {e:?}");
        } else {
            println!("Sending ACSS share messages for index {wrt_index}");
        }

        Ok(state.clone())
    }

    fn add_peer(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        peer: PeerId,
    ) -> Result<(), Box<dyn Error>> {
        println!("Routing updated with peer: {:?}", peer);
        state.known_peer_ids.insert(peer);
        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
        let combinations: Vec<(PeerId, PeerId)> = state
            .known_peer_ids
            .iter()
            .combinations(2)
            .map(|pair| (pair[0].clone(), pair[1].clone()))
            .collect();
        for (a, b) in combinations {
            if let None = state.broadcast_topics.get(&(b, a)) {
                let topic = gossipsub::IdentTopic::new(format!("{}-{}", b, a));
                state.broadcast_topics.insert((b, a), topic.clone());
                swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
            }
            if let None = state.broadcast_topics.get(&(a, b)) {
                let topic = gossipsub::IdentTopic::new(format!("{}-{}", a, b));
                state.broadcast_topics.insert((a, b), topic.clone());
                swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
            }
        }
        return Ok(());
    }

    fn remove_peer(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        peer: PeerId,
    ) -> Result<(), Box<dyn Error>> {
        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
        if let Some(topic) = state.broadcast_topics.get(&(state.peer_id, peer)) {
            swarm.behaviour_mut().gossipsub.unsubscribe(&topic)?;
        }
        state.broadcast_topics.remove(&(state.peer_id, peer));
        Ok(())
    }

    println!("Peer ID is {} + index is {}", state.peer_id, state.index);
    loop {
        select! {
            /*Ok(Some(line)) = stdin.next_line() => {
                handle_stdin(&mut state, &mut swarm, line);
            }*/
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. })) => {
                    add_peer(&mut state, &mut swarm, peer)?;
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::UnroutablePeer { peer })) => {
                    remove_peer(&mut state, &mut swarm, peer)?;
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer, _multiaddr) in list {
                        add_peer(&mut state, &mut swarm, peer)?;
                    }
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer, _multiaddr) in list {
                        remove_peer(&mut state, &mut swarm, peer)?;
                    }
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => {
                    state = handle_message(&mut state, &mut swarm, max_malicious, threshold, peer_id, id, message)?;
                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                }
                _ => {}
            }
        }
    }
}
