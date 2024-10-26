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

use curve25519_dalek::Scalar;
use futures::prelude::*;
use itertools::Itertools;
use keypair::Keypair;
use libp2p::gossipsub::{IdentTopic, Message, MessageId, Topic};
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{gossipsub, identify, kad, mdns, Multiaddr, PeerId, Swarm};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{io, io::AsyncBufReadExt, select};
use tracing_subscriber::EnvFilter;
use util::i32_to_scalar;

struct NodeState {
    peer_id: PeerId,
    index: i32,
    opaque_keypair: Keypair,
    // hashmap of (current, wrt)
    bv_broadcast_topics: HashMap<(PeerId, PeerId), (IdentTopic, BVBroadcastNodeState)>,
    known_peer_ids: HashSet<PeerId>,
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

#[derive(Serialize, Deserialize)]
struct BVBroadcastMessage {
    proposed_value: bool,
    current_index: i32,
    current_id: PeerId,
    wrt_index: i32,
    wrt_id: PeerId,
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
        peer_id: PeerId::random(),      // temporary
        known_peer_ids: HashSet::new(), // temporary
        index: 0,
        opaque_keypair: Keypair::new(),
        bv_broadcast_topics: HashMap::new(),
    };

    let max_malicious = 1;

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

    fn handle_bv_state_receive(
        state: &mut NodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        max_malicious: usize,
        peer_id: PeerId,
        id: MessageId,
        message: Message,
    ) -> Result<(), Box<dyn Error>> {
        let (topic, bv_state) = state
            .bv_broadcast_topics
            .get_mut(&(state.peer_id, peer_id))
            .unwrap();

        let message_data: BVBroadcastMessage =
            serde_json::from_slice(message.data.as_slice()).unwrap();

        bv_state
            .received_from
            .entry(message_data.proposed_value)
            .or_insert_with(HashSet::new)
            .insert(message_data.current_index);
        /*let received_result = bv_state.received_from.get(&message_data.proposed_value);
        let mut received: HashSet<i32> = HashSet::new();
        if let Some(r) = received_result {
            received = r.clone();
        }
        println!("Before received_from: {:?}", bv_state.received_from);
        received.insert(message_data.current_index);
        bv_state
            .received_from
            .insert(message_data.proposed_value, received.clone());*/
        println!("Before now received_from: {:?}", bv_state.received_from);

        let num_responses = bv_state
            .received_from
            .get(&message_data.proposed_value)
            .unwrap()
            .len();
        println!(
            "Got message: '{}' with id: {id} from peer: {peer_id}. Have {} responses.",
            String::from_utf8(message.data).unwrap(),
            num_responses
        );

        if num_responses >= (max_malicious + 1) && !bv_state.has_second_broadcasted {
            println!(
                "Rebroadcasting {} wrt {} to final set.",
                message_data.proposed_value, message_data.wrt_index
            );
            let init_message = serde_json::to_vec(&BVBroadcastMessage {
                proposed_value: message_data.proposed_value,
                current_index: state.index,
                current_id: state.peer_id,
                wrt_index: message_data.wrt_index,
                wrt_id: message_data.wrt_id,
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
                message_data.proposed_value, message_data.wrt_index
            );
            bv_state.bin_values.insert(message_data.proposed_value);
        }

        println!("New received_from: {:?}", bv_state.received_from);

        Ok(())
    }

    fn handle_stdin(state: &mut NodeState, swarm: &mut Swarm<P2PBehaviour>, line: String) {
        let parts: Vec<&str> = line.split_whitespace().collect(); // index + proposal +
                                                                  // index_peer_id
        let proposal = parts[1].parse::<i32>().unwrap();
        let at_index = parts[0].parse::<i32>().unwrap();
        let at_id = PeerId::from_str(parts[2]).unwrap();

        let init_message = serde_json::to_vec(&BVBroadcastMessage {
            proposed_value: proposal != 0,
            current_index: state.index,
            current_id: state.peer_id,
            wrt_index: at_index,
            wrt_id: at_id,
        })
        .unwrap();

        /*println!(
            "Current broadcast topics {:?} + known peer IDs {:?}",
            state.bv_broadcast_topics, state.known_peer_ids
        );*/

        let (topic, _) = state
            .bv_broadcast_topics
            .get(&(state.peer_id, at_id))
            .unwrap();
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

    println!("Peer ID is {} + index is {}", state.peer_id, state.index);
    loop {
        select! {
            Ok(Some(line)) = stdin.next_line() => {
                handle_stdin(&mut state, &mut swarm, line);
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. })) => {
                    println!("Routing updated with peer: {:?}", peer);
                    state.known_peer_ids.insert(peer);
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                    let combinations: Vec<(PeerId, PeerId)> = state.known_peer_ids.iter()
                        .combinations(2)
                        .map(|pair| (pair[0].clone(), pair[1].clone()))
                        .collect();
                    for (a, b) in combinations {
                        if let None = state.bv_broadcast_topics.get(&(b, a)) {
                            let topic = gossipsub::IdentTopic::new(format!("{}-{}", b, a));
                            state.bv_broadcast_topics.insert((b, a), (topic.clone(), BVBroadcastNodeState::new()));
                            swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
                        }
                        if let None = state.bv_broadcast_topics.get(&(a, b)) {
                            let topic = gossipsub::IdentTopic::new(format!("{}-{}", a, b));
                            state.bv_broadcast_topics.insert((a, b), (topic.clone(), BVBroadcastNodeState::new()));
                            swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
                        }
                    }
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::UnroutablePeer { peer })) => {
                    swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                    if let Some((topic, _)) = state.bv_broadcast_topics.get(&(state.peer_id, peer)) {
                        swarm.behaviour_mut().gossipsub.unsubscribe(&topic)?;
                    }
                    state.bv_broadcast_topics.remove(&(state.peer_id, peer));
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer, _multiaddr) in list {
                        println!("mDNS discovered a new peer: {peer}");
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                        state.known_peer_ids.insert(peer);
                        let combinations: Vec<(PeerId, PeerId)> = state.known_peer_ids.iter()
                            .combinations(2)
                            .map(|pair| (pair[0].clone(), pair[1].clone()))
                            .collect();
                        for (a, b) in combinations {
                            if let None = state.bv_broadcast_topics.get(&(b, a)) {
                                let topic = gossipsub::IdentTopic::new(format!("{}-{}", b, a));
                                state.bv_broadcast_topics.insert((b, a), (topic.clone(), BVBroadcastNodeState::new()));
                                swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
                            }
                            if let None = state.bv_broadcast_topics.get(&(a, b)) {
                                let topic = gossipsub::IdentTopic::new(format!("{}-{}", a, b));
                                state.bv_broadcast_topics.insert((a, b), (topic.clone(), BVBroadcastNodeState::new()));
                                swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
                            }
                        }
                    }
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer, _multiaddr) in list {
                        println!("mDNS discover peer has expired: {peer}");
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                        if let Some((topic, _)) = state.bv_broadcast_topics.get(&(state.peer_id, peer)) {
                            swarm.behaviour_mut().gossipsub.unsubscribe(&topic)?;
                        }
                        state.bv_broadcast_topics.remove(&(state.peer_id, peer));
                    }
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => {
                    handle_bv_state_receive(&mut state, &mut swarm, max_malicious, peer_id, id, message)?;
                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                }
                _ => {}
            }
        }
    }
}
