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
use keypair::Keypair;
use libp2p::gossipsub::{IdentTopic, Message, MessageId};
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{gossipsub, identify, kad, mdns, Multiaddr, PeerId, Swarm};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{io, io::AsyncBufReadExt, select};
use tracing_subscriber::EnvFilter;
use util::i32_to_scalar;

struct NodeState {
    opaque_keypair: Keypair,
}

struct BVBroadcastNodeState {
    bin_values: HashSet<Scalar>,
    has_second_broadcasted: bool,
    received_from: HashMap<Scalar, HashSet<PeerId>>,
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
        opaque_keypair: Keypair::new(),
    };

    let mut bv_state = BVBroadcastNodeState {
        bin_values: HashSet::new(),
        has_second_broadcasted: false,
        received_from: HashMap::new(),
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
                hasher.update(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis()
                        .to_le_bytes(),
                );
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

    let topic = gossipsub::IdentTopic::new("p2p-opaque");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
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

    fn handle_bv_state_receive(
        bv_state: &mut BVBroadcastNodeState,
        swarm: &mut Swarm<P2PBehaviour>,
        topic: IdentTopic,
        max_malicious: usize,
        peer_id: PeerId,
        id: MessageId,
        message: Message,
    ) -> Result<(), Box<dyn Error>> {
        let message_int = i32::from_le_bytes(message.data.as_slice().try_into().unwrap());
        let message_scalar = i32_to_scalar(message_int);
        let received_result = bv_state.received_from.get(&message_scalar);
        let mut received: HashSet<PeerId> = HashSet::new();
        if let Some(r) = received_result {
            received = r.clone();
        }
        received.insert(peer_id);
        println!(
            "Got message: '{message_int}' with id: {id} from peer: {peer_id}. Have {} responses.",
            received.len()
        );
        bv_state
            .received_from
            .insert(message_scalar, received.clone());
        if received.len() >= (max_malicious + 1) && !bv_state.has_second_broadcasted {
            println!("Rebroadcasting '{message_int}' to final set.");
            if let Err(e) = swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic.clone(), message.data)
            {
                println!("Publish error: {e:?}");
            } else {
                bv_state.has_second_broadcasted = true;
            }
        }
        if received.len() >= (2 * max_malicious + 1) {
            println!("Added '{message_int}' to final set.");
            bv_state.bin_values.insert(message_scalar);
        }

        Ok(())
    }

    loop {
        select! {
            Ok(Some(line)) = stdin.next_line() => {
                // will restart BV broadcast each time
                bv_state.bin_values = HashSet::new();
                bv_state.received_from = HashMap::new();
        bv_state.has_second_broadcasted= false;
                let int = line.to_string().parse::<i32>().unwrap();
                if let Err(e) = swarm
                    .behaviour_mut().gossipsub
                    .publish(topic.clone(), int.to_le_bytes()) {
                    println!("Publish error: {e:?}");
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. })) => {
                     println!("Routing updated with peer: {:?}", peer);
                    swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Kad(kad::Event::UnroutablePeer { peer })) => {
                    swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discovered a new peer: {peer_id}");
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discover peer has expired: {peer_id}");
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(P2PBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => {
                    handle_bv_state_receive(&mut bv_state, &mut swarm, topic.clone(), max_malicious, peer_id, id, message)?;
                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                }
                _ => {}
            }
        }
    }
}
