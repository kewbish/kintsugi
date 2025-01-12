mod kad_interactions;
mod kintsugi_lib;
mod local_files;
mod login;
mod messages;
mod node_state;
mod recovery;
mod refresh;
mod registration;
mod tauri_interactions;

#[allow(unused_imports)]
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::Scalar;
use futures::prelude::*;
use kintsugi_lib::keypair::Keypair;
use kintsugi_lib::opaque::P2POpaqueNode;
use libp2p::kad::{store::MemoryStore, GetRecordError, GetRecordOk};
use libp2p::{
    identify,
    kad::{self, InboundRequest},
    mdns,
    request_response::{self, ProtocolSupport, ResponseChannel},
    Multiaddr, PeerId, StreamProtocol, Swarm,
};
use libp2p::{
    kad::RecordKey,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use rand::rngs::OsRng;
#[allow(unused_imports)]
use rand::RngCore;
use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager};
use tokio::{select, sync::mpsc};

#[derive(NetworkBehaviour)]
struct KintsugiBehaviour {
    kad: kad::Behaviour<MemoryStore>,
    identify: identify::Behaviour,
    mdns: mdns::tokio::Behaviour,
    request_response:
        request_response::json::Behaviour<messages::RequestMessage, messages::ResponseMessage>,
}

#[allow(deprecated)]
fn new_swarm(
    keypair: libp2p::identity::ed25519::Keypair,
) -> Result<Swarm<KintsugiBehaviour>, Box<dyn Error>> {
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

            Ok(KintsugiBehaviour {
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

fn handle_request(
    state_arc: Arc<Mutex<node_state::NodeState>>,
    swarm: &mut Swarm<KintsugiBehaviour>,
    peer_id: PeerId,
    request: messages::RequestMessage,
    channel: ResponseChannel<messages::ResponseMessage>,
) -> Result<(), Box<dyn Error>> {
    let mut state = state_arc.lock().unwrap();

    match request {
        messages::RequestMessage::OPRFRegInitMessage(msg) => {
            registration::handle_message_reg_init(&mut state, swarm, peer_id, msg, channel)
        }
        messages::RequestMessage::OPRFRegFinishReqMessage(msg) => {
            registration::handle_message_reg_finish_req(&mut state, swarm, peer_id, msg)?;
            local_files::update_recovery_shares_local(&mut state)
        }
        messages::RequestMessage::OPRFRecoveryStartReqMessage(msg) => {
            recovery::handle_message_rec_start_req(&mut state, swarm, peer_id, msg, channel)
        }
        messages::RequestMessage::DPSSRefreshInitMessage(msg) => {
            refresh::handle_message_dpss_init(&mut state, swarm, peer_id, msg)
        }
        messages::RequestMessage::DPSSRefreshReshareMessage(msg) => {
            refresh::handle_message_dpss_reshare(&mut state, swarm, peer_id, msg)?;
            local_files::update_recovery_shares_local(&mut state)
        }
        messages::RequestMessage::DPSSRefreshCompleteMessage(msg) => {
            let res = refresh::handle_message_dpss_complete(&mut state, swarm, peer_id, msg)?;
            if res {
                std::mem::drop(state);
                kad_interactions::update_recovery_addrs(state_arc.clone(), swarm)
            } else {
                Ok(())
            }
        }
    }
}

fn handle_response(
    state_arc: Arc<Mutex<node_state::NodeState>>,
    swarm: &mut Swarm<KintsugiBehaviour>,
    peer_id: PeerId,
    response: messages::ResponseMessage,
) -> Result<(), Box<dyn Error>> {
    let mut state = state_arc.lock().unwrap();

    match response {
        messages::ResponseMessage::OPRFRegStartRespMessage(msg) => {
            registration::handle_message_reg_start_resp(&mut state, swarm, peer_id, msg)
        }
        messages::ResponseMessage::OPRFRecoveryStartRespMessage(msg) => {
            recovery::handle_message_rec_start_resp(&mut state, swarm, peer_id, msg)
        }
    }
}
fn send_request_msg(
    swarm: &mut Swarm<KintsugiBehaviour>,
    state: &mut node_state::NodeState,
    username: String,
    msg: messages::RequestMessage,
) {
    let destination_peer_id = state.username_to_peer_id.get(&username);
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

fn add_peer(
    state_arc: Arc<Mutex<node_state::NodeState>>,
    swarm: &mut Swarm<KintsugiBehaviour>,
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
            if let Err(e) =
                registration::handle_username_update(state_arc.clone(), swarm, bootstrap_username)
            {
                println!("[BOOTSTRAP] Error updating username in DHT: {:?}", e);
            }
        }
    }
}

fn remove_peer(
    state_arc: Arc<Mutex<node_state::NodeState>>,
    swarm: &mut Swarm<KintsugiBehaviour>,
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

fn pass_tauri_handle(state_arc: Arc<Mutex<node_state::NodeState>>, handle: AppHandle) {
    let mut state = state_arc.lock().unwrap();
    state.tauri_handle = Some(handle);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let (tx, mut rx) = mpsc::channel::<tauri_interactions::TauriToRustCommand>(32);
    let mut state = node_state::NodeState {
        peer_id: PeerId::random(), // temp
        username: "".to_string(),  // temp
        opaque_keypair: Keypair::new(),
        libp2p_keypair_bytes: [0u8; 64],
        is_bootstrap: false,
        threshold: 1, // temp
        username_to_peer_id: HashMap::new(),
        username_to_index: HashMap::new(), // temp
        username_to_opaque_pkey: HashMap::new(),
        h_point: Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT,
        username_to_h_point_queries: HashMap::new(),
        opaque_node: P2POpaqueNode::new("".to_string()),
        peer_recoveries: HashMap::new(),
        registration_received: None,
        recovery_expecting: None,
        recovery_h_point: None,
        recovery_received: None,
        reshare_received: None,
        reshare_complete_received: None,
        kad_filtering: HashMap::new(),
        kad_done: HashSet::new(),
        waiting_for_peer_id: HashMap::new(),
        tauri_handle: None,
    };
    state.opaque_node.keypair = state.opaque_keypair.clone();
    let mut is_bootstrap = false;
    let mut bootstrap_keypair: libp2p::identity::ed25519::Keypair =
        libp2p::identity::ed25519::Keypair::generate();

    let args: Vec<String> = env::args().collect();
    if args.len() == 3 && args[1] != "BOOTSTRAP" {
        state.username = args[1].clone();
        state.peer_id = PeerId::from_str(&args[2])?;
    } else if args.len() == 3 && args[1] == "BOOTSTRAP" {
        is_bootstrap = true;
        node_state::BootstrapNodeState::setup_bootstrap(&mut state, args, &mut bootstrap_keypair)?;
    }

    if !is_bootstrap {
        state.peer_id = PeerId::from(libp2p::identity::PublicKey::from(
            bootstrap_keypair.public(),
        ));
    }

    local_files::read_recovery_shares_local(&mut state)?;
    local_files::read_envelopes_local(&mut state)?;

    let state_arc = Arc::new(Mutex::new(state));

    let mut swarm = new_swarm(bootstrap_keypair)?;

    tauri::async_runtime::set(tokio::runtime::Handle::current());
    tauri::Builder::default()
            .invoke_handler(tauri::generate_handler![
                tauri_interactions::get_peers,
                tauri_interactions::get_threshold,
                tauri_interactions::get_recovery_addresses,
                local_files::read_notepad,
                local_files::save_notepad,
                local_files::tauri_save_local_envelope,
                login::local_login,
                registration::local_register,
                recovery::local_recovery,
                refresh::local_refresh,
            ])
            .manage(tauri_interactions::TauriState(Arc::clone(&state_arc), tx))
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
                                tauri_interactions::TauriToRustCommand::RegStart(username, password, recovery_nodes, threshold) => {
                                    registration::handle_username_update(state_arc.clone(), &mut swarm, username).unwrap();
                                    registration::handle_reg_init(state_arc.clone(), &mut swarm, password, recovery_nodes, threshold).unwrap();
                                }
                                tauri_interactions::TauriToRustCommand::RecoveryStart(username, password, recovery_nodes, h_point) => {
                                    recovery::handle_recovery_init(state_arc.clone(), &mut swarm, username, password, recovery_nodes, h_point).unwrap();
                                }
                                tauri_interactions::TauriToRustCommand::RefreshStart(recovery_nodes, new_threshold) => {
                                    refresh::handle_refresh_init(state_arc.clone(), &mut swarm, recovery_nodes, new_threshold as usize).unwrap();
                                }
                                tauri_interactions::TauriToRustCommand::GetRecvAddrs(username) => {
                                    kad_interactions::handle_get_recv_addrs_init(&mut swarm, username);
                                }
                            },
                            event = swarm.select_next_some() => match event {
                                SwarmEvent::Behaviour(KintsugiBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                                    for (peer, multiaddr) in list {
                                        add_peer(state_arc.clone(), &mut swarm, peer, multiaddr);
                                    }
                                },
                                SwarmEvent::Behaviour(KintsugiBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                                    for (peer, multiaddr) in list {
                                        remove_peer(state_arc.clone(), &mut swarm, peer, multiaddr).unwrap();
                                    }
                                },
                                SwarmEvent::Behaviour(KintsugiBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, is_new_peer, .. })) => {
                                    println!("[KAD] Peer routing updated with peer {:?} ({:?})", peer, is_new_peer);
                                },
                                SwarmEvent::Behaviour(KintsugiBehaviourEvent::Kad(kad::Event::InboundRequest { request })) => {
                                     if let InboundRequest::PutRecord { record, .. } = request.clone() {
                                        kad_interactions::handle_kad_inbound_request(state_arc.clone(), &mut swarm, record.unwrap());
                                     }
                                },
                                SwarmEvent::Behaviour(KintsugiBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result, .. })) => {
                                    match result {
                                        kad::QueryResult::GetRecord(r) => {
                                            match r {
                                                Ok(GetRecordOk::FoundRecord(r_ok)) => kad_interactions::handle_kad_found_record(state_arc.clone(), &mut swarm, r_ok, id),
                                                Err(GetRecordError::NotFound{ key, .. }) => kad_interactions::handle_kad_no_add_record(state_arc.clone(), &mut swarm, id, key),
                                                _ => {}
                                            }
                                        }
                                        kad::QueryResult::PutRecord(Ok(kad::PutRecordOk { key })) => {
                                            println!(
                                                "[KAD] Successfully put record {:?}",
                                                std::str::from_utf8(key.as_ref()).unwrap()
                                            );
                                        },
                                        kad::QueryResult::PutRecord(Err(err)) => {
                                            println!("[KAD] Failed to put record: {err:?}");
                                        },
                                        _ => {}
                                    }
                                },
                                SwarmEvent::Behaviour(KintsugiBehaviourEvent::RequestResponse(
                                    request_response::Event::Message { message, peer },
                                )) => match message {
                                    request_response::Message::Request { request, channel, .. } => {
                                        handle_request(state_arc.clone(), &mut swarm, peer, request, channel).unwrap();
                                    }
                                    request_response::Message::Response { response, .. } => {
                                        handle_response(state_arc.clone(), &mut swarm, peer, response).unwrap();
                                    }
                                },
                                SwarmEvent::Behaviour(KintsugiBehaviourEvent::RequestResponse(
                                    request_response::Event::OutboundFailure { peer, request_id, error },
                                )) => {
                                    println!("[LOCAL] RR Outbound failure {:?} {:?} {:?}", peer,request_id, error);
                                }
                                SwarmEvent::Behaviour(KintsugiBehaviourEvent::RequestResponse(
                                    request_response::Event::InboundFailure { peer, request_id, error },
                                )) => {
                                    println!("[LOCAL] RR Inbound failure {:?} {:?} {:?}", peer,request_id, error);
                                }
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
