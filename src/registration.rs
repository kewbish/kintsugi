use crate::kad_interactions;
use crate::kintsugi_lib::acss::ACSS;
use crate::local_files;
use crate::messages;
use crate::node_state;
use crate::send_request_msg;
use crate::tauri_interactions;
use crate::KintsugiBehaviour;
use curve25519_dalek::Scalar;
use libp2p::kad::{self, RecordKey};
use libp2p::request_response::ResponseChannel;
use libp2p::{PeerId, Swarm};
use rand::rngs::OsRng;
#[allow(unused_imports)]
use rand::RngCore;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use tauri::State;

pub fn handle_username_update(
    state_arc: Arc<Mutex<node_state::NodeState>>,
    swarm: &mut Swarm<KintsugiBehaviour>,
    username: String,
) -> Result<(), String> {
    if username != "" {
        let mut state = state_arc.lock().unwrap();

        state.username = username.clone();
        state.opaque_node.id = username.clone();
        let pkey = state.opaque_keypair.public_key.clone();
        state.username_to_opaque_pkey.insert(username.clone(), pkey);
        let peer_id = state.peer_id.clone();
        state.username_to_peer_id.insert(username.clone(), peer_id);

        let (_peer_id_kad_record, peer_id_record) = kad_interactions::KadRecord::new(
            RecordKey::new(&format!("/peer_id/{}", state.username)),
            kad_interactions::KadRecordType::PeerId(state.peer_id),
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

        let (_pk_kad_record, pk_record) = kad_interactions::KadRecord::new(
            RecordKey::new(&format!("/pk/{}", state.username)),
            kad_interactions::KadRecordType::Pk(state.opaque_keypair.clone().public_key),
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
    }

    Ok(())
}

pub fn handle_reg_init(
    state_arc: Arc<Mutex<node_state::NodeState>>,
    swarm: &mut Swarm<KintsugiBehaviour>,
    password: String,
    recovery_addresses: HashMap<String, i32>,
    threshold: usize,
) -> Result<(), Box<dyn Error>> {
    let mut state = state_arc.lock().unwrap();

    let peer_public_keys = recovery_addresses
        .iter()
        .map(|(k, _)| {
            (
                k.clone(),
                state.username_to_opaque_pkey.get(k).unwrap().clone(),
            )
        })
        .collect();

    let s = Scalar::random(&mut OsRng);
    let (acss_dealer_shares, _, _) = ACSS::share_dealer(
        state.h_point,
        s,
        threshold - 1,
        state.opaque_keypair.private_key,
        peer_public_keys,
        recovery_addresses.clone(),
    )?;
    state.registration_received = Some(HashMap::new());

    state.threshold = threshold;
    for (username, index) in recovery_addresses.iter() {
        state
            .username_to_index
            .insert(username.clone(), index.clone());

        let reg_start_req = state
            .opaque_node
            .local_registration_start(password.clone(), username.clone())?;

        let init_message =
            messages::RequestMessage::OPRFRegInitMessage(messages::OPRFRegInitMessage {
                h_point: state.h_point,
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

    kad_interactions::update_recovery_addrs(state_arc.clone(), swarm)?;

    Ok(())
}

pub fn handle_message_reg_init(
    state: &mut node_state::NodeState,
    swarm: &mut Swarm<KintsugiBehaviour>,
    _peer_id: PeerId,
    message: messages::OPRFRegInitMessage,
    channel: ResponseChannel<messages::ResponseMessage>,
) -> Result<(), Box<dyn Error>> {
    let node_share = ACSS::share(
        message.h_point,
        message
            .dealer_shares
            .get(&state.username.clone())
            .unwrap()
            .clone(),
        state.opaque_keypair.clone(),
        message.dealer_key,
    )?;

    state.peer_recoveries.insert(
        message.user_username.clone(),
        (node_share.clone(), message.node_index),
    );

    let reg_start_resp = state.opaque_node.peer_registration_start(
        message.reg_start_req,
        node_share.s_i_d,
        message.node_index,
    )?;
    let reg_start_resp_message =
        messages::ResponseMessage::OPRFRegStartRespMessage(messages::OPRFRegStartRespMessage {
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

pub fn handle_message_reg_start_resp(
    state: &mut node_state::NodeState,
    swarm: &mut Swarm<KintsugiBehaviour>,
    _peer_id: PeerId,
    message: messages::OPRFRegStartRespMessage,
) -> Result<(), Box<dyn Error>> {
    if let None = state.registration_received {
        return Ok(());
    }

    let mut s = state.registration_received.take().unwrap();
    s.insert(message.node_username, message.reg_start_resp.clone());
    state.registration_received = Some(s.clone());

    if s.len() != state.threshold {
        return Ok(());
    }

    let reg_finish_reqs = state
        .opaque_node
        .local_registration_finish(s.values().map(|v| v.clone()).collect())?;
    let username_to_index_map = state.username_to_index.clone();
    for (username, index) in username_to_index_map {
        let mut reg_finish_req = reg_finish_reqs.iter().next().unwrap().clone();
        reg_finish_req.node_username = username.clone();
        let reg_finish_req_message =
            messages::RequestMessage::OPRFRegFinishReqMessage(messages::OPRFRegFinishReqMessage {
                reg_finish_req,
                user_username: state.username.clone(),
                node_index: index.clone(),
                node_username: username.clone(),
            });

        send_request_msg(swarm, state, username.clone(), reg_finish_req_message);
        println!(
            "[REG START RESP] Sending reg start finish message for user {} at index {}",
            state.username, index
        );
    }

    Ok(())
}

pub fn handle_message_reg_finish_req(
    state: &mut node_state::NodeState,
    _swarm: &mut Swarm<KintsugiBehaviour>,
    _peer_id: PeerId,
    message: messages::OPRFRegFinishReqMessage,
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

#[tauri::command]
pub fn local_register(
    state: State<tauri_interactions::TauriState>,
    username: String,
    password: String,
    recovery_addresses: HashMap<String, i32>,
    threshold: usize,
) -> Result<(), String> {
    let mut node_state = state.0.lock().unwrap();

    if node_state.username_to_peer_id.contains_key(&username) {
        return Err("Username is already taken.".to_string());
    }

    for address in recovery_addresses.keys() {
        if !node_state.username_to_peer_id.contains_key(address) {
            return Err(format!("Recovery node {address} could not be found"));
        }
    }

    node_state.username = username.clone();
    node_state.username_to_index = recovery_addresses.clone();
    local_files::save_local_envelope(
        username.clone(),
        password.clone(),
        node_state.opaque_keypair.clone(),
    )?;

    let tx_clone = state.1.clone();
    let username = node_state.username.clone();
    let password_clone = password.clone();
    tauri::async_runtime::spawn(async move {
        tx_clone
            .send(tauri_interactions::TauriToRustCommand::RegStart(
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
