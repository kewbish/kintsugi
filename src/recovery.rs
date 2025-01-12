use crate::messages;
use crate::node_state;
use crate::send_request_msg;
use crate::tauri_interactions;
use crate::KintsugiBehaviour;
use curve25519_dalek::RistrettoPoint;
use libp2p::request_response::ResponseChannel;
use libp2p::{PeerId, Swarm};
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use tauri::{Emitter, State};

pub fn handle_recovery_init(
    state_arc: Arc<Mutex<node_state::NodeState>>,
    swarm: &mut Swarm<KintsugiBehaviour>,
    _username: String,
    password: String,
    recovery_addresses: HashMap<String, i32>,
    h_point: RistrettoPoint,
) -> Result<(), Box<dyn Error>> {
    let mut state = state_arc.lock().unwrap();

    state.recovery_received = Some(HashMap::new());
    state.recovery_expecting = Some(recovery_addresses.len());

    for (username, index) in recovery_addresses.iter() {
        let recovery_start_req = state
            .opaque_node
            .local_login_start(password.clone(), username.clone())?;

        let login_start_req = messages::RequestMessage::OPRFRecoveryStartReqMessage(
            messages::OPRFRecoveryStartReqMessage {
                recovery_start_req: recovery_start_req.clone(),
                h_point,
                user_username: state.username.clone(),
                node_index: index.clone(),
                node_username: username.clone(),
            },
        );

        send_request_msg(swarm, &mut state, username.clone(), login_start_req);
        println!(
            "[REC INIT] Sending initial req for user {} at index {}",
            state.username, index
        );
    }

    Ok(())
}

pub fn handle_message_rec_start_req(
    state: &mut node_state::NodeState,
    swarm: &mut Swarm<KintsugiBehaviour>,
    _peer_id: PeerId,
    message: messages::OPRFRecoveryStartReqMessage,
    channel: ResponseChannel<messages::ResponseMessage>,
) -> Result<(), Box<dyn Error>> {
    let (node_share, _) = state.peer_recoveries.get(&message.user_username).unwrap();
    let rec_start_resp = state.opaque_node.peer_login_start(
        message.recovery_start_req,
        node_share.s_i_d,
        message.node_index,
    )?;
    let rec_start_resp_message = messages::ResponseMessage::OPRFRecoveryStartRespMessage(
        messages::OPRFRecoveryStartRespMessage {
            recovery_start_resp: rec_start_resp,
            h_point: message.h_point,
            user_username: message.user_username.clone(),
            node_index: message.node_index,
            node_username: state.username.clone(),
        },
    );

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

pub fn handle_message_rec_start_resp(
    state: &mut node_state::NodeState,
    _swarm: &mut Swarm<KintsugiBehaviour>,
    _peer_id: PeerId,
    message: messages::OPRFRecoveryStartRespMessage,
) -> Result<(), Box<dyn Error>> {
    if let None = state.recovery_received {
        return Ok(());
    }

    let mut s = state.recovery_received.take().unwrap();
    s.insert(message.node_username.clone(), message.recovery_start_resp);
    state.recovery_h_point = Some(message.h_point);

    state.recovery_received = Some(s.clone());

    if s.len() != state.recovery_expecting.unwrap() {
        return Ok(());
    }

    let opaque_keypair = state
        .opaque_node
        .local_login_finish(s.values().map(|v| v.clone()).collect());
    match opaque_keypair {
        Ok(opaque_keypair) => {
            state.opaque_keypair = opaque_keypair.clone();
            state.opaque_node.keypair = opaque_keypair;

            if let Err(e) = state.tauri_handle.clone().unwrap().emit(
                "recovery",
                tauri_interactions::TauriRecFinished {
                    username: state.username.clone(),
                    error: None,
                },
            ) {
                println!("[REC START RESP] Tauri could not emit recovery: {:?}", e);
            } else {
                println!("[REC START RESP] Successfully recovered keypair");
            }
        }
        Err(decryption_err) => {
            if let Err(e) = state.tauri_handle.clone().unwrap().emit(
                "recovery",
                tauri_interactions::TauriRecFinished {
                    username: state.username.clone(),
                    error: Some(decryption_err.to_string()),
                },
            ) {
                println!(
                    "[REC START RESP] Tauri could not emit recovery error: {:?}",
                    e
                );
            }
        }
    }

    state.h_point = state.recovery_h_point.unwrap();
    state.recovery_h_point = None;

    Ok(())
}

#[tauri::command]
pub fn local_recovery(
    state: State<tauri_interactions::TauriState>,
    username: String,
    password: String,
    recovery_addresses: HashMap<String, i32>,
) -> Result<(), String> {
    let mut node_state = state.0.lock().unwrap();

    if !node_state.username_to_peer_id.contains_key(&username) {
        return Err(format!("User {username} could not be found"));
    }

    for address in recovery_addresses.keys() {
        if !node_state.username_to_peer_id.contains_key(address) {
            return Err(format!("Recovery node {address} could not be found"));
        }
    }

    node_state.username = username.clone();
    node_state.opaque_node.id = username.clone();
    let h_point = node_state.username_to_h_point_queries.get(&username);
    if let None = h_point {
        return Err(format!("User recovery config was incomplete"));
    }
    let h_point = h_point.unwrap().clone();

    let tx_clone = state.1.clone();
    tauri::async_runtime::spawn(async move {
        tx_clone
            .send(tauri_interactions::TauriToRustCommand::RecoveryStart(
                username,
                password,
                recovery_addresses,
                h_point,
            ))
            .await
            .unwrap();
    });
    Ok(())
}
