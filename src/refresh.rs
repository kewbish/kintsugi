use crate::kintsugi_lib::acss::ACSSNodeShare;
use crate::kintsugi_lib::acss::ACSS;
use crate::kintsugi_lib::dpss::DPSS;
use crate::kintsugi_lib::keypair::PublicKey;
use crate::kintsugi_lib::util::i32_to_scalar;
use crate::messages;
use crate::node_state;
use crate::send_request_msg;
use crate::tauri_interactions;
use crate::KintsugiBehaviour;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use libp2p::{PeerId, Swarm};
use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::sync::{Arc, Mutex};
use tauri::{Emitter, State};

pub fn handle_refresh_init(
    state_arc: Arc<Mutex<node_state::NodeState>>,
    swarm: &mut Swarm<KintsugiBehaviour>,
    new_recovery_addresses: HashMap<String, i32>,
    new_threshold: usize,
) -> Result<(), Box<dyn Error>> {
    let mut state = state_arc.lock().unwrap();
    if new_threshold > new_recovery_addresses.len() {
        return Err(Box::from(
            "Not enough recovery addresses for this threshold",
        ));
    }

    let username_to_index_map = state.username_to_index.clone();
    for (username, index) in username_to_index_map.iter() {
        let init_message =
            messages::RequestMessage::DPSSRefreshInitMessage(messages::DPSSRefreshInitMessage {
                new_recovery_addresses: new_recovery_addresses.clone(),
                new_threshold,
                old_committee_size: username_to_index_map.len(),
                user_username: state.username.clone(),
                node_index: index.clone(),
                node_username: username.clone(),
            });

        send_request_msg(swarm, &mut state, username.clone(), init_message);
        println!(
            "[DPSS INIT] Sending init message for user {} to index {}",
            state.username, index
        );
    }

    state.reshare_complete_received = None;

    Ok(())
}

pub fn handle_message_dpss_init(
    state: &mut node_state::NodeState,
    swarm: &mut Swarm<KintsugiBehaviour>,
    _peer_id: PeerId,
    message: messages::DPSSRefreshInitMessage,
) -> Result<(), Box<dyn Error>> {
    let (node_share, _) = state.peer_recoveries.get(&message.user_username).unwrap();

    let peer_public_keys: HashMap<String, PublicKey> = message
        .new_recovery_addresses
        .iter()
        .map(|(k, _)| {
            (
                k.clone(),
                state.username_to_opaque_pkey.get(k).unwrap().clone(),
            )
        })
        .collect();

    let (acss_dealer_share_s, _, _) = ACSS::share_dealer(
        state.h_point,
        node_share.s_i_d,
        message.new_threshold - 1,
        state.opaque_keypair.private_key,
        peer_public_keys.clone(),
        message.new_recovery_addresses.clone(),
    )?;

    let (acss_dealer_share_s_hat, _, _) = ACSS::share_dealer(
        state.h_point,
        node_share.s_hat_i_d,
        message.new_threshold - 1,
        state.opaque_keypair.private_key,
        peer_public_keys,
        message.new_recovery_addresses.clone(),
    )?;

    let old_commitment = state
        .peer_recoveries
        .get(&message.user_username)
        .unwrap()
        .0
        .c_i;

    for (username, index) in message.new_recovery_addresses.iter() {
        let reshare_msg = messages::DPSSRefreshReshareMessage {
            h_point: state.h_point,
            dealer_shares: acss_dealer_share_s.clone(),
            dealer_shares_hat: acss_dealer_share_s_hat.clone(),
            dealer_key: state.opaque_keypair.public_key,
            new_recovery_addresses: message.new_recovery_addresses.clone(),
            new_threshold: message.new_threshold,
            old_committee_size: message.old_committee_size,
            old_commitment,
            user_username: message.user_username.clone(),
            from_index: message.node_index.clone(),
            node_index: index.clone(),
            node_username: state.username.clone(),
        };
        if username.clone() == state.username {
            if let Err(e) = handle_message_dpss_reshare(state, swarm, state.peer_id, reshare_msg) {
                println!("[DPSS REFR INIT] To self failed with error {:?}", e);
            }
        } else {
            let reshare_msg_wrapped =
                messages::RequestMessage::DPSSRefreshReshareMessage(reshare_msg);
            send_request_msg(swarm, state, username.clone(), reshare_msg_wrapped);
        }

        println!(
            "[DPSS REFR INIT] Sending initial ACSS reshares for user {} at {}, index {}",
            state.username,
            username.clone(),
            index,
        );
    }

    if !message.new_recovery_addresses.contains_key(&state.username) {
        state.peer_recoveries.remove(&message.user_username);
    }

    Ok(())
}

pub fn handle_message_dpss_reshare(
    state: &mut node_state::NodeState,
    swarm: &mut Swarm<KintsugiBehaviour>,
    _peer_id: PeerId,
    message: messages::DPSSRefreshReshareMessage,
) -> Result<(), Box<dyn Error>> {
    let node_share = ACSS::share(
        message.h_point,
        message.dealer_shares.get(&state.username).unwrap().clone(),
        state.opaque_keypair.clone(),
        message.dealer_key,
    )?;
    let node_share_hat = ACSS::share(
        message.h_point,
        message
            .dealer_shares_hat
            .get(&state.username)
            .unwrap()
            .clone(),
        state.opaque_keypair.clone(),
        message.dealer_key,
    )?;

    let mut s: HashMap<String, (ACSSNodeShare, ACSSNodeShare, i32, RistrettoPoint)>;
    if let None = state.reshare_received {
        s = HashMap::new();
    } else {
        s = state.reshare_received.take().unwrap();
    }

    s.insert(
        message.node_username.clone(),
        (
            node_share,
            node_share_hat,
            message.from_index,
            message.old_commitment,
        ),
    );

    state.reshare_received = Some(s.clone());

    // because MVBA isn't implemented, we require all prior nodes to participate in refresh to
    // avoid having to agree on a subset of them (Algorithm 3, line 206, DPSS Yurek et al. paper)
    if s.len() != message.old_committee_size {
        return Ok(());
    }

    let evaluations: HashMap<Scalar, Scalar> = s
        .iter()
        .map(|(_, v)| (i32_to_scalar(v.2), v.0.s_i_d))
        .collect();
    let evaluations_hat: HashMap<Scalar, Scalar> = s
        .iter()
        .map(|(_, v)| (i32_to_scalar(v.2), v.1.s_i_d))
        .collect();
    let commitments: HashMap<Scalar, RistrettoPoint> =
        s.iter().map(|(_, v)| (i32_to_scalar(v.2), v.3)).collect();
    let (s_i_d_prime, s_hat_i_d_prime) = DPSS::reshare_w_evals(evaluations, evaluations_hat)?;
    let commitment_i =
        DPSS::get_commitment_at_index(i32_to_scalar(message.node_index), commitments);

    state.peer_recoveries.insert(
        message.user_username.clone(),
        (
            ACSSNodeShare {
                s_i_d: s_i_d_prime.clone(),
                s_hat_i_d: s_hat_i_d_prime,
                c_i: commitment_i.clone(),
            },
            message.node_index,
        ),
    );

    let complete_msg = messages::RequestMessage::DPSSRefreshCompleteMessage(
        messages::DPSSRefreshCompleteMessage {
            new_threshold: message.new_threshold,
            new_recovery_addresses: message.new_recovery_addresses,
            user_username: message.user_username.clone(),
            node_username: state.username.clone(),
        },
    );
    send_request_msg(swarm, state, message.user_username, complete_msg);

    state.reshare_received = None;

    println!("[DPSS RESH] Successfully refreshed secret shares");

    Ok(())
}

pub fn handle_message_dpss_complete(
    state: &mut node_state::NodeState,
    _swarm: &mut Swarm<KintsugiBehaviour>,
    _peer_id: PeerId,
    message: messages::DPSSRefreshCompleteMessage,
) -> Result<bool, Box<dyn Error>> {
    let mut s: HashSet<String>;
    if let None = state.reshare_complete_received {
        s = HashSet::new();
    } else {
        s = state.reshare_complete_received.take().unwrap();
    }

    s.insert(message.node_username.clone());

    state.reshare_complete_received = Some(s.clone());

    if s.len() != message.new_threshold {
        return Ok(false);
    }

    state.threshold = message.new_threshold;
    state.username_to_index = message.new_recovery_addresses;

    if let Err(e) = state
        .tauri_handle
        .clone()
        .unwrap()
        .emit("refresh", tauri_interactions::TauriRefrFinished {})
    {
        println!("[DPSS COMP] Tauri could not emit refresh complete: {:?}", e);
    } else {
        println!("[DPSS COMP] Successfully refreshed shares");
    }

    Ok(true)
}

#[tauri::command]
pub fn local_refresh(
    state: State<tauri_interactions::TauriState>,
    new_recovery_addresses: HashMap<String, i32>,
    new_threshold: i32,
) -> Result<(), String> {
    let tx_clone = state.1.clone();

    let node_state = state.0.lock().unwrap();
    for address in new_recovery_addresses.keys() {
        if !node_state.username_to_peer_id.contains_key(address) {
            return Err(format!("Recovery node {address} could not be found"));
        }
    }

    tauri::async_runtime::spawn(async move {
        tx_clone
            .send(tauri_interactions::TauriToRustCommand::RefreshStart(
                new_recovery_addresses,
                new_threshold,
            ))
            .await
            .unwrap();
    });
    Ok(())
}
