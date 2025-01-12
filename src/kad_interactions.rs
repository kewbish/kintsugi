use crate::{
    kintsugi_lib::{
        keypair::{Keypair, PublicKey},
        signature::Signature,
    },
    node_state, tauri_interactions, KintsugiBehaviour,
};
use curve25519_dalek::ristretto::CompressedRistretto;
use libp2p::{
    kad::{self, store::RecordStore, PeerRecord, QueryId, Record, RecordKey},
    PeerId, Swarm,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};
use std::{error::Error, num::NonZeroUsize};
use tauri::Emitter;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct KadRecord {
    pub(crate) data: KadRecordType,
    pub(crate) username: String,
    pub(crate) signature: Signature,
}

impl KadRecord {
    pub fn new(
        key: RecordKey,
        data: KadRecordType,
        username: String,
        publisher: PeerId,
        signing_keypair: Keypair,
    ) -> (Self, Record) {
        let mut data_to_sign = key.to_vec();
        data_to_sign.extend_from_slice(username.as_bytes());
        let serialized_data = serde_json::to_vec(&data).unwrap();
        data_to_sign.extend(serialized_data);
        let kad_record = KadRecord {
            data,
            username,
            signature: Signature::new_with_keypair(data_to_sign.as_slice(), signing_keypair),
        };
        let record = Record {
            key,
            value: serde_json::to_vec(&kad_record).unwrap(),
            publisher: Some(publisher),
            expires: None,
        };
        (kad_record, record)
    }
    pub fn signed_data(&self) -> Vec<u8> {
        let mut vec = Vec::from(self.username.as_bytes());
        let serialized_data = serde_json::to_vec(&self.data).unwrap();
        vec.extend(serialized_data);
        vec
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub enum KadRecordType {
    Pk(PublicKey),
    RecvAddr(BTreeMap<String, i32>, usize, [u8; 32]),
    PeerId(PeerId),
}

pub fn handle_kad_inbound_request(
    state_arc: Arc<Mutex<node_state::NodeState>>,
    swarm: &mut Swarm<KintsugiBehaviour>,
    record: Record,
) {
    let mut state = state_arc.lock().unwrap();

    let deserialized_record: KadRecord = serde_json::from_slice(record.value.as_slice()).unwrap();
    let query_id = swarm
        .behaviour_mut()
        .kad
        .get_record(RecordKey::new(&format!(
            "/pk/{}",
            deserialized_record.username
        )));

    println!(
        "[KAD] Received inbound request for {:?}, putting at query ID {:?}",
        record.clone().key,
        query_id
    );
    state.kad_filtering.insert(query_id, record.clone());
}

pub fn handle_kad_data_store_emit(
    state_arc: Arc<Mutex<node_state::NodeState>>,
    swarm: &mut Swarm<KintsugiBehaviour>,
    deserialized_record: KadRecord,
    record: Record,
) {
    let mut state = state_arc.lock().unwrap();

    match deserialized_record.data {
        KadRecordType::Pk(public_key) => {
            state
                .username_to_opaque_pkey
                .insert(deserialized_record.username.clone(), public_key);
        }
        KadRecordType::RecvAddr(recovery_addresses, threshold, h_point) => {
            let recovery_addresses_hashmap = HashMap::from_iter(
                recovery_addresses
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone())),
            );
            if let Err(e) = state.tauri_handle.clone().unwrap().emit(
                "recv_addr",
                tauri_interactions::TauriRecvAddr {
                    username: deserialized_record.username.clone(),
                    recovery_addresses: recovery_addresses_hashmap,
                    threshold,
                    error: None,
                },
            ) {
                println!("[KAD] Tauri could not emit recovery addresses: {:?}", e);
            } else {
                println!("[KAD] Emitted Tauri update")
            }
            state.username_to_h_point_queries.insert(
                deserialized_record.username,
                CompressedRistretto::from_slice(&h_point)
                    .unwrap()
                    .decompress()
                    .unwrap(),
            );
        }
        KadRecordType::PeerId(peer_id) => {
            let username_peer_id_map = state.username_to_peer_id.clone();
            for (k, v) in username_peer_id_map.iter() {
                if v.clone() == peer_id.clone() {
                    state.username_to_peer_id.remove(k);
                }
            }
            state.username_to_peer_id.insert(
                deserialized_record.username.clone(),
                record.publisher.unwrap(),
            );

            let queued_msgs_option = state.waiting_for_peer_id.get(&deserialized_record.username);
            if let Some(queued_msgs) = queued_msgs_option {
                for msg in queued_msgs.iter() {
                    swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer_id, msg.clone());
                }
            }
        }
    }
}

pub fn handle_kad_found_record(
    state_arc: Arc<Mutex<node_state::NodeState>>,
    swarm: &mut Swarm<KintsugiBehaviour>,
    pk_record: PeerRecord,
    query_id: QueryId,
) {
    let mut state = state_arc.lock().unwrap();

    if state.kad_done.contains(&query_id) {
        return;
    }

    let kad_filtering = state.kad_filtering.clone();
    let actual_record = kad_filtering.get(&query_id);
    if let None = actual_record {
        let deserialized_actual_record: KadRecord =
            serde_json::from_slice(pk_record.record.value.as_slice()).unwrap();
        let peer_pkey = state
            .username_to_opaque_pkey
            .get(&deserialized_actual_record.username)
            .unwrap();
        let mut signature_message = pk_record.record.key.to_vec();
        signature_message.extend(deserialized_actual_record.signed_data());
        if deserialized_actual_record
            .clone()
            .signature
            .verify(signature_message.as_slice(), peer_pkey.clone())
        {
            println!(
                "[KAD] Found, processing data from final record {:?}",
                pk_record.clone().record.key
            );
            state.kad_done.insert(query_id);
            // the only get without filtering should be for the recv addrs
            if let KadRecordType::RecvAddr(_, _, _) = deserialized_actual_record.data {
                std::mem::drop(state);
                handle_kad_data_store_emit(
                    state_arc.clone(),
                    swarm,
                    deserialized_actual_record,
                    pk_record.record.clone(),
                );
            }
        }
    } else {
        let actual_record = actual_record.unwrap();
        let deserialized_pk_record: KadRecord =
            serde_json::from_slice(pk_record.record.value.as_slice()).unwrap();
        let deserialized_actual_record: KadRecord =
            serde_json::from_slice(actual_record.value.as_slice()).unwrap();
        // shouldn't be any other record type
        if let KadRecordType::Pk(public_key) = deserialized_pk_record.data {
            let mut signature_message = actual_record.key.to_vec();
            signature_message.extend(deserialized_actual_record.signed_data());
            if deserialized_actual_record
                .clone()
                .signature
                .verify(signature_message.as_slice(), public_key)
            {
                if let Err(e) = swarm
                    .behaviour_mut()
                    .kad
                    .store_mut()
                    .put(actual_record.clone())
                {
                    println!(
                        "[KAD] Found, could not store final record {:?}",
                        &e.to_string(),
                    );
                } else {
                    println!(
                        "[KAD] Found, stored final record {:?}",
                        actual_record.clone().key
                    );
                    state.kad_filtering.remove(&query_id);
                    state.kad_done.insert(query_id);
                    std::mem::drop(state);
                    handle_kad_data_store_emit(
                        state_arc.clone(),
                        swarm,
                        deserialized_actual_record,
                        actual_record.clone(),
                    );
                }
            }
        }
    }
}

pub fn handle_kad_no_add_record(
    state_arc: Arc<Mutex<node_state::NodeState>>,
    swarm: &mut Swarm<KintsugiBehaviour>,
    query_id: QueryId,
    key: RecordKey,
) {
    let mut state = state_arc.lock().unwrap();

    if state.kad_done.contains(&query_id) {
        return;
    }

    let kad_filtering = state.kad_filtering.clone();
    let actual_record = kad_filtering.get(&query_id);
    if let None = actual_record {
        let key_str = String::from_utf8(key.to_vec()).unwrap();
        if key_str.starts_with("/recv_addr/") {
            let username = key_str.strip_prefix("/recv_addr/").unwrap().to_string();
            if let Err(e) = state.tauri_handle.clone().unwrap().emit(
                "recv_addr",
                tauri_interactions::TauriRecvAddr {
                    username: username.clone(),
                    recovery_addresses: HashMap::new(),
                    threshold: 0,
                    error: Some(format!(
                        "Recovery addresses for {} could not be found",
                        username
                    )),
                },
            ) {
                println!(
                    "[KAD] Tauri could not emit recovery addresses error: {:?}",
                    e
                );
            } else {
                println!("[KAD] Emitted Tauri update, not found")
            }
        }
        return;
    }
    let actual_record = actual_record.unwrap();
    if let Err(e) = swarm
        .behaviour_mut()
        .kad
        .store_mut()
        .put(actual_record.clone())
    {
        println!(
            "[KAD] DNF, could not store final record {:?}",
            &e.to_string(),
        );
    } else {
        println!(
            "[KAD] DNF, stored final record {:?}",
            actual_record.clone().key
        );
        state.kad_filtering.remove(&query_id);
        state.kad_done.insert(query_id);

        std::mem::drop(state);
        let deserialized_actual_record: KadRecord =
            serde_json::from_slice(actual_record.value.as_slice()).unwrap();
        handle_kad_data_store_emit(
            state_arc.clone(),
            swarm,
            deserialized_actual_record,
            actual_record.clone(),
        );
    }
}

pub fn handle_get_recv_addrs_init(swarm: &mut Swarm<KintsugiBehaviour>, username: String) {
    let query_id = swarm
        .behaviour_mut()
        .kad
        .get_record(RecordKey::new(&format!("/recv_addr/{}", username.clone())));

    println!(
        "[RECOVERY GET] Getting recovery addresses for {:?} at query ID {:?}",
        RecordKey::new(&format!("/recv_addr/{}", username.clone())),
        query_id
    );
}

pub fn update_recovery_addrs(
    state_arc: Arc<Mutex<node_state::NodeState>>,
    swarm: &mut Swarm<KintsugiBehaviour>,
) -> Result<(), Box<dyn Error>> {
    let state = state_arc.lock().unwrap();

    let (_recv_addr_kad_record, recv_addr_record) = KadRecord::new(
        RecordKey::new(&format!("/recv_addr/{}", state.username)),
        KadRecordType::RecvAddr(
            BTreeMap::from_iter(
                state
                    .username_to_index
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone())),
            ),
            state.threshold,
            state.h_point.compress().to_bytes(),
        ),
        state.username.clone(),
        state.peer_id,
        state.opaque_keypair.clone(),
    );

    swarm.behaviour_mut().kad.put_record(
        recv_addr_record.clone(),
        kad::Quorum::N(NonZeroUsize::new(state.threshold).unwrap()),
    )?;

    Ok(())
}
