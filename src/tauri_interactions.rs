use crate::node_state;
use curve25519_dalek::RistrettoPoint;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::State;

pub struct TauriState(
    pub(crate) Arc<Mutex<node_state::NodeState>>,
    pub(crate) tokio::sync::mpsc::Sender<TauriToRustCommand>,
);

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct TauriRecvAddr {
    pub(crate) username: String,
    pub(crate) recovery_addresses: HashMap<String, i32>,
    pub(crate) threshold: usize,
    pub(crate) error: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct TauriRecFinished {
    pub(crate) username: String,
    pub(crate) error: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct TauriRefrFinished {}

pub enum TauriToRustCommand {
    RegStart(String, String, HashMap<String, i32>, usize),
    RecoveryStart(String, String, HashMap<String, i32>, RistrettoPoint),
    RefreshStart(HashMap<String, i32>, i32),
    GetRecvAddrs(String),
}

#[tauri::command]
pub fn get_peers(state: State<TauriState>) -> Vec<String> {
    let node_state = state.0.lock().unwrap();
    return Vec::from_iter(node_state.username_to_index.keys().map(|v| v.to_string()));
}

#[tauri::command]
pub fn get_threshold(state: State<TauriState>) -> i32 {
    let node_state = state.0.lock().unwrap();
    node_state.threshold.try_into().unwrap()
}

#[tauri::command]
pub fn get_recovery_addresses(state: State<TauriState>, username: String) {
    let tx_clone = state.1.clone();
    tauri::async_runtime::spawn(async move {
        tx_clone
            .send(TauriToRustCommand::GetRecvAddrs(username))
            .await
            .unwrap();
    });
}
