use crate::kintsugi_lib::keypair::{Keypair, PublicKey};
use crate::kintsugi_lib::opaque::{LoginStartResponse, RegStartResponse};
use crate::kintsugi_lib::{acss::ACSSNodeShare, opaque::P2POpaqueNode};
use crate::messages::RequestMessage;
use curve25519_dalek::RistrettoPoint;
use libp2p::{
    kad::{QueryId, Record},
    PeerId,
};
use serde_with::{serde_as, Bytes};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::Path;
use tauri::AppHandle;

#[derive(Debug, Clone)]
pub struct NodeState {
    pub(crate) peer_id: PeerId,
    pub(crate) username: String,
    pub(crate) opaque_keypair: Keypair,
    pub(crate) libp2p_keypair_bytes: [u8; 64],
    pub(crate) is_bootstrap: bool,
    pub(crate) threshold: usize,
    pub(crate) username_to_peer_id: HashMap<String, PeerId>,
    pub(crate) username_to_index: HashMap<String, i32>, // this node's recovery nodes' indices
    pub(crate) username_to_opaque_pkey: HashMap<String, PublicKey>,
    pub(crate) h_point: RistrettoPoint,
    // volatile, temporary map populated by Kademlia queries
    pub(crate) username_to_h_point_queries: HashMap<String, RistrettoPoint>,
    pub(crate) opaque_node: P2POpaqueNode,
    // the indices for nodes for which this node is a recovery node
    pub(crate) peer_recoveries: HashMap<String, (ACSSNodeShare, i32)>,
    pub(crate) registration_received: Option<HashMap<String, RegStartResponse>>,
    pub(crate) recovery_expecting: Option<usize>,
    pub(crate) recovery_h_point: Option<RistrettoPoint>,
    pub(crate) recovery_received: Option<HashMap<String, LoginStartResponse>>,
    pub(crate) reshare_received:
        Option<HashMap<String, (ACSSNodeShare, ACSSNodeShare, i32, RistrettoPoint)>>,
    pub(crate) reshare_complete_received: Option<HashSet<String>>,
    pub(crate) kad_filtering: HashMap<QueryId, Record>,
    pub(crate) kad_done: HashSet<QueryId>,
    pub(crate) waiting_for_peer_id: HashMap<String, Vec<RequestMessage>>,
    pub(crate) tauri_handle: Option<AppHandle>,
}

#[serde_as]
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct BootstrapNodeState {
    pub(crate) peer_id: PeerId,
    pub(crate) opaque_keypair: Keypair,
    #[serde_as(as = "Bytes")]
    pub(crate) libp2p_keypair_bytes: [u8; 64],
}

impl BootstrapNodeState {
    pub fn setup_bootstrap(
        state: &mut NodeState,
        args: Vec<String>,
        bootstrap_keypair: &mut libp2p::identity::ed25519::Keypair,
    ) -> Result<(), Box<dyn Error>> {
        state.is_bootstrap = true;
        let file_path = format!("tmp/bootstrap_0.envelope");
        if Path::new(&file_path).exists() {
            let parsed_index: i32 = args[2].parse()?;
            let file_path = format!("tmp/bootstrap_{}.envelope", parsed_index);
            let contents = std::fs::read_to_string(file_path);
            let bootstrap_node_state: BootstrapNodeState =
                serde_json::from_str(&contents.unwrap())?;

            state.username = format!("bootstrap{parsed_index}");
            state.peer_id = bootstrap_node_state.peer_id;
            state.libp2p_keypair_bytes = bootstrap_node_state.libp2p_keypair_bytes;
            *bootstrap_keypair = libp2p::identity::ed25519::Keypair::try_from_bytes(
                &mut state.libp2p_keypair_bytes.clone(),
            )
            .unwrap();
            state.opaque_keypair = bootstrap_node_state.opaque_keypair.clone();
            state.opaque_node.keypair = bootstrap_node_state.opaque_keypair.clone();
            state.username_to_opaque_pkey.insert(
                state.username.clone(),
                bootstrap_node_state.opaque_keypair.clone().public_key,
            );
        } else {
            for i in 0..5 {
                let libp2p_keypair = libp2p::identity::ed25519::Keypair::generate();
                let new_peer_id = PeerId::from_public_key(
                    &(libp2p::identity::PublicKey::from(libp2p_keypair.public())),
                );
                let opaque_keypair = Keypair::new();

                let serialized_keypairs = serde_json::to_string(&BootstrapNodeState {
                    libp2p_keypair_bytes: libp2p_keypair.to_bytes(),
                    peer_id: new_peer_id,
                    opaque_keypair: opaque_keypair.clone(),
                })?;
                let file_path = format!("tmp/bootstrap_{i}.envelope");
                let mut file = fs::File::create(file_path)?;
                file.write_all(serialized_keypairs.as_bytes())?;

                if i == 0 {
                    state.username = format!("bootstrap{i}");
                    state.peer_id = new_peer_id.clone();
                    state.libp2p_keypair_bytes = libp2p_keypair.to_bytes();
                    *bootstrap_keypair = libp2p_keypair;
                    state.opaque_keypair = opaque_keypair.clone();
                    state.opaque_node.keypair = opaque_keypair.clone();
                    state
                        .username_to_opaque_pkey
                        .insert(state.username.clone(), opaque_keypair.public_key);
                }
            }
        }

        println!("[BOOTSTRAP] Node is running at peer ID {}", state.peer_id);

        Ok(())
    }
}
