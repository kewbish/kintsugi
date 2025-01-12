use crate::kintsugi_lib::acss::ACSSNodeShare;
use crate::kintsugi_lib::keypair::Keypair;
use crate::kintsugi_lib::local_envelope::LocalEnvelope;
use crate::kintsugi_lib::opaque::EncryptedEnvelope;
use crate::{node_state, tauri_interactions};
#[allow(unused_imports)]
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::Path;
use tauri::State;

pub fn read_envelopes_local(state: &mut node_state::NodeState) -> Result<(), String> {
    let file_path = format!("tmp/{}_envelopes.list", state.username);
    if Path::new(&file_path).exists() {
        let contents = std::fs::read_to_string(file_path);
        if let Err(e) = contents {
            return Err(e.to_string());
        }
        let envelopes_list: Result<HashMap<String, EncryptedEnvelope>, _> =
            serde_json::from_str(&contents.unwrap());
        if let Err(e) = envelopes_list {
            return Err(e.to_string());
        }
        state.opaque_node.envelopes = envelopes_list.unwrap();
    }
    Ok(())
}

pub fn read_recovery_shares_local(state: &mut node_state::NodeState) -> Result<(), String> {
    let file_path = format!("tmp/{}_peers.list", state.username);
    if Path::new(&file_path).exists() {
        let contents = std::fs::read_to_string(file_path);
        if let Err(e) = contents {
            return Err(e.to_string());
        }
        let peers_list: Result<HashMap<String, (ACSSNodeShare, i32)>, _> =
            serde_json::from_str(&contents.unwrap());
        if let Err(e) = peers_list {
            return Err(e.to_string());
        }
        state.peer_recoveries = peers_list.unwrap();
    }
    Ok(())
}

pub fn update_recovery_shares_local(
    state: &mut node_state::NodeState,
) -> Result<(), Box<dyn Error>> {
    let serialized_peers = serde_json::to_string(&state.peer_recoveries.clone())?;
    let file_path = format!("tmp/{}_peers.list", state.username);
    let mut file = fs::File::create(file_path)?;
    file.write_all(serialized_peers.as_bytes())?;

    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct EncryptedTauriNotepad {
    pub(crate) encrypted_contents: Vec<u8>,
    pub(crate) nonce: [u8; 12],
}

#[tauri::command]
pub fn read_notepad(state: State<tauri_interactions::TauriState>) -> Result<String, String> {
    let node_state = state.0.lock().unwrap();
    let file_path = format!("tmp/{}_notepad.txt", node_state.username);
    if !Path::new(&file_path).exists() {
        return Ok("".to_string());
    }
    let contents = std::fs::read_to_string(file_path);
    if let Err(e) = contents {
        return Err(e.to_string());
    }
    let encrypted_notepad: Result<EncryptedTauriNotepad, _> =
        serde_json::from_str(&contents.unwrap());
    if let Err(e) = encrypted_notepad {
        return Err(e.to_string());
    }
    let encrypted_notepad = encrypted_notepad.unwrap();
    let mut hasher = Sha3_256::new();
    hasher.update(node_state.opaque_keypair.private_key);
    let key = hasher.finalize();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = Nonce::from_slice(&encrypted_notepad.nonce);

    let plaintext_bytes = cipher.decrypt(nonce, encrypted_notepad.encrypted_contents.as_ref());
    if let Err(e) = plaintext_bytes {
        return Err("Decryption failed: ".to_string() + &e.to_string());
    }
    let plaintext_bytes = plaintext_bytes.unwrap();
    let notepad = std::str::from_utf8(&plaintext_bytes);
    if let Err(e) = notepad {
        return Err(e.to_string());
    }
    Ok(notepad.unwrap().to_string())
}

#[tauri::command]
pub fn save_notepad(
    state: State<tauri_interactions::TauriState>,
    notepad: String,
) -> Result<(), String> {
    let node_state = state.0.lock().unwrap();
    let mut hasher = Sha3_256::new();
    hasher.update(node_state.opaque_keypair.private_key);
    let key = hasher.finalize();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, notepad.as_bytes());
    if let Err(e) = ciphertext {
        return Err("Encryption of notepad failed: ".to_string() + &e.to_string());
    }
    let ciphertext = ciphertext.unwrap();
    let encrypted_notepad = EncryptedTauriNotepad {
        encrypted_contents: ciphertext,
        nonce: nonce_bytes,
    };
    let serialized_ciphertext = serde_json::to_string(&encrypted_notepad);
    if let Err(e) = serialized_ciphertext {
        return Err(e.to_string());
    }
    let file_path = format!("tmp/{}_notepad.txt", node_state.username);
    if let Err(e) = fs::create_dir_all("tmp") {
        return Err(e.to_string());
    }
    let file = fs::File::create(file_path);
    if let Err(e) = file {
        return Err(e.to_string());
    }
    let result = file
        .unwrap()
        .write_all(serialized_ciphertext.unwrap().as_bytes());
    if let Err(e) = result {
        return Err(e.to_string());
    }
    Ok(())
}

pub fn save_local_envelope(
    username: String,
    password: String,
    opaque_keypair: Keypair,
) -> Result<(), String> {
    let file_path = format!("tmp/{username}_login.envelope");
    if Path::new(&file_path).exists() {
        return Err("Encrypted envelope already exists".to_string());
    }
    if let Err(e) = fs::create_dir_all("tmp") {
        return Err(e.to_string());
    }
    let file = fs::File::create(file_path);
    if let Err(e) = file {
        return Err(e.to_string());
    }
    let envelope = LocalEnvelope {
        keypair: opaque_keypair.clone(),
        username,
    };
    let encrypted_envelope = envelope.clone().encrypt_w_password(password.clone());
    if let Err(e) = encrypted_envelope {
        return Err(e.to_string());
    }
    let serialized_envelope = serde_json::to_string(&encrypted_envelope.unwrap());
    if let Err(e) = serialized_envelope {
        return Err(e.to_string());
    }
    let result = file
        .unwrap()
        .write_all(serialized_envelope.unwrap().as_bytes());
    if let Err(e) = result {
        return Err(e.to_string());
    }
    Ok(())
}

#[tauri::command]
pub fn tauri_save_local_envelope(
    state: State<tauri_interactions::TauriState>,
    password: String,
) -> Result<(), String> {
    let node_state = state.0.lock().unwrap();
    save_local_envelope(
        node_state.username.clone(),
        password,
        node_state.opaque_keypair.clone(),
    )
}
