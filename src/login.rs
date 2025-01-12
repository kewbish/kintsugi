use crate::{kintsugi_lib::local_envelope::LocalEncryptedEnvelope, tauri_interactions::TauriState};
use std::path::Path;
use tauri::State;

#[tauri::command]
pub fn local_login(
    state: State<TauriState>,
    username: String,
    password: String,
) -> Result<bool, String> {
    let mut node_state = state.0.lock().unwrap();
    let file_path = format!("tmp/{username}_login.envelope");
    if !Path::new(&file_path).exists() {
        return Err("Encrypted envelope does not exist".to_string());
    }
    let contents = std::fs::read_to_string(file_path);
    if let Err(e) = contents {
        return Err(e.to_string());
    }
    let encrypted_envelope: Result<LocalEncryptedEnvelope, _> =
        serde_json::from_str(&contents.unwrap());
    if let Err(e) = encrypted_envelope {
        return Err(e.to_string());
    }
    let envelope = encrypted_envelope.unwrap().decrypt_w_password(password);
    if let Err(e) = envelope {
        return Err(e.to_string());
    }
    let envelope = envelope.unwrap();
    if envelope.username != username {
        return Ok(false);
    }
    node_state.username = username;
    Ok(true)
}
