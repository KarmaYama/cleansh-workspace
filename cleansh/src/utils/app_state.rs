// cleansh/src/utils/app_state.rs
//! Application state management for the `cleansh` CLI tool.
//!
//! This module handles the loading, saving, and encryption of the application's
//! state, including usage statistics.

use anyhow::Result;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use base64::{engine::general_purpose, Engine as _};

use rand::RngCore;
use rand::rngs::OsRng;
use keyring::Entry as KeyringEntry;

const KEYRING_SERVICE: &str = "cleansh";
const KEYRING_USERNAME: &str = "state-encryption";
const LOCAL_KEY_FILENAME: &str = "state_key.b64";
const AES_NONCE_LEN: usize = 12;
const STATE_FILE_TMP_SUFFIX: &str = ".tmp";

#[derive(Debug, Serialize, Deserialize)]
pub struct AppState {
    pub usage_count: u64,
    pub stats_only_usage_count: u64,
    pub last_prompt_timestamp: Option<u64>,
    pub donation_prompts_disabled: bool,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            usage_count: 0,
            stats_only_usage_count: 0,
            last_prompt_timestamp: None,
            donation_prompts_disabled: false,
        }
    }
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(AppState::new());
        }

        let mut f = OpenOptions::new().read(true).open(path)?;
        fs2::FileExt::lock_shared(&f)?;

        let mut raw = Vec::new();
        f.read_to_end(&mut raw)?;
        fs2::FileExt::unlock(&f)?;

        if raw.is_empty() {
            return Ok(AppState::new());
        }

        if let Ok(state) = decrypt_state_blob(&raw, path) {
            Ok(state)
        } else {
            match serde_json::from_slice::<AppState>(&raw) {
                Ok(s) => Ok(s),
                Err(_) => Ok(AppState::new())
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_vec_pretty(&self)?;
        let encrypted_blob = encrypt_state_blob(&json, path)?;

        let tmp_path = path.with_extension(format!("{}{}", path.extension().map(|s| s.to_string_lossy()).unwrap_or_default(), STATE_FILE_TMP_SUFFIX));
        {
            let mut tmp = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp_path)?;
            fs2::FileExt::lock_exclusive(&tmp)?;
            tmp.write_all(&encrypted_blob)?;
            tmp.flush()?;
            fs2::FileExt::unlock(&tmp)?;
        }

        fs::rename(&tmp_path, path)?;
        Ok(())
    }
}

fn get_or_create_state_key(state_path: &Path) -> Result<Vec<u8>> {
    match KeyringEntry::new(KEYRING_SERVICE, KEYRING_USERNAME).and_then(|entry| entry.get_password()) {
        Ok(s) => {
            let decoded = general_purpose::STANDARD.decode(s)?;
            if decoded.len() == 32 { return Ok(decoded); }
        },
        _ => {}
    }

    let key_file = if let Some(parent) = state_path.parent() {
        parent.join(LOCAL_KEY_FILENAME)
    } else {
        PathBuf::from(LOCAL_KEY_FILENAME)
    };

    if key_file.exists() {
        let s = fs::read_to_string(&key_file)?;
        let decoded = general_purpose::STANDARD.decode(s.trim())?;
        if decoded.len() == 32 { return Ok(decoded); }
    }

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let b64 = general_purpose::STANDARD.encode(&key);
    let _ = KeyringEntry::new(KEYRING_SERVICE, KEYRING_USERNAME).and_then(|entry| entry.set_password(&b64));

    Ok(key.to_vec())
}

fn encrypt_state_blob(plaintext: &[u8], state_path: &Path) -> Result<Vec<u8>> {
    let key = get_or_create_state_key(state_path)?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;

    let mut nonce_bytes = [0u8; AES_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {:?}", e))?;

    let out_str = format!(
        "v1.{}.{}",
        general_purpose::STANDARD.encode(&nonce_bytes),
        general_purpose::STANDARD.encode(&ciphertext)
    );
    Ok(out_str.into_bytes())
}

fn decrypt_state_blob(blob: &[u8], state_path: &Path) -> Result<AppState> {
    let s = std::str::from_utf8(blob)?;
    if !s.starts_with("v1.") {
        return Err(anyhow::anyhow!("State file version header missing"));
    }
    let parts: Vec<&str> = s.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!("Invalid encrypted state format"));
    }
    let nonce_b = general_purpose::STANDARD.decode(parts[1])?;
    let ct_b = general_purpose::STANDARD.decode(parts[2])?;

    let key = get_or_create_state_key(state_path)?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Nonce::from_slice(&nonce_b);

    let plaintext = cipher.decrypt(nonce, ct_b.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to decrypt state blob: {:?}", e))?;
    
    let state: AppState = serde_json::from_slice(&plaintext)?;
    Ok(state)
}