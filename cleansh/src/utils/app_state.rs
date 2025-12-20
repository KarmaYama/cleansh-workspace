// cleansh/src/utils/app_state.rs
/// Application state management for the `cleansh` CLI tool.
///
/// This module handles the loading, saving, and encryption of the application's
/// state, including usage statistics.
// cleansh/src/utils/app_state.rs

use anyhow::{Result, Context};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use chrono::{Utc, TimeZone};
use log::{warn, debug};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use base64::{engine::general_purpose, Engine as _};

use crate::ui::theme::ThemeMap;
use crate::commands::cleansh::info_msg;

/// AES-GCM
use rand::RngCore;
use rand::rngs::OsRng;
/// Keyring usage
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

// The Default trait for AppState must not be recursive.
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

    /// Load state, decrypting if needed. If file missing -> default state.
    pub fn load(path: &Path) -> Result<Self> {
        // If state file doesn't exist, return default
        if !path.exists() {
            debug!("App state file not found at {}. Using default.", path.display());
            return Ok(AppState::new());
        }

        // Acquire read lock on the file to avoid races
        let mut f = OpenOptions::new().read(true).open(path)
            .with_context(|| format!("Failed to open app state file: {}", path.display()))?;
        // try to lock shared (read)
        fs2::FileExt::lock_shared(&f)?;

        let mut raw = Vec::new();
        f.read_to_end(&mut raw)?;

        // Release shared lock (will drop)
        fs2::FileExt::unlock(&f)?;

        // Try to treat file as encrypted. If parse fails, fallback to plain JSON parse.
        if let Ok(state) = decrypt_state_blob(&raw, path) {
            Ok(state)
        } else {
            // Try parse as plain json
            match serde_json::from_slice::<AppState>(&raw) {
                Ok(s) => Ok(s),
                Err(e) => {
                    warn!("Failed to parse app state (both encrypted and plaintext): {}. Returning default state.", e);
                    Ok(AppState::new())
                }
            }
        }
    }

    /// Save state to disk with encryption. Uses atomic write and exclusive lock.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Serialize plaintext JSON
        let json = serde_json::to_vec_pretty(&self)?;

        // Encrypt using keyring (fallback)
        let encrypted_blob = encrypt_state_blob(&json, path)?;

        // Atomic write to temp + rename, with exclusive lock on temp file during write
        let tmp_path = path.with_extension(format!("{}{}", path.extension().map(|s| s.to_string_lossy()).unwrap_or_default(), STATE_FILE_TMP_SUFFIX));
        {
            let mut tmp = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp_path)
                .with_context(|| format!("Failed to create temp state file at {}", tmp_path.display()))?;
            // lock exclusive while writing
            fs2::FileExt::lock_exclusive(&tmp)?;
            tmp.write_all(&encrypted_blob)?;
            tmp.flush()?;
            fs2::FileExt::unlock(&tmp)?;
        }

        // Replace original file atomically
        fs::rename(&tmp_path, path)?;

        Ok(())
    }

    // donation prompt logic
    pub fn increment_usage(&mut self) {
        self.usage_count += 1;
        debug!("Main usage count incremented to {}", self.usage_count);
    }

    pub fn increment_stats_only_usage(&mut self) {
        self.stats_only_usage_count += 1;
        debug!("Stats-only usage count incremented to {}", self.stats_only_usage_count);
    }

    pub fn should_display_donation_prompt(&mut self) -> bool {
        if self.donation_prompts_disabled {
            return false;
        }

        const PROMPT_THRESHOLD: u64 = 5;
        const PROMPT_COOLDOWN_DAYS: i64 = 30;

        let now = Utc::now().timestamp() as u64;
        if self.usage_count >= PROMPT_THRESHOLD || self.stats_only_usage_count >= PROMPT_THRESHOLD {
            if let Some(last_prompt) = self.last_prompt_timestamp {
                let last_prompt_date = Utc.timestamp_opt(last_prompt as i64, 0).single();
                let now_date = Utc.timestamp_opt(now as i64, 0).single();

                if let (Some(last_p_date), Some(n_date)) = (last_prompt_date, now_date) {
                    if (n_date - last_p_date).num_days() < PROMPT_COOLDOWN_DAYS {
                        debug!("Donation prompt cooldown active. Last prompt: {} days ago.", (n_date - last_p_date).num_days());
                        return false;
                    }
                } else {
                    warn!("Failed to convert timestamps for donation prompt cooldown. Displaying prompt.");
                }
            }

            debug!("Donation prompt conditions met. Displaying prompt.");
            self.last_prompt_timestamp = Some(now);
            true
        } else {
            debug!("Donation prompt threshold not met. Main count: {}, Stats count: {}", self.usage_count, self.stats_only_usage_count);
            false
        }
    }

    pub fn check_and_prompt_donation(&mut self, theme_map: &ThemeMap) -> Result<()> {
        if self.should_display_donation_prompt() {
            info_msg(
                "Hello! If Cleansh has been useful to you, consider donating. We rely on community support to continue development. Please consider donating to help keep this project going: https://github.com/KarmaYama/cleansh-workspace",
                theme_map,
            );
        }
        Ok(())
    }
}

// ---------------------- encryption & key management helpers ----------------------

/// Try to fetch/generate a symmetric key (32 bytes) from keyring or fallback local key file.
/// Returns raw key bytes.
fn get_or_create_state_key(state_path: &Path) -> Result<Vec<u8>> {
    // try keyring first. We use .and_then to handle Entry::new returning a Result in keyring v3.
    match KeyringEntry::new(KEYRING_SERVICE, KEYRING_USERNAME).and_then(|entry| entry.get_password()) {
        Ok(s) => {
            let decoded = general_purpose::STANDARD.decode(s)
                .context("Failed to decode base64 key from keyring")?;
            if decoded.len() != 32 {
                warn!("Keyring returned key of unexpected length. Generating a new key and storing it.");
            } else {
                return Ok(decoded);
            }
        },
        Err(e) => {
            debug!("Keyring access failed: {}. Will attempt local key fallback.", e);
        }
    }

    // Fallback local key file next to state_path
    let key_file = if let Some(parent) = state_path.parent() {
        parent.join(LOCAL_KEY_FILENAME)
    } else {
        PathBuf::from(LOCAL_KEY_FILENAME)
    };

    if key_file.exists() {
        let s = fs::read_to_string(&key_file)?;
        let decoded = general_purpose::STANDARD.decode(s.trim())
            .context("Failed to decode base64 key from local key file")?;
        if decoded.len() == 32 {
            return Ok(decoded);
        } else {
            warn!("Local key file has invalid key length; regenerating.");
        }
    }

    // Generate new 32-byte key
    let mut key = [0u8; 32];
    // Instantiate OsRng to satisfy trait bounds in rand 0.9.x / generic usage
    let mut rng = OsRng;
    rng.fill_bytes(&mut key);

    // Try to store in keyring (best effort)
    let b64 = general_purpose::STANDARD.encode(&key);
    // KeyringEntry::new also returns Result here, so we map it out
    match KeyringEntry::new(KEYRING_SERVICE, KEYRING_USERNAME).and_then(|entry| entry.set_password(&b64)) {
        Ok(_) => {
            debug!("Stored state encryption key in OS keyring.");
        }
        Err(e) => {
            warn!("Failed to store key in keyring: {}. Falling back to local key file.", e);
            // write local file and restrict permissions when possible
            fs::write(&key_file, &b64)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&key_file)?.permissions();
                perms.set_mode(0o600);
                fs::set_permissions(&key_file, perms)?;
            }
        }
    }

    Ok(key.to_vec())
}

/// Encrypt the plaintext state and return the wrapped blob to write.
/// Format: b"v1.<base64(nonce)>.<base64(ciphertext)>"
fn encrypt_state_blob(plaintext: &[u8], state_path: &Path) -> Result<Vec<u8>> {
    let key = get_or_create_state_key(state_path)?;
    let cipher = Aes256Gcm::new_from_slice(&key).context("Failed to create AES-GCM cipher")?;

    let mut nonce_bytes = [0u8; AES_NONCE_LEN];
    // Instantiate OsRng explicitly
    let mut rng = OsRng;
    rng.fill_bytes(&mut nonce_bytes);
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

/// Attempt to decrypt stored blob; if format unrecognized, return Err.
fn decrypt_state_blob(blob: &[u8], state_path: &Path) -> Result<AppState> {
    let s = std::str::from_utf8(blob).context("State file is not valid UTF-8")?;
    // expected: v1.<base64(nonce)>.<base64(ciphertext)>
    if !s.starts_with("v1.") {
        return Err(anyhow::anyhow!("State file does not have expected version header"));
    }
    let parts: Vec<&str> = s.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(anyhow::anyhow!("Invalid encrypted state format"));
    }
    let nonce_b = general_purpose::STANDARD.decode(parts[1])
        .context("Failed to decode nonce")?;
    let ct_b = general_purpose::STANDARD.decode(parts[2])
        .context("Failed to decode ciphertext")?;

    let key = get_or_create_state_key(state_path)?;
    let cipher = Aes256Gcm::new_from_slice(&key).context("Failed to create AES-GCM cipher")?;
    let nonce = Nonce::from_slice(&nonce_b);

    let plaintext = cipher.decrypt(nonce, ct_b.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to decrypt state blob: {:?}", e))?;
    let state: AppState = serde_json::from_slice(&plaintext)
        .context("Failed to deserialize decrypted AppState JSON")?;
    Ok(state)
}