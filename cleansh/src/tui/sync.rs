// cleansh/src/tui/sync.rs
//! Background synchronization for the Fingerprint Vault.
//! 
//! Handles the periodic sync of redaction fingerprints.
//! v0.2.0: Now defaults to Local Vault for zero-config persistence.

use tokio::time::{self, Duration};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::tui::app::App;
use anyhow::Result;
use cleansh_core::remediation::vault::{FingerprintVault, local::LocalVault};

/// Statistics sent from the background sync task to the UI.
#[derive(Debug, Clone)]
pub struct SyncStats {
    pub active: bool,
    pub total_hashes: usize,
    pub last_sync_ms: u128,
    pub provider: String,
}

/// Orchestrates the background synchronization loop.
pub async fn start_sync_task(
    app: Arc<Mutex<App>>,
    interval_secs: u64,
) -> Result<()> {
    // Initialize Local Vault (Infrastructure Layer)
    let vault = match LocalVault::new() {
        Ok(v) => v,
        Err(e) => {
            log::error!("Failed to initialize local vault: {}", e);
            return Ok(()); // Fail gracefully, just no persistence
        }
    };

    let mut interval = time::interval(Duration::from_secs(interval_secs));

    tokio::spawn(async move {
        loop {
            interval.tick().await;

            let start = std::time::Instant::now();
            
            // --- SYNC LOGIC ---
            // 1. Fetch persistent fingerprints from disk
            let fingerprints = vault.fetch_all().await.unwrap_or_default();
            let count = fingerprints.len();
            
            // 2. TODO: Inject these fingerprints into the Engine's Hash Cache
            // (This requires a channel to the Engine, for now we just update UI stats)
            
            let duration = start.elapsed().as_millis();
            // --- SYNC LOGIC END ---

            // Update App State atomically
            let mut app_lock = app.lock().await;
            app_lock.sync_stats = SyncStats {
                active: true,
                total_hashes: count,
                last_sync_ms: duration,
                provider: "Local Vault".to_string(),
            };
        }
    });

    Ok(())
}