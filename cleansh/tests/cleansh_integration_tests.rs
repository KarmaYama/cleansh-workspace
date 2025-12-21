// cleansh/tests/cleansh_integration_tests.rs
//! Integration tests for the CleanSH v0.2.0 engines and orchestrator logic.

use anyhow::Result;
use chrono::Utc;
use tokio::sync::mpsc;

use cleansh_core::config::{RedactionConfig, RedactionRule};
use cleansh_core::{
    EntropyEngine,
    RegexEngine,
    SanitizationEngine, 
};
use cleansh::tui::app::{App, EngineType};

// FIXED: Removed all unused imports (HashMap, ThemeEntry, etc.)

#[allow(unused_imports)]
#[cfg(test)]
mod test_setup {
    use std::sync::Once;
    static INIT: Once = Once::new();

    pub fn setup_logger() {
        INIT.call_once(|| {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
                .is_test(true)
                .try_init()
                .ok();
        });
    }
}

#[tokio::test]
async fn test_entropy_remediation_channel_integration() -> Result<()> {
    test_setup::setup_logger();
    
    let mut config = RedactionConfig::load_default_rules()?;
    config.engines.entropy.threshold = Some(0.1);
    let mut engine = EntropyEngine::new(config)?;

    let (tx, mut rx) = mpsc::channel(10);
    engine.set_remediation_tx(tx);

    let input = "DEBUG: API_KEY=8x9#bF2!kL0Z@mN9_extra_padding";
    let _ = engine.sanitize(input, "test", "run", "", "user", "manual", "success", None)?;

    let match_result = rx.try_recv();
    assert!(match_result.is_ok(), "Engine failed to tee the secret to the remediation channel");
    
    let redaction = match_result.unwrap();
    assert!(redaction.original_string.contains("8x9#bF2!"));
    
    Ok(())
}

#[test]
fn test_tui_app_log_buffer_limit() {
    let mut app = App::new(5, EngineType::Regex); 
    
    for i in 0..10 {
        let msg = format!("line {}", i);
        app.push_log_pair(msg.clone(), msg);
    }
    
    assert_eq!(app.log_lines.len(), 5);
    assert_eq!(app.log_lines.back().unwrap(), "line 9");
    assert_eq!(app.log_lines.front().unwrap(), "line 5");
}

#[test]
fn test_run_cleansh_basic_regex_sanitization() -> Result<()> {
    test_setup::setup_logger();
    let input = "email: test@example.com. My SSN is 123-45-6789.";
    
    let config = RedactionConfig {
        rules: vec![
            RedactionRule {
                name: "email".to_string(),
                description: Some("An email address pattern.".to_string()),
                pattern: Some(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".to_string()),
                pattern_type: "regex".to_string(),
                replace_with: "[EMAIL]".to_string(),
                author: "test_author".to_string(),
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
                version: "1.0.0".to_string(),
                enabled: Some(true),
                ..Default::default()
            },
        ],
        engines: Default::default(),
    };

    let engine = RegexEngine::new(config)?;
    let (output, _) = engine.sanitize(input, "test", "run", "", "user", "manual", "success", None)?;

    assert!(output.contains("[EMAIL]"));
    Ok(())
}