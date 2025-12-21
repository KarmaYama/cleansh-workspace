// cleansh/tests/stats_tests.rs
//! Verifies the statistical analysis logic used by the TUI dashboard.

use anyhow::Result;
use cleansh_core::config::RedactionConfig;
use cleansh_core::{engine::SanitizationEngine, RegexEngine};

#[test]
fn test_engine_analysis_mode() -> Result<()> {
    let config = RedactionConfig::load_default_rules()?;
    let engine = RegexEngine::new(config)?;

    let input = "Email: test@example.com, IP: 1.1.1.1";
    let summary = engine.analyze_for_stats(input, "test")?;

    // Check that summary contains counts without modifying input
    let email_stats = summary.iter().find(|s| s.rule_name == "email").unwrap();
    assert_eq!(email_stats.occurrences, 1);
    
    let ip_stats = summary.iter().find(|s| s.rule_name == "ipv4_address").unwrap();
    assert_eq!(ip_stats.occurrences, 1);

    Ok(())
}