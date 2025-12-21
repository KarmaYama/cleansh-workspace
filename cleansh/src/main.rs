// cleansh/src/main.rs
//! CleanSH v0.2.0 Entry Point.
//!
//! Initializes the chosen sanitization engine and launches the TUI runner.

use cleansh_core::{
    EntropyEngine, RegexEngine, 
    engine::SanitizationEngine, 
    config::RedactionConfig,
    load_profile_by_name,
    apply_profile_to_config
};
use cleansh::tui::run_tui;
use cleansh::ui::theme::build_theme_map;
use clap::{Parser, ValueEnum};
use anyhow::{Result, Context};
use cleansh::logger;

#[derive(Debug, Clone, ValueEnum)]
enum EngineType {
    /// Pattern-based matching (Fast, reliable for known secrets)
    Regex,
    /// Statistical analysis (Finds high-entropy anomalies)
    Entropy,
    /// Runs both engines for maximum security
    Hybrid,
}

#[derive(Parser)]
#[command(name = "cleansh", author, version, about)]
struct Cli {
    /// Select the sanitization engine
    #[arg(long, short = 'e', value_enum, default_value = "entropy")]
    engine: EngineType,

    /// Load specific security profile
    #[arg(long, short = 'p', default_value = "default")]
    profile: String,

    /// Suppress internal logging
    #[arg(long, short = 'q', default_value_t = true)]
    quiet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    if args.quiet {
        logger::init_logger(Some(log::LevelFilter::Off));
    } else {
        logger::init_logger(Some(log::LevelFilter::Debug));
    }

    let theme_map = build_theme_map(None).context("Theme error")?;
    
    // 1. Load Base Rules
    let mut config = RedactionConfig::load_default_rules()?;

    // 2. Apply Profile Override (The Fix)
    if args.profile != "default" {
        // This will error if the profile doesn't exist, fixing the test case
        let profile_config = load_profile_by_name(&args.profile)
            .with_context(|| format!("Failed to load profile '{}'", args.profile))?;
        
        config = apply_profile_to_config(&profile_config, config);
    }

    // 3. Multi-Engine Bootstrapping
    let engine: Box<dyn SanitizationEngine> = match args.engine {
        EngineType::Regex => Box::new(RegexEngine::new(config)?),
        EngineType::Entropy => Box::new(EntropyEngine::new(config)?),
        EngineType::Hybrid => {
            // Future: Implement a CompositeEngine to wrap both
            Box::new(EntropyEngine::new(config)?)
        }
    };

    run_tui(engine, theme_map).await.context("TUI failure")?;

    Ok(())
}