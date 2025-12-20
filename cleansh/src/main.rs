//! Cleansh CLI Application
//! 
//! This is the main entry point for the cleansh CLI, responsible for parsing 
//! arguments, initializing engines, and orchestrating the redaction pipeline.
//!
//! License: MIT OR Apache-2.0

use cleansh_core::{
    engine::SanitizationEngine,
    RegexEngine,
    EntropyEngine,
    config::{merge_rules, RedactionConfig},
    RedactionSummaryItem,
};
use anyhow::{Context, Result};
use clap::Parser;
use std::io::{self, Read, Write, IsTerminal, BufReader, BufRead};
use std::fs;
use std::env;
use std::path::PathBuf;
use log::{info, debug, LevelFilter};
use dotenvy;
use std::collections::HashMap;

use cleansh::commands;
use cleansh::logger;
use cleansh::ui;
use cleansh::utils::app_state::AppState;
use cleansh::utils::platform;
use cleansh::cli::{Cli, Commands, EngineChoice, SanitizeCommand, ScanCommand, ProfilesCommand};
use cleansh_core::profiles;

/// Creates a fully configured and compiled sanitization engine based on CLI arguments.
/// 
/// This function merges default rules, profile settings, and manual CLI overrides 
/// (like entropy thresholds or window sizes) into a final engine instance.
fn create_sanitization_engine(
    config_path: Option<&PathBuf>,
    profile_name: Option<&String>,
    engine_choice: &EngineChoice,
    enable_rules: &[String],
    disable_rules: &[String],
    cli_entropy_threshold: Option<f64>,
    cli_entropy_window: Option<usize>,
) -> Result<Box<dyn SanitizationEngine>> {
    // 1. Start with baseline default rules
    let mut config = RedactionConfig::load_default_rules()
        .context("Failed to load default redaction rules")?;

    // 2. Layer on Profile or custom Config file
    if let Some(name) = profile_name {
        let profile = profiles::load_profile_by_name(name)
            .context("Failed to load specified profile")?;

        profile.validate(&config)?;
        config = profiles::apply_profile_to_config(&profile, config);
    } else if let Some(path) = config_path {
        let user_config = RedactionConfig::load_from_file(path)
            .context("Failed to load user-defined configuration file")?;
        config = merge_rules(config, Some(user_config));
    }

    // 3. Apply Heuristic Tuning Overrides from CLI flags
    // These take the highest precedence.
    if let Some(t) = cli_entropy_threshold {
        debug!("Applying CLI override: entropy threshold = {}", t);
        config.engines.entropy.threshold = Some(t);
    }
    if let Some(w) = cli_entropy_window {
        debug!("Applying CLI override: entropy window size = {}", w);
        config.engines.entropy.window_size = Some(w);
    }

    // 4. Apply explicit rule enabling/disabling
    config.set_active_rules(enable_rules, disable_rules);

    // 5. Instantiate the requested engine
    match engine_choice {
        EngineChoice::Regex => {
            let engine = Box::new(RegexEngine::new(config)
                .context("Failed to initialize RegexEngine")?);
            Ok(engine)
        },
        EngineChoice::Entropy => {
            let engine = Box::new(EntropyEngine::new(config)
                .context("Failed to initialize EntropyEngine")?);
            Ok(engine)
        }
    }
}

/// Reads input content from a file or stdin, handling both terminal and non-terminal cases.
fn read_input(input_file: &Option<PathBuf>, theme_map: &ui::theme::ThemeMap) -> Result<String> {
    if let Some(path) = input_file.as_ref() {
        commands::cleansh::info_msg(format!("Reading input from file: {}", path.display()), theme_map);
        fs::read_to_string(path)
            .with_context(|| format!("Failed to read input from {}", path.display()))
    } else if io::stdin().is_terminal() {
        commands::cleansh::info_msg(
            &format!("Reading input from stdin. Press {} then Enter to finish input.", platform::eof_key_combo()),
            theme_map,
        );
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)
            .context("Failed to read from stdin")?;
        Ok(buffer)
    } else {
        commands::cleansh::info_msg("Reading input from stdin...", theme_map);
        let mut buffer = String::new();
        io::stdin().read_to_string(&mut buffer)
            .context("Failed to read from stdin")?;
        Ok(buffer)
    }
}

/// Reads input line-by-line from stdin for real-time stream processing.
fn run_line_buffered_mode(engine: Box<dyn SanitizationEngine>, opts: &SanitizeCommand, theme_map: &ui::theme::ThemeMap, quiet: bool) -> Result<()> {
    let stdin = io::stdin().lock();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    let mut summary_items: HashMap<String, RedactionSummaryItem> = HashMap::new();

    let mut writer: Box<dyn Write> = if let Some(path) = opts.output.as_ref() {
        Box::new(fs::File::create(path)
            .with_context(|| format!("Failed to create output file: {}", path.display()))?)
    } else {
        Box::new(io::stdout().lock())
    };

    let flush_per_line = opts.output.is_none();
    
    commands::cleansh::info_msg("Using line-buffered mode...", theme_map);

    while reader.read_line(&mut line)? > 0 {
        let (sanitized_line, line_summary) = engine.sanitize(&line, "", "", "", "", "", "", None)
            .context("Sanitization failed in line-buffered mode")?;
        
        let mut sanitized_line = sanitized_line;

        if !sanitized_line.ends_with('\n') {
            sanitized_line.push('\n');
        }

        writer.write_all(sanitized_line.as_bytes())
            .context("Failed to write sanitized line")?;

        if flush_per_line {
            writer.flush().context("Failed to flush stdout")?;
        }

        for item in line_summary {
            summary_items
                .entry(item.rule_name.clone())
                .and_modify(|existing_item| {
                    existing_item.occurrences += item.occurrences;
                })
                .or_insert(item);
        }

        line.clear();
    }
    
    if !quiet && !opts.no_summary {
        let summary_vec: Vec<RedactionSummaryItem> = summary_items.into_values().collect();
        let stderr_supports_color = io::stderr().is_terminal();
        ui::redaction_summary::print_summary(&summary_vec, &mut io::stderr(), theme_map, stderr_supports_color)?;
    }

    Ok(())
}

/// Entrypoint for the `sanitize` subcommand.
fn handle_sanitize_command(opts: &SanitizeCommand, cli: &Cli, theme_map: &ui::theme::ThemeMap) -> Result<()> {
    if opts.line_buffered && (opts.diff || opts.clipboard || opts.input_file.is_some()) {
        commands::cleansh::error_msg(
            "Error: --line-buffered is incompatible with --diff, --clipboard, and --input-file.",
            &theme_map,
        );
        std::process::exit(1);
    }
    
    let engine = create_sanitization_engine(
        opts.config.as_ref(),
        opts.profile.as_ref(),
        &opts.engine,
        &opts.enable,
        &opts.disable,
        opts.entropy_threshold, // Pass CLI threshold override
        opts.entropy_window,    // Pass CLI window override
    )?;

    if opts.line_buffered {
        run_line_buffered_mode(engine, &opts, theme_map, cli.quiet)
    } else {
        let input_content = read_input(&opts.input_file, theme_map)?;

        let cleansh_options = commands::cleansh::CleanshOptions {
            input: input_content,
            clipboard: opts.clipboard,
            diff: opts.diff,
            output_path: opts.output.clone(),
            no_redaction_summary: opts.no_summary,
            quiet: cli.quiet,
        };
        commands::cleansh::run_cleansh_opts(&*engine, cleansh_options, theme_map)
    }
}

/// Entrypoint for the `scan` subcommand.
fn handle_scan_command(opts: &ScanCommand, theme_map: &ui::theme::ThemeMap) -> Result<()> {
    // Note: Scan currently defaults to Regex, but could support Entropy in the future 
    // by adding threshold/window flags to ScanCommand in cli.rs.
    let engine = create_sanitization_engine(
        opts.config.as_ref(),
        opts.profile.as_ref(),
        &EngineChoice::Regex,
        &opts.enable,
        &opts.disable,
        None, // No specific CLI entropy overrides for scan yet
        None,
    )?;

    commands::stats::run_stats_command(&opts, theme_map, &*engine)
}

/// Entrypoint for profile management commands.
fn handle_profiles_command(opts: &ProfilesCommand, _cli: &Cli, theme_map: &ui::theme::ThemeMap) -> Result<()> {
    match opts {
        ProfilesCommand::Sign { path, key_file } => {
            let key_bytes = fs::read(key_file)
                .context("Failed to read key file for signing.")?;
            profiles::sign_profile(path, &key_bytes)?;
            commands::cleansh::info_msg(format!("Profile '{}' signed successfully.", path.display()), theme_map);
            Ok(())
        },
        ProfilesCommand::Verify { path: _, pub_key_file: _ } => {
            commands::cleansh::warn_msg("RSA verification is not yet implemented.", theme_map);
            Ok(())
        },
        ProfilesCommand::List => {
            let available_profiles = profiles::list_available_profiles();
            commands::cleansh::info_msg("Available Profiles:", theme_map);
            for profile in available_profiles {
                println!("- {}: {} ({})", profile.profile_name, profile.version, profile.display_name.unwrap_or_default());
            }
            Ok(())
        },
    }
}

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    
    let cli = Cli::parse();
    
    // Resolve app state path with potential test overrides
    let app_state_path: PathBuf = env::var("CLEANSH_STATE_FILE_OVERRIDE_FOR_TESTS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if let Some(dir) = dirs::data_dir() {
                dir.join("cleansh").join("state.json")
            } else {
                env::current_dir().expect("Failed to get current dir").join("cleansh_state.json")
            }
        });
    
    let theme_map = ui::theme::build_theme_map(cli.theme.as_ref())?;
    
    // Determine log level based on quiet/debug flags
    let effective_log_level = if cli.quiet {
        Some(LevelFilter::Off)
    } else if cli.debug && !cli.disable_debug {
        Some(LevelFilter::Debug)
    } else if cli.disable_debug {
        Some(LevelFilter::Info)
    } else {
        None
    };

    logger::init_logger(effective_log_level);
    info!("cleansh started. Version: {}", env!("CARGO_PKG_VERSION"));
    
    let result = match cli.command {
        Commands::Uninstall { yes } => {
            commands::uninstall::elevate_and_run_uninstall(yes, &theme_map)
        },
        ref opts @ _ => {
            let mut app_state = AppState::load(&app_state_path)?;
            app_state.donation_prompts_disabled = cli.disable_donation_prompts || cli.quiet;

            let command_result = match opts {
                Commands::Sanitize(sanitize_opts) => handle_sanitize_command(sanitize_opts, &cli, &theme_map),
                Commands::Scan(scan_opts) => handle_scan_command(scan_opts, &theme_map),
                Commands::Profiles(profile_opts) => handle_profiles_command(profile_opts, &cli, &theme_map),
                Commands::Uninstall { .. } => unreachable!(),
            };

            // Post-command community engagement
            if !app_state.donation_prompts_disabled {
                if let Err(e) = app_state.check_and_prompt_donation(&theme_map) {
                    debug!("Donation prompt error (non-fatal): {}", e);
                }
            }

            // Persistence
            if let Err(e) = app_state.save(&app_state_path) {
                commands::cleansh::warn_msg(format!("Failed to save app state: {}", e), &theme_map);
            }

            command_result
        }
    };
    
    result
}