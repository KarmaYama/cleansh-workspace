// cleansh/src/tui/mod.rs
pub mod app;
pub mod ui;
pub mod sync;

use std::io;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use anyhow::{Result, Context};
use crate::tui::app::{App, EngineType};
use crate::tui::sync::start_sync_task;
use cleansh_core::{EntropyEngine, RegexEngine, engine::SanitizationEngine, config::RedactionConfig};
use cleansh_core::redaction_match::RedactionMatch;
use std::time::{Duration, Instant};
use futures::stream::StreamExt;

pub async fn run_tui(mut engine: Box<dyn SanitizationEngine>, theme_map: crate::ui::theme::ThemeMap) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create the main data channel
    let (tx_line, mut rx_line) = mpsc::channel::<String>(1000);
    let (tx_match, mut rx_match) = mpsc::channel::<RedactionMatch>(100);

    engine.set_remediation_tx(tx_match.clone());

    // Clone sender for the background thread
    let tx_stdin = tx_line.clone();

    // NEW: Unbuffered Byte-Level Stdin Reader
    // This bypasses the standard library's internal buffering to ensure zero-latency streaming.
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let stdin = std::io::stdin();
        let mut handle = stdin.lock();
        let mut buffer = [0u8; 1]; // Read 1 byte at a time for instant reaction
        let mut line_acc = Vec::with_capacity(1024);

        loop {
            match handle.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let byte = buffer[0];
                    if byte == b'\n' {
                        // Flush accumulated line immediately upon hitting newline
                        if let Ok(s) = String::from_utf8(line_acc.clone()) {
                            // Trim Windows CR (\r) if present
                            let clean_s = s.trim_end_matches('\r').to_string();
                            if tx_stdin.blocking_send(clean_s).is_err() { break; }
                        }
                        line_acc.clear();
                    } else {
                        line_acc.push(byte);
                    }
                }
                Err(_) => break,
            }
        }
        
        // Flush any remaining data (if the stream ends without a newline)
        if !line_acc.is_empty() {
            if let Ok(s) = String::from_utf8(line_acc) {
                let clean_s = s.trim_end_matches('\r').to_string();
                let _ = tx_stdin.blocking_send(clean_s);
            }
        }
    });

    let app = Arc::new(Mutex::new(App::new(1000, EngineType::Entropy)));
    start_sync_task(Arc::clone(&app), 60).await?;

    let mut event_stream = event::EventStream::new();
    let mut last_input = Instant::now();
    let debounce = Duration::from_millis(200);

    loop {
        {
            let app_lock = app.lock().await;
            if app_lock.should_quit { break; }
            terminal.draw(|f| ui::draw(f, &app_lock, &theme_map))?;
        }

        tokio::select! {
            Some(Ok(evt)) = event_stream.next() => {
                if let Event::Key(key) = evt {
                    let now = Instant::now();
                    if now.duration_since(last_input) < debounce { continue; }
                    last_input = now;

                    let mut app_write = app.lock().await;
                    
                    // --- GLOBAL KEYS (Work anytime unless menu is open) ---
                    if !app_write.show_engine_menu {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => app_write.should_quit = true,
                            KeyCode::Char('h') => app_write.toggle_heatmap(),
                            KeyCode::Char('d') => app_write.toggle_diff(),
                            KeyCode::Char('e') => app_write.toggle_engine_menu(),
                            
                            // Remediation Actions
                            KeyCode::Char('a') => { app_write.approve_current(); },
                            KeyCode::Char('i') => { app_write.ignore_current(); },
                            
                            KeyCode::Down => app_write.next_match(),
                            KeyCode::Up => app_write.previous_match(),
                            _ => {}
                        }
                    } else {
                        // --- MENU KEYS (Only work when menu is open) ---
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('e') => app_write.toggle_engine_menu(),
                            KeyCode::Enter => {
                                let selected = app_write.engine_list_state.selected().unwrap_or(1);
                                let new_type = match selected {
                                    0 => EngineType::Regex,
                                    1 => EngineType::Entropy,
                                    _ => EngineType::Hybrid,
                                };
                                
                                // 1. Swap Engine
                                let config = RedactionConfig::load_default_rules().unwrap();
                                engine = match new_type {
                                    EngineType::Regex => Box::new(RegexEngine::new(config).unwrap()),
                                    _ => Box::new(EntropyEngine::new(config).unwrap()),
                                };
                                engine.set_remediation_tx(tx_match.clone());
                                
                                // 2. RETROACTIVE SCANNING
                                let history: Vec<String> = app_write.raw_input_buffer.drain(..).collect();
                                app_write.log_lines.clear();
                                app_write.matches.clear();
                                app_write.heat_map.clear();
                                app_write.current_engine = new_type;
                                app_write.show_engine_menu = false;

                                // Clone the *original* tx_line which is still valid here
                                let tx_replay = tx_line.clone();
                                tokio::spawn(async move {
                                    for line in history {
                                        let _ = tx_replay.send(line).await;
                                    }
                                });
                            },
                            KeyCode::Down => app_write.next_engine(),
                            KeyCode::Up => {
                                let i = match app_write.engine_list_state.selected() {
                                    Some(i) => if i == 0 { 2 } else { i - 1 },
                                    None => 0,
                                };
                                app_write.engine_list_state.select(Some(i));
                            },
                            _ => {}
                        }
                    }
                }
            }

            // Engine Processing Loop
            Some(m) = rx_match.recv() => {
                let mut app_write = app.lock().await;
                app_write.add_match(m);
            }
            Some(raw_line) = rx_line.recv() => {
                let (sanitized, _) = engine.sanitize(&raw_line, "tui", "v02", "", "user", "auto", "proc", None)
                    .context("Engine failure")?;
                let mut app_write = app.lock().await;
                app_write.heat_map = engine.get_heat_scores(&raw_line);
                app_write.push_log_pair(raw_line, sanitized);
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}