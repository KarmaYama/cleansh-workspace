// cleansh/src/tui/app.rs
//! Application state for the CleanSH TUI.
//!
//! Manages buffers, security matches, and the dynamic engine switcher state.

use cleansh_core::redaction_match::RedactionMatch;
use crate::tui::sync::SyncStats;
use ratatui::widgets::ListState;
use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq)]
pub enum RemediationStatus {
    Pending,
    Approved,
    Revoked,
    Ignored,
}

/// Available engine choices for the dynamic switcher.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EngineType {
    Regex = 0,
    Entropy = 1,
    Hybrid = 2,
}

pub struct App {
    pub raw_input_buffer: VecDeque<String>,
    pub log_lines: VecDeque<String>,
    pub matches: Vec<(RedactionMatch, RemediationStatus)>, 
    pub match_list_state: ListState,
    pub should_quit: bool,
    pub heat_map: Vec<f64>,
    pub show_heatmap: bool,
    pub show_diff: bool,
    pub show_remediation: bool,
    pub sync_stats: SyncStats,
    pub max_history: usize,
    
    // Engine Switcher State
    pub current_engine: EngineType,
    pub show_engine_menu: bool,
    pub engine_list_state: ListState,
}

impl App {
    pub fn new(max_history: usize, initial_engine: EngineType) -> Self {
        let mut engine_state = ListState::default();
        engine_state.select(Some(initial_engine as usize));

        Self {
            raw_input_buffer: VecDeque::with_capacity(max_history),
            log_lines: VecDeque::with_capacity(max_history),
            matches: Vec::new(),
            match_list_state: ListState::default(),
            should_quit: false,
            heat_map: Vec::new(),
            show_heatmap: false,
            show_diff: false,
            show_remediation: false,
            sync_stats: SyncStats {
                active: false,
                total_hashes: 0,
                last_sync_ms: 0,
                provider: "Initializing...".to_string(),
            },
            max_history,
            current_engine: initial_engine,
            show_engine_menu: false,
            engine_list_state: engine_state,
        }
    }

    pub fn on_tick(&mut self) {}

    pub fn toggle_engine_menu(&mut self) {
        self.show_engine_menu = !self.show_engine_menu;
    }

    pub fn next_engine(&mut self) {
        let i = match self.engine_list_state.selected() {
            Some(i) => if i >= 2 { 0 } else { i + 1 },
            None => 0,
        };
        self.engine_list_state.select(Some(i));
    }

    pub fn push_log_pair(&mut self, raw: String, sanitized: String) {
        if self.log_lines.len() >= self.max_history {
            self.log_lines.pop_front();
            self.raw_input_buffer.pop_front();
        }
        self.raw_input_buffer.push_back(raw);
        self.log_lines.push_back(sanitized);
    }

    pub fn add_match(&mut self, m: RedactionMatch) {
        if !self.matches.iter().any(|(existing, _)| existing.original_string == m.original_string) {
            self.matches.push((m, RemediationStatus::Pending));
            if self.match_list_state.selected().is_none() {
                self.match_list_state.select(Some(0));
            }
        }
    }

    pub fn approve_current(&mut self) -> Option<RedactionMatch> {
        if let Some(index) = self.match_list_state.selected() {
            if let Some((m, status)) = self.matches.get_mut(index) {
                if *status == RemediationStatus::Pending {
                    *status = RemediationStatus::Approved;
                    return Some(m.clone());
                }
            }
        }
        None
    }

    pub fn ignore_current(&mut self) {
        if let Some(index) = self.match_list_state.selected() {
            if let Some((_, status)) = self.matches.get_mut(index) {
                *status = RemediationStatus::Ignored;
            }
        }
    }

    pub fn toggle_heatmap(&mut self) {
        self.show_heatmap = !self.show_heatmap;
        if self.show_heatmap { self.show_diff = false; }
    }

    pub fn toggle_diff(&mut self) {
        self.show_diff = !self.show_diff;
        if self.show_diff { self.show_heatmap = false; }
    }

    pub fn next_match(&mut self) {
        if self.matches.is_empty() { return; }
        let i = match self.match_list_state.selected() {
            Some(i) => if i >= self.matches.len() - 1 { 0 } else { i + 1 },
            None => 0,
        };
        self.match_list_state.select(Some(i));
    }

    pub fn previous_match(&mut self) {
        if self.matches.is_empty() { return; }
        let i = match self.match_list_state.selected() {
            Some(i) => if i == 0 { self.matches.len() - 1 } else { i - 1 },
            None => 0,
        };
        self.match_list_state.select(Some(i));
    }
}