// cleansh/src/tui/ui.rs
//! TUI Rendering Logic for CleanSH v0.2.0.
//!
//! Implements multi-panel layouts including Live Stream, Diff Analysis,
//! and the Shannon Entropy character-map with enhanced visual aesthetics.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect, Alignment},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, BorderType, List, ListItem, Paragraph, Wrap, Clear, Gauge, Padding},
    Frame,
};
use crate::tui::app::{App, RemediationStatus};
use crate::ui::diff_viewer::generate_diff_lines;

/// Main draw cycle.
pub fn draw(f: &mut Frame, app: &App, theme_map: &crate::ui::theme::ThemeMap) {
    let main_constraints = if app.show_diff || app.show_heatmap {
        vec![Constraint::Percentage(50), Constraint::Percentage(50)]
    } else {
        vec![Constraint::Percentage(100)]
    };

    let vertical_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(12),
        ])
        .split(f.area());

    // 1. Header
    // FIXED: Added [I] Ignore back to the visual header
    let header_text = Line::from(vec![
        Span::styled(" CleanSH v0.2.0 ", Style::default().fg(Color::Cyan).bold()),
        Span::raw("| "),
        Span::styled("[Q] Quit ", Style::default().fg(Color::Red)),
        Span::styled("[H] Heatmap ", Style::default().fg(Color::Yellow)),
        Span::styled("[D] Diff ", Style::default().fg(Color::Magenta)),
        Span::styled("[E] Engine ", Style::default().fg(Color::Blue)),
        Span::styled("[A] Approve ", Style::default().fg(Color::Green)),
        Span::styled("[I] Ignore ", Style::default().fg(Color::DarkGray)),
    ]);
    
    let header = Paragraph::new(header_text)
        .alignment(Alignment::Center)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray)));
    f.render_widget(header, vertical_chunks[0]);

    // 2. Main Content
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(main_constraints)
        .split(vertical_chunks[1]);

    let logs: Vec<ListItem> = app.log_lines.iter()
        .map(|l| ListItem::new(l.as_str()))
        .collect();
    
    let log_block = Block::default()
        .title(" 📡 Live Stream ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::White))
        .padding(Padding::new(1, 1, 0, 0)); 

    let log_list = List::new(logs).block(log_block);
    f.render_widget(log_list, content_chunks[0]);

    if app.show_diff {
        let orig = app.raw_input_buffer.iter().rev().take(15).cloned().collect::<Vec<_>>().join("\n");
        let sanit = app.log_lines.iter().rev().take(15).cloned().collect::<Vec<_>>().join("\n");
        let diff_lines = generate_diff_lines(&orig, &sanit, theme_map);
        let diff_para = Paragraph::new(diff_lines)
            .block(Block::default()
                .title(" 🔍 Redaction Diff ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded))
            .wrap(Wrap { trim: false });
        f.render_widget(diff_para, content_chunks[1]);
    } else if app.show_heatmap {
        render_heatmap(f, app, content_chunks[1]);
    }

    render_dashboard(f, app, vertical_chunks[2]);

    // NEW: Floating Engine Menu
    if app.show_engine_menu {
        render_engine_dropdown(f, app);
    }
}

fn render_heatmap(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);

    let mut spans = Vec::new();
    if let Some(last_raw) = app.raw_input_buffer.back() {
        for (i, c) in last_raw.chars().enumerate() {
            let score = app.heat_map.get(i).unwrap_or(&0.0);
            let color = if *score > 4.5 { Color::Red } 
                        else if *score > 3.5 { Color::LightRed }
                        else if *score > 2.5 { Color::Yellow }
                        else { Color::DarkGray };
            spans.push(Span::styled(c.to_string(), Style::default().fg(color)));
        }
    }
    let heatmap_para = Paragraph::new(Line::from(spans))
        .block(Block::default()
            .title(" 🔥 Entropy Matrix ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Yellow)))
        .wrap(Wrap { trim: true });
    f.render_widget(heatmap_para, chunks[0]);

    // Entropy Gauge
    let avg_entropy: f64 = if app.heat_map.is_empty() { 0.0 } else { app.heat_map.iter().sum::<f64>() / app.heat_map.len() as f64 };
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).title(" Average Threat Level "))
        .gauge_style(Style::default().fg(Color::LightRed).bg(Color::DarkGray))
        .ratio((avg_entropy / 8.0).min(1.0));
    f.render_widget(gauge, chunks[1]);
}

fn render_engine_dropdown(f: &mut Frame, app: &App) {
    let area = centered_rect(40, 25, f.area());
    f.render_widget(Clear, area);
    let items = vec![
        ListItem::new(" 🚀 Regex Engine (Pattern Based)"),
        ListItem::new(" 🎲 Entropy Engine (Statistical)"),
        ListItem::new(" 🛡️  Hybrid Engine (Max Security)"),
    ];
    let dropdown = List::new(items)
        .block(Block::default()
            .title(" Select Core ")
            .borders(Borders::ALL)
            .border_type(BorderType::Thick)
            .border_style(Style::default().fg(Color::Cyan).bg(Color::Black)))
        .highlight_style(Style::default().bg(Color::Cyan).fg(Color::Black).bold())
        .highlight_symbol(" ▶ ");
    let mut state = app.engine_list_state.clone();
    f.render_stateful_widget(dropdown, area, &mut state);
}

fn render_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    let match_items: Vec<ListItem> = app.matches.iter().enumerate().map(|(i, (m, status))| {
        let prefix = if app.match_list_state.selected() == Some(i) { ">" } else { " " };
        let (st, style) = match status {
            RemediationStatus::Pending => ("🔒 PENDING", Style::default().fg(Color::Yellow)),
            RemediationStatus::Approved => ("✅ APPROVED", Style::default().fg(Color::Green)),
            RemediationStatus::Revoked => ("💀 REVOKED", Style::default().fg(Color::Blue)),
            RemediationStatus::Ignored => ("👻 IGNORED", Style::default().fg(Color::DarkGray)),
        };
        
        let selection_style = if app.match_list_state.selected() == Some(i) {
            Style::default().bg(Color::Rgb(40,40,40)).bold()
        } else {
            Style::default()
        };

        ListItem::new(Line::from(vec![
            Span::styled(format!("{} {:<10} ", prefix, st), style),
            Span::raw(format!("Match: {}", m.rule_name)),
            Span::styled(" (CONFIDENCE: 99%) ", Style::default().dim()),
        ])).style(selection_style)
    }).collect();

    let remediation_list = List::new(match_items)
        .block(Block::default()
            .title(" 🛡️ Self-Healing Dashboard ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(if !app.matches.is_empty() { Color::LightRed } else { Color::Green })));
    
    let mut state = app.match_list_state.clone();
    f.render_stateful_widget(remediation_list, chunks[0], &mut state);

    let stats = &app.sync_stats;
    let sync_info = vec![
        Line::from(vec![Span::raw("Status:   "), Span::styled(" ONLINE ●", Style::default().fg(Color::Green))]),
        Line::from(vec![Span::raw("Provider: "), Span::styled(&stats.provider, Style::default().fg(Color::Cyan))]),
        Line::from(vec![Span::raw("Engine:   "), Span::styled(format!("{:?}", app.current_engine), Style::default().fg(Color::Magenta))]),
        Line::from(vec![Span::raw("Cache:    "), Span::styled(format!("{} hashes", stats.total_hashes), Style::default().fg(Color::Yellow))]),
    ];
    let sync_panel = Paragraph::new(sync_info)
        .block(Block::default()
            .title(" 🌐 Ubiquity ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .style(Style::default().fg(Color::Cyan)));
    f.render_widget(sync_panel, chunks[1]);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}