// cleansh/src/ui/diff_viewer.rs
//! TUI-native Diff Viewer for CleanSH v0.2.0.
//!
//! Generates Ratatui-compatible Spans and Lines to visualize redactions.

use crate::ui::theme::{ThemeEntry, ThemeMap};
use ratatui::text::{Line, Span};
use ratatui::style::{Style, Color, Modifier};
use diffy::{create_patch, Line as DiffLine};

/// Generates a list of Lines for a Ratatui List or Paragraph widget.
/// This highlights exactly what was removed (red) and what was added (green).
pub fn generate_diff_lines<'a>(
    original: &'a str,
    sanitized: &'a str,
    theme_map: &ThemeMap,
) -> Vec<Line<'a>> {
    let patch = create_patch(original, sanitized);
    let mut lines = Vec::new();

    // Add Header Line
    lines.push(Line::from(Span::styled(
        "--- Diff Analysis ---",
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    )));

    for hunk in patch.hunks() {
        for line_change in hunk.lines() {
            match line_change {
                DiffLine::Delete(s) => {
                    lines.push(Line::from(vec![
                        Span::styled("- ", Style::default().fg(Color::Red)),
                        Span::styled(s.to_string(), get_theme_style(ThemeEntry::DiffRemoved, theme_map)),
                    ]));
                }
                DiffLine::Insert(s) => {
                    lines.push(Line::from(vec![
                        Span::styled("+ ", Style::default().fg(Color::Green)),
                        Span::styled(s.to_string(), get_theme_style(ThemeEntry::DiffAdded, theme_map)),
                    ]));
                }
                DiffLine::Context(s) => {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::raw(s.to_string()),
                    ]));
                }
            }
        }
    }

    if lines.len() <= 1 {
        lines.push(Line::from(Span::raw("No changes detected in this segment.")));
    }

    lines
}

/// Helper to map our ThemeMap entries to Ratatui Styles.
fn get_theme_style(entry: ThemeEntry, theme_map: &ThemeMap) -> Style {
    if let Some(theme_style) = theme_map.get(&entry) {
        if let Some(color) = &theme_style.fg {
            return Style::default().fg(color.to_ansi_color_ratatui());
        }
    }
    Style::default()
}

/// Extension trait for ThemeColor to support Ratatui types.
impl crate::ui::theme::ThemeColor {
    pub fn to_ansi_color_ratatui(&self) -> Color {
        match self {
            crate::ui::theme::ThemeColor::Named(name) => match name.as_str() {
                "black" => Color::Black,
                "red" => Color::Red,
                "green" => Color::Green,
                "yellow" => Color::Yellow,
                "blue" => Color::Blue,
                "magenta" => Color::Magenta,
                "cyan" => Color::Cyan,
                "white" => Color::White,
                "brightblack" => Color::DarkGray,
                "brightred" => Color::LightRed,
                "brightgreen" => Color::LightGreen,
                "brightyellow" => Color::LightYellow,
                "brightblue" => Color::LightBlue,
                "brightmagenta" => Color::LightMagenta,
                "brightcyan" => Color::LightCyan,
                "brightwhite" => Color::White,
                _ => Color::Reset,
            },
        }
    }
}