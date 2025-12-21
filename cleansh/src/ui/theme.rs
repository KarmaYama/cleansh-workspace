//! Module for managing the application's command-line interface (CLI) theme.
//!
//! This module defines the structure for theme configuration, allowing users
//! to customize the colors of various output elements. It supports 16-color
//! ANSI named colors for foreground styling and provides functionality to
//! load themes from YAML files and manage default theme settings.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf}; // Added PathBuf
use std::str::FromStr;
use anyhow::{Context, Result};
use owo_colors::AnsiColors;

/// Type alias for the theme map, providing a consistent type definition.
pub type ThemeMap = HashMap<ThemeEntry, ThemeStyle>;

/// The different logical parts of your output that can be styled.
///
/// Each variant represents a distinct type of message or UI element
/// that can have a configurable foreground color in the theme.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeEntry {
    /// Style for prominent headers or section titles.
    Header,
    /// Style for successful operation messages.
    Success,
    /// Style for general informational messages.
    Info,
    /// Style for warning messages.
    Warn,
    /// Style for error messages.
    Error,
    /// Style for text that has been redacted.
    RedactedText,
    /// Style for lines added in a diff view.
    DiffAdded,
    /// Style for lines removed in a diff view.
    DiffRemoved,
    /// Style for the header/footer of a diff view.
    DiffHeader,
    /// Style for the name of a rule in a summary or statistics output.
    SummaryRuleName,
    /// Style for the number of occurrences in a summary or statistics output.
    SummaryOccurrences,
    /// Style for user prompts or confirmation questions.
    Prompt,
    /// Heatmap: Critical entropy (likely a secret core).
    HeatmapCritical,
    /// Heatmap: High entropy (suspicious randomness).
    HeatmapHigh,
    /// Heatmap: Moderate entropy (potential noise).
    HeatmapModerate,
    /// Heatmap: Low entropy (predictable text).
    HeatmapLow,
}

/// Represents an ANSI color that can be used in the theme.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ThemeColor {
    /// A named ANSI color (e.g., "red", "brightgreen").
    Named(String),
}

/// Error type for parsing an invalid `ThemeColor` string.
#[derive(Debug, Clone)]
pub struct ParseThemeColorError;

impl fmt::Display for ParseThemeColorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Invalid theme color; expected one of: black, red, green, yellow, blue, \
            magenta, cyan, white, brightblack, brightred, brightgreen, brightyellow, \
            brightblue, brightmagenta, brightcyan, brightwhite."
        )
    }
}

impl std::error::Error for ParseThemeColorError {}

impl FromStr for ThemeColor {
    type Err = ParseThemeColorError;

    /// Attempts to parse a string into a `ThemeColor`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_lowercase();
        match lower.as_str() {
            "black" | "red" | "green" | "yellow" | "blue" | "magenta" | "cyan" | "white" |
            "brightblack" | "brightred" | "brightgreen" | "brightyellow" | "brightblue" | 
            "brightmagenta" | "brightcyan" | "brightwhite" => Ok(ThemeColor::Named(lower)),
            _ => Err(ParseThemeColorError),
        }
    }
}

impl ThemeColor {
    /// Converts the `ThemeColor` enum variant into its corresponding `owo_colors::AnsiColors`.
    pub fn to_ansi_color(&self) -> AnsiColors {
        match self {
            ThemeColor::Named(name) => match name.as_str() {
                "black" => AnsiColors::Black,
                "red" => AnsiColors::Red,
                "green" => AnsiColors::Green,
                "yellow" => AnsiColors::Yellow,
                "blue" => AnsiColors::Blue,
                "magenta" => AnsiColors::Magenta,
                "cyan" => AnsiColors::Cyan,
                "white" => AnsiColors::White,
                "brightblack" => AnsiColors::BrightBlack,
                "brightred" => AnsiColors::BrightRed,
                "brightgreen" => AnsiColors::BrightGreen,
                "brightyellow" => AnsiColors::BrightYellow,
                "brightblue" => AnsiColors::BrightBlue,
                "brightmagenta" => AnsiColors::BrightMagenta,
                "brightcyan" => AnsiColors::BrightCyan,
                "brightwhite" => AnsiColors::BrightWhite,
                _ => AnsiColors::White,
            },
        }
    }
}

/// Represents the style configuration for a specific `ThemeEntry`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ThemeStyle {
    /// An optional `ThemeColor` to apply as the foreground color.
    pub fg: Option<ThemeColor>,
}

/// Loads a theme configuration from a YAML file or returns the default theme.
pub fn build_theme_map(theme_path: Option<&PathBuf>) -> Result<ThemeMap> {
    if let Some(path) = theme_path {
        ThemeStyle::load_from_file(path)
    } else {
        Ok(ThemeStyle::default_theme_map())
    }
}

impl ThemeStyle {
    /// Loads a theme configuration from a YAML file on disk and merges it with default styles.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<ThemeMap> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read theme file {}", path.display()))?;
        let mut custom: ThemeMap = serde_yaml::from_str(&text)
            .with_context(|| format!("Failed to parse theme file {}", path.display()))?;
        
        for entry in [
            ThemeEntry::Header, ThemeEntry::Success, ThemeEntry::Info, ThemeEntry::Warn,
            ThemeEntry::Error, ThemeEntry::RedactedText, ThemeEntry::DiffAdded,
            ThemeEntry::DiffRemoved, ThemeEntry::DiffHeader, ThemeEntry::SummaryRuleName,
            ThemeEntry::SummaryOccurrences, ThemeEntry::Prompt,
            ThemeEntry::HeatmapCritical, ThemeEntry::HeatmapHigh,
            ThemeEntry::HeatmapModerate, ThemeEntry::HeatmapLow,
        ] {
            custom.entry(entry).or_insert_with(|| ThemeStyle { fg: Some(ThemeColor::Named("white".into())) });
        }
        Ok(custom)
    }

    /// Returns a default theme map with predefined color mappings.
    pub fn default_theme_map() -> ThemeMap {
        let mut default_theme = HashMap::new();
        default_theme.insert(ThemeEntry::DiffAdded, ThemeStyle { fg: Some(ThemeColor::Named("green".into())) });
        default_theme.insert(ThemeEntry::DiffRemoved, ThemeStyle { fg: Some(ThemeColor::Named("red".into())) });

        // Default Heatmap Colors
        default_theme.insert(ThemeEntry::HeatmapCritical, ThemeStyle { fg: Some(ThemeColor::Named("brightred".into())) });
        default_theme.insert(ThemeEntry::HeatmapHigh, ThemeStyle { fg: Some(ThemeColor::Named("red".into())) });
        default_theme.insert(ThemeEntry::HeatmapModerate, ThemeStyle { fg: Some(ThemeColor::Named("yellow".into())) });
        default_theme.insert(ThemeEntry::HeatmapLow, ThemeStyle { fg: Some(ThemeColor::Named("brightblack".into())) });

        for entry in [
            ThemeEntry::Header, ThemeEntry::Success, ThemeEntry::Info, ThemeEntry::Warn,
            ThemeEntry::Error, ThemeEntry::RedactedText, ThemeEntry::DiffHeader,
            ThemeEntry::SummaryRuleName, ThemeEntry::SummaryOccurrences, ThemeEntry::Prompt,
        ] {
            default_theme.entry(entry).or_insert_with(|| ThemeStyle { fg: Some(ThemeColor::Named("white".into())) });
        }
        default_theme
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_named_colors() {
        assert!("red".parse::<ThemeColor>().is_ok());
        assert!("BrightGreen".parse::<ThemeColor>().is_ok());
        assert!("unknown".parse::<ThemeColor>().is_err());
    }

    #[test]
    fn to_ansi_color_roundtrip() {
        let tc: ThemeColor = "blue".parse().unwrap();
        assert_eq!(tc.to_ansi_color(), AnsiColors::Blue);
        let tc: ThemeColor = "brightmagenta".parse().unwrap();
        assert_eq!(tc.to_ansi_color(), AnsiColors::BrightMagenta);
    }
}