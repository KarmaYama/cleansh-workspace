# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2025-12-21 — The TUI & Surgical Entropy Update

This release transforms CleanSH from a passive CLI filter into an interactive **Terminal Heads-Up Display (HUD)**. It also introduces "Surgical Extraction" to the entropy engine, allowing for precise secret removal without destroying surrounding data structures.

### Added (TUI & Interaction)
* **Real-Time TUI Dashboard:** Replaced the scrolling text output with a fully interactive Terminal User Interface (built on `ratatui`).
    * **Live Stream Panel:** View raw logs and redactions in real-time.
    * **Visual Diff Viewer:** Toggle (`[D]`) to see a side-by-side comparison of original vs. redacted text.
    * **Entropy Heatmap:** Toggle (`[H]`) to visualize the statistical "heat" (Z-score) of every character in the stream.
* **Interactive Remediation:**
    * **[A] Approve:** Whitelist false positives instantly during a session.
    * **[I] Ignore:** Dismiss alerts for the current session.
* **Dynamic Engine Switcher:** Press (`[E]`) to swap detection engines (Regex $\leftrightarrow$ Entropy) at runtime without restarting the pipe.
* **Retroactive Scanning:** Switching engines now automatically re-scans and re-renders the entire visible log history with the new detection rules.

### Added (Engine & Math)
* **Surgical Entropy Extraction:** Replaced the old fixed-window scanner with a **Statistical Decay Walk**. The engine now identifies the "heat core" of a secret and "shrink-wraps" the redaction around it, preserving surrounding text.
* **Semantic Boundary Anchoring:** The engine now respects common delimiters (e.g., `=`, `:`, `"`, `'`), preventing variable names or JSON keys from being swallowed by the redaction (e.g., `key=[REDACTED]` instead of `[REDACTED]`).
* **Explanation Dashboard:** The TUI now displays the confidence score and trigger reason for every redaction in the "Self-Healing Dashboard" panel.

### Changed
* **CLI Architecture:** The `sanitize` subcommand has been removed. Running `cleansh` now defaults immediately to the TUI mode.
* **Output Buffering:** Migrated to an unbuffered byte-level reader to support zero-latency streaming on all platforms (bypassing standard library line-buffering).
* **Configuration:** "Confidence Threshold" logic has been recalibrated. The default threshold is now optimized for the new Z-score model (0.5 - 1.0 range recommended).

### Removed
* **Legacy Flags:** Removed `--line-buffered`, `--clipboard`, and `--diff` CLI flags. These features are now native interactive toggles inside the TUI.
* **Scan Command:** The `scan` subcommand has been temporarily deprecated in favor of the live TUI workflow (will return in v0.3.0 as `cleansh shell`).

---