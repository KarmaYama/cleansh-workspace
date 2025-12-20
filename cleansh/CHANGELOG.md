# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.11] - 2025-12-20 — Dynamic Entropy Configuration

### Added
* **Configurable Entropy Threshold:** `CleanSH` now supports dynamic configuration of the entropy engine's sensitivity. While there is no direct CLI flag yet, you can now set `engines.entropy.threshold` in your `cleansh.toml` or custom config file (default: 0.5).
* **CLI Dependency Update:** Updated `cleansh-core` to `v0.1.5` to enable the fix for the "impossible threshold" bug in the entropy engine.

---

## [0.1.9] - 2025-12-19 — Open Source Transition & Entropy Engine

This release marks a pivotal shift in the project's history. **`CleanSH` is now fully Open Source under the MIT/Apache-2.0 licenses**, removing all previous usage restrictions. We have also introduced the powerful new **Dynamic Contextual Entropy Engine** for detecting unstructured secrets.

### Added

* **Entropy Engine:** A new detection backend that uses Shannon entropy and contextual analysis (Z-score anomaly detection) to find high-randomness secrets (like custom API keys) that regex patterns often miss.
    * Enable it via: `cleansh sanitize --engine entropy`
* **`cleansh-entropy` Crate:** A standalone, `no_std`, zero-copy library implementing the core math for entropy scanning, statistical baselining, and Aho-Corasick context matching.
* **`--engine` Flag:** New CLI option to switch between `regex` (default) and `entropy` engines.

### Changed

* **Re-Licensing:** The entire workspace is now dual-licensed under **MIT OR Apache-2.0**. The PolyForm Noncommercial license has been retired.
* **Open Core Model:** Previously "Pro" features like the `scan` command are now free and ungated for all users.
* **Rebranding:** Project ownership updated to **Relay** (formerly Obscura Tech). Support contact updated to `security@relay.africa`.
* **Core Refactor:** `cleansh-core` architecture simplified to remove duplicate sanitizer logic and strictly enforce the `SanitizationEngine` trait.

### Removed

* **License Gating:** Removed all local license validation logic, cryptographic key checks, and the `utils/license.rs` module.
* **License Notes:** Deleted `LICENSE_NOTES.md` as the tiered restriction model no longer applies to the CLI.
* **Build Warnings:** Removed the build-time warning regarding the PolyForm license in `build.rs`.

---

## [0.1.8] - 2025-08-08 — Core Engine Refactoring & CLI Improvements

This release is a major architectural overhaul, focusing on making `CleanSH` more **modular, maintainable, and extensible**. We've introduced an abstraction layer for the sanitization engine, streamlined the command-line interface, and separated core logic into reusable functions.

### Added

* **Engine Abstraction:** A new `SanitizationEngine` trait allows for different sanitization backends, starting with the primary `RegexEngine`.
* **New Subcommands:** A new, more intuitive subcommand structure has been introduced (`sanitize`, `scan`, `profiles`).
* **Line-Buffered Mode Summary:** The line-buffered mode now aggregates match counts and prints a summary upon completion.

### Changed

* **Code Modularity:** All key logic, including input reading, engine creation, and command handling, has been centralized into dedicated helper functions.
* **Simplified CLI Flags:** The `--no-clipboard` and `--no-diff` flags have been removed. The `--clipboard` and `--diff` flags now default to `false` and must be explicitly enabled.
* **State Management:** The logic for donation prompts and application state persistence has been moved to the main command loop.

---

## [0.1.7] - 2025-08-03 — Fix: Improved Redaction Accuracy & CLI Stability Enhancements

This release focuses on addressing a critical issue in path redaction and a configuration parsing error, enhancing the overall precision and reliability of `CleanSH`.

### Fixed

* **Corrected Linux and macOS Path Redaction:** Resolved a bug where backreferences (`$1`) in the `replace_with` string were not being expanded correctly by the core sanitization engine.
* **Corrected Interactive Stdin Instructions:** Fixed an issue where the CLI incorrectly prompted users on Linux/macOS to use `Ctrl+Z` to end standard input.

---

## [0.1.6] - 2025-07-31 — Architectural Refinement for Stability & Future Growth

This release primarily focuses on a significant **architectural refinement** within `CleanSH`, laying a more robust and modular foundation for its continued evolution.

### Changed

* **Underlying Architectural Reorganization:** `CleanSH` has undergone a substantial internal architectural shift. This change introduces a clearer separation of concerns, decoupling the core data processing and redaction logic from the CLI's user interface.

### Improved

* **Enhanced Maintainability and Clarity:** The refactored codebase improves overall code clarity and adheres more rigorously to best practices in modular design.

---

## [0.1.5] - 2025-07-27 — Phase 1: Refined Redaction, Stats Foundation & Rule Expansion

This release marks a significant leap forward for `CleanSH`, introducing a **powerful new statistics mode for in-depth redaction analysis**.

### Added

* **New Command: Uninstall (`Cleansh uninstall`)**
* **Redaction Statistics Mode (`--stats-only`)**
* **JSON Statistics Export (`--stats-json-file <FILE>`, `--export-json-to-stdout`)**
* **Sample Matches in Statistics (`--sample-matches <N>`)**
* **Fail-over Threshold (`--fail-over <X>`)**
* **New redaction patterns:** GitHub PATs, Stripe keys, OAuth tokens, IPv6, SSN, NINO, and more.
* **Real-time Monitoring Mode (`--line-buffered`)**
* **ANSI Escape Stripping Layer**

### Changed

* **Regex Patterns:** Added `\b` anchors or full start/end matches to all regex rules to reduce partial/substring false positives.
* **Rule Management System:** Now respects `opt_in: true` and filters rules at runtime.
* **Filesystem Path Rules:** Improved detection for Windows drive letters and refocused Linux/macOS rules.

---

## [0.1.2] - 2025-07-12 - Stability & Output Refinement

### Fixed

* **Resolved critical output formatting issues** ensuring the application's stdout behavior aligns perfectly with expectations.
* **Corrected an oversight in the application's output logic** where an "No redactions applied." message was incorrectly suppressed.

---

## [0.1.1] - 2025-07-12 - Precision View

### Fixed

* Resolved a critical bug in the `--diff` view functionality that caused incorrect output formatting.

### Changed

* Upgraded the internal diff generation engine for more robust and visually appealing diff output.

---

## [0.1.0] - 2025-07-12 - Initial Public Release (Pre-release)

### Added

* Initial core sanitization capabilities for common sensitive data types.
* Absolute path redaction and normalization.
* Core CLI flags: `--clipboard (-c)`, `--diff (-d)`, `--config`, `--out`.
* Layered configuration system supporting runtime settings and user-defined YAML rules.
* Robust logging and error handling infrastructure.