# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.6] - 2025-12-20 — Heat-Mapping API & Dependency Inversion

### Added
* **Heat Score Provider:** Updated the `SanitizationEngine` trait with `get_heat_scores(&self, content: &str)`.This allows UI implementations to render statistical heatmaps without direct dependencies on the low-level math crate.
***Statistical Decay Walk:** Implemented the high-level orchestration for entropy gradient extraction, enabling precision redaction in unstructured logs.


## [0.1.5] - 2025-12-20 — Dynamic Entropy Configuration

### Added
* **Configurable Entropy Threshold:** Implemented `EntropyConfig` and `EngineConfig` structs within `RedactionConfig`. This allows users to fine-tune the confidence `threshold` for the entropy engine directly via their configuration file (e.g., `cleansh.toml`).
* **Integration Tests:** Added `tests/entropy_config_test.rs` to verify that the dynamic threshold is respected and effectively controls detection sensitivity (e.g., setting it to `0.5` vs `5.0`).

### Fixed
* **Impossible Threshold Bug:** Fixed a critical logic error where the `EntropyEngine` was initialized with a hardcoded confidence threshold of `4.0`. Since the maximum possible score from the scoring algorithm is `3.0` (1.0 entropy + 2.0 context), this effectively disabled all secret detection. The default is now safely set to `0.5` and is fully configurable.

---

## [0.1.4] - 2025-12-20 — Security Fix

### Security

* **Fixed Hardcoded Key Vulnerability:** Resolved a CodeQL alert (CWE-321) in the profile run-seed generation logic. Previously, dynamic strings were inadvertently used as cryptographic keys in HMAC operations. The logic has been updated to use a fixed, high-entropy salt as the key, treating the dynamic version strings as input data. This ensures cryptographic best practices are followed.

---

## [0.1.3] - 2025-12-19 — Entropy Engine Integration & Open Source Transition

This release integrates the new **Dynamic Contextual Entropy Engine**, enabling `cleansh-core` to detect unstructured secrets based on statistical randomness. It also marks the transition of the core library to a fully Open Source license model.

### Added

* **Entropy Engine Integration:** Added `cleansh-entropy` as a dependency.
* **`EntropyEngine` Struct:** A new `SanitizationEngine` implementation that adapts the low-level math from `cleansh-entropy` to the high-level sanitization trait.
* **New Engine Module:** Added `engines/entropy_engine.rs` to house the new logic.

### Changed

* **Re-Licensing:** The crate is now dual-licensed under **MIT OR Apache-2.0**. The PolyForm Noncommercial license has been retired.
* **Engine Trait Updates:** Minor adjustments to `SanitizationEngine` to support probabilistic matching (confidence scores).

---

## [0.1.2] - 2025-08-08 — Core Engine Refactoring, Engine Abstraction & Improved Rule Management

This release introduces a major architectural refactoring of the core sanitization engine. It abstracts the redaction logic behind a trait, enabling multiple backends and improving the application's extensibility. The update also streamlines CLI flags and centralizes key logic into dedicated helper functions, making the codebase more modular, maintainable, and robust. This version also refactors the programmatic validators for Social Security Numbers and UK National Insurance Numbers for improved clarity and accuracy.

### Added

* **Engine Abstraction (`SanitizationEngine` Trait)::** A new trait, `SanitizationEngine`, has been introduced to define a common interface for different sanitization backends. The existing regex-based logic is now encapsulated in a concrete implementation, `RegexEngine`, which adheres to this trait.
* **New `engine.rs` Module:** A new module has been created to house the `SanitizationEngine` trait and the `RegexEngine` implementation. This modular design separates the core sanitization logic from the rule compilation process.
* **New `sanitizers/` Directory:** A new directory has been added to house the `regex_sanitizer.rs` module, which contains the compilation logic for regex-based rules.
* **`SanitizationContext` Struct:** A new helper struct that centralizes the boilerplate logic for resolving overlapping matches, building the final sanitized string, and generating the summary.
* **`RedactionMatch` Position Data:** The `RedactionMatch` struct has been enhanced with two new fields, `start` and `end`, to record the byte indices of a match. This is crucial for accurately handling overlapping matches and reconstructing the sanitized string.
* **`RedactionConfig::set_active_rules` Method:** A new function that allows for explicit, programmatic control over which rules are active by accepting separate lists of rules to enable and disable. This replaces the less flexible "default" and "strict" configurations.
* **`HashSet` Dependency:** The `std::collections::HashSet` has been added to improve the efficiency of managing and checking rule names.
* **`profiles.rs` Module:** A new module, `profiles.rs`, has been added to introduce the concept of named redaction profiles. This module provides the core logic for defining, loading, and applying profile-specific settings, including sampling and post-processing configurations.
* **New `opt_in` Rule Flag:** The `RedactionRule` struct now includes an `opt_in` boolean field. Rules with `opt_in: true` are disabled by default and are only compiled and applied if explicitly enabled.
* **Credit Card Validator:** Added a new `is_valid_credit_card_programmatically` validator that uses the Luhn algorithm for an additional layer of accuracy in identifying valid credit card numbers.

### Changed

* **Sanitization Logic Flow:** The core sanitization process has been refactored. The `sanitize_content` function has been removed and its logic is now part of the `SanitizationEngine::sanitize` method and the `SanitizationContext` struct. This moves the match aggregation and string reconstruction logic to a single, centralized location.
* **Rule Compilation (`compile_rules`):** The signature of `compile_rules` has been simplified to only accept `rules_to_compile`, as the filtering logic for enabling and disabling rules is now handled earlier in the `RedactionConfig` module. The function has been moved into the new `sanitizers/regex_sanitizer.rs` module.
* **`validators.rs`:** The validation logic for US Social Security Numbers (`is_valid_ssn_programmatically`) has been corrected to more accurately reflect historical rules, removing an incorrect check for the `700-729` area code range and adding the `800` range as invalid. The UK NINO validation logic was also refactored for clarity, using more readable methods and array lookups.
* **Core API & `lib.rs`:** The top-level `lib.rs` now re-exports the new `SanitizationEngine` and `RegexEngine` types, which represent the new primary public API. The older, lower-level functions like `sanitize_content` are no longer publicly exposed.
* **Backreference Handling:** The `replace_all` closure within the regex matching logic has been updated to correctly process replacement strings containing backreferences (e.g., `$1`).
* **Logging:** Logging statements have been streamlined across the configuration module. Redundant log prefixes have been removed for cleaner output, and the final loaded rule count is now reported at a more appropriate `info!` level.
* **`RedactionMatch` Example:** An inaccuracy in the `redact_sensitive` function's documentation example has been corrected to reflect the actual character count of the example string.
* **SSN Validation Logic:** The programmatic validation for US Social Security Numbers (`is_valid_ssn_programmatically`) has been rewritten to be more readable and structured. The long, chained conditional checks were replaced with a series of distinct, easy-to-read checks for each validation criterion. The parsing of SSN parts now uses a `match` statement for safer, more explicit error handling.
* **UK NINO Validation Logic:** The programmatic validation for UK National Insurance Numbers (`is_valid_uk_nino_programmatically`) was refactored for clarity. The validation steps are now clearly separated and use more explicit methods like array lookups (`contains`) instead of macros where appropriate.

### Removed

* **`sanitize_content` Function:** The top-level `sanitize_content` function has been removed. Its core logic has been refactored and integrated into the new `SanitizationEngine` trait and `SanitizationContext` helper struct.
* **`RedactionConfig::set_active_rules_config` Method:** This method has been removed in favor of the more flexible and explicit `set_active_rules` method.
* **`sanitizer.rs` Module:** The `sanitizer.rs` module has been removed and its functionality has been moved to the new `sanitizers/regex_sanitizer.rs` module.

---

## [0.1.1] - 2025-08-03 — Fix: Backreference Handling & Enhanced Config Validation

This release addresses two key issues found during integration testing, ensuring the core sanitization engine correctly handles backreferences in replacement strings and gracefully recovers from malformed rule configurations.

### Fixed

* **Corrected Backreference Expansion:** The `replace_all` closure now correctly processes replacement strings with backreferences (e.g., `"$1"`). This ensures that rules like `absolute_linux_path` and `absolute_macos_path` can perform partial redactions, preserving non-sensitive portions of the matched text.

---

## [0.1.0] - 2025-07-31 — Initial Library Crate Release

This is the inaugural release of the `CleanSH-core` library crate. This version encapsulates the core logic of the `CleanSH` application, providing a robust and reusable engine for sensitive data redaction.

### Added

* **Core Sanitization Engine:** A dedicated, standalone library for identifying and redacting sensitive data.
* **Rule Management & Compilation:** Functionality to load, validate, and compile redaction rules from a configuration source into efficient regular expressions.
* **Programmatic Validation Hooks:** Support for advanced, non-regex validation checks (e.g., checksums) via the `programmatic_validation` flag in rules.
* **ANSI Escape Stripping:** A preprocessing layer to remove ANSI escape codes before pattern matching, ensuring reliable redaction.
* **Redaction Match Struct:** A structured format for reporting details of each redaction, including original and sanitized values.
* **Modular Design:** The crate is designed with a clear separation of concerns, making it easy to integrate into other applications or CLI tools.