# `CleanSH-core` - Core Sanitization Library

[![CodeQL](https://github.com/KarmaYama/cleansh/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/github-code-scanning/codeql) [![CodeQL Advanced](https://github.com/KarmaYama/cleansh/actions/workflows/codeql.yml/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/codeql.yml) [![Dependabot Updates](https://github.com/KarmaYama/cleansh/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/dependabot/dependabot-updates) [![Release](https://github.com/KarmaYama/cleansh/actions/workflows/release.yml/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/release.yml) [![Rust CI](https://github.com/KarmaYama/cleansh/actions/workflows/rust.yml/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/rust.yml)

**CleanSH-core** provides the fundamental, platform-independent logic for data sanitization and redaction used by the `CleanSH` CLI.

Developed by **Relay**.

## Features

* **Pluggable Architecture:** Built on the `SanitizationEngine` trait, allowing for modular detection backends.
* **Regex Engine:** High-performance, pre-compiled regex matching with ANSI escape stripping and programmatic validation (e.g., Luhn algorithms, checksums).
* **Entropy Engine:** Dynamic contextual entropy analysis for detecting unstructured secrets and high-randomness tokens.
* **Safety:** Designed with strict memory safety principles and minimal runtime overhead.

## Usage Warning

⚠️ **Note:** This library is primarily designed as the internal engine for the `cleansh` CLI. While it is published to allow for community audit and advanced integration, the public API is considered **unstable** and may change without major version bumps. Depend on it at your own risk.

For user documentation, please refer to the [Main CLI Documentation](./../cleansh/README.md).

## License

This project is licensed under the **MIT License** or **Apache License 2.0**, at your option.