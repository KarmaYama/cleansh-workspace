# `CleanSH-core` - Core Sanitization Library

**CleanSH-core** provides the fundamental, platform-independent logic for data sanitization and redaction used by the `CleanSH` CLI.

Developed by **Relay**.

---

## Features

* **Pluggable Architecture:** Built on the `SanitizationEngine` trait, allowing for modular detection backends.
* **Regex Engine:** High-performance, pre-compiled regex matching with ANSI escape stripping and programmatic validation (e.g., Luhn algorithms, checksums).
* **Entropy Engine (v0.1.6):** Dynamic contextual entropy analysis for detecting unstructured secrets and high-randomness tokens. It now supports **Entropy Heatmaps** through a dedicated heat score provider.
* **Heat-Seeker Extraction:** Precision redaction logic that identifies the "heat core" of a secret and surgically extracts it, preventing natural language bleeding.
* **Safety:** Designed with strict memory safety principles and minimal runtime overhead.

---

## Technical Overview: The Explainability Bridge

The library utilizes **Strict Dependency Inversion** to provide statistical transparency to the UI layer. The `SanitizationEngine` trait now includes a `get_heat_scores` method. This allows the CLI to visualize Shannon entropy gradients without needing a direct dependency on low-level math crates.

---

## Usage Warning

⚠️ **Note:** This library is primarily designed as the internal engine for the `cleansh` CLI. While it is published to allow for community audit and advanced integration, the public API is considered **unstable** and may change without major version bumps. Depend on it at your own risk.

For user documentation, please refer to the [suspicious link removed].

---

## License

This project is licensed under the **MIT License** or **Apache License 2.0**, at your option.
