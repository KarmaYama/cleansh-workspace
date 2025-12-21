# CleanSH Workspace – The Secure Terminal Monorepo

**[Contributing](https://www.google.com/search?q=CONTRIBUTING.md)** | **[Code of Conduct](https://www.google.com/search?q=CODE_OF_CONDUCT.md)** | **[Security Policy](SECURITY.md)**

> **CleanSH** (Clean Shell) is a high-trust, modular Rust ecosystem designed to securely sanitize sensitive data from terminal output, logs, and text streams.
> **v0.2.0 Update:** The CLI has evolved into a real-time **Terminal HUD (Heads-Up Display)** with surgical entropy detection.

---

## Overview

This repository is a **Rust Monorepo** managing the ecosystem of tools and libraries that power CleanSH. It promotes modularity, type safety, and zero-copy performance across the stack.

### Key Components

| Crate | Location | Description |
| --- | --- | --- |
| **`cleansh`** | [`/cleansh`](https://www.google.com/search?q=./cleansh/README.md) | **The CLI Application.** Now a full TUI dashboard built on `ratatui`. It orchestrates the real-time scanning pipeline, renders the "Cockpit" UI, and handles user interaction (Approvals/Ignores). |
| **`cleansh-core`** | [`/cleansh-core`](https://www.google.com/search?q=./cleansh-core/README.md) | **The Business Logic.** Defines the `SanitizationEngine` trait, manages configuration profiles (`config.yaml`), and handles the "Surgical Extraction" logic. |
| **`cleansh-entropy`** | [`/cleansh-entropy`](https://www.google.com/search?q=./cleansh-entropy/README.md) | **The Math Engine.** A `no_std`, zero-copy library implementing Shannon entropy calculation, Z-Score anomaly detection, and statistical decay walks. |

---

## Technical Principles: The "Surgical" Approach

CleanSH v0.2.0 solves the "Locator Bleed" problem common in regex-based scanners. Most tools are blunt instruments—they redact entire lines or fixed windows, destroying context. CleanSH uses a **Surgical Pipeline**:

### 1. Dynamic Z-Score Detection

Instead of a static threshold (which causes false positives), CleanSH calculates a **local entropy baseline**. A token is only flagged if its Shannon entropy deviates significantly (standard deviations) from the surrounding text.

### 2. Statistical Decay Walk (Surgical Extraction)

Once a high-entropy "peak" is found, the engine performs a **decay walk** outwards character-by-character. It identifies exactly where the randomness "cools down" into natural language.

* **Result:** It preserves suffixes like `_padding`, `.json`, or `";`, ensuring JSON structures and variable assignments remain valid code even after redaction.

### 3. Semantic Boundary Anchoring

The engine respects semantic delimiters (`=`, `:`, `"`, `'`). It "snaps" the redaction start point to these anchors, ensuring that labels (e.g., `api_key=`) are never swallowed by the redaction mask.

---

## License (Open Source)

The entire workspace is **Open Source**.

* **License:** Dual-licensed under **MIT** or **Apache-2.0**.
* **Commercial Use:** You are free to use, modify, and distribute these tools for any purpose, including commercial applications.

*Note: The restrictive "PolyForm" license used in early versions has been retired.*

---

## Getting Started

### Prerequisites

* Rust 1.70+ (Stable)

### Build from Source

1. **Clone the Monorepo:**
```bash
git clone https://github.com/KarmaYama/cleansh-workspace.git
cd cleansh-workspace

```


2. **Build All Crates:**
```bash
cargo build --release --workspace

```


3. **Run the Test Suite:**
```bash
# Runs unit tests, integration tests, and entropy math verification
cargo test --workspace

```


4. **Install the CLI Locally:**
```bash
cargo install --path cleansh

```



---

## Contributing

We welcome contributions! Whether it's optimizing the math engine, adding new TUI widgets, or improving documentation.

1. Check the [Issues](https://github.com/KarmaYama/cleansh-workspace/issues) page.
2. Read the [Contributing Guide](https://www.google.com/search?q=CONTRIBUTING.md).
3. Open a Pull Request.

---

**CleanSH Workspace**
*Precision redaction through statistical anomaly detection.*