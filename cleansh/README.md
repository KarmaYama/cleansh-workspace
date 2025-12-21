# CleanSH – Sanitize Your Terminal Output, Securely.

**[Contributing Guidelines](https://www.google.com/search?q=CONTRIBUTING.md)** | **[Code of Conduct](https://www.google.com/search?q=CODE_OF_CONDUCT.md)** | **[Changelog](CHANGELOG.md)** | **[Security Policy](SECURITY.md)** | **[Trademark Policy](https://www.google.com/search?q=TRADEMARK.md)** | **[Command Handbook](https://www.google.com/search?q=COMMANDS.md)**

> CleanSH (clean shell) is a high‑trust, single‑purpose CLI tool designed to sanitize terminal output for safe sharing.
> It prioritizes security by default, requires zero configuration to get started, and offers extendability when needed.
> The project is in active development, with **`v0.1.12`** bringing major advancements in surgical redaction precision and statistical explainability.
> We value your feedback. Please report any issues you encounter. Star the repository if you like it!

---

## Table of Contents

| Section |
| --- |
| [1. Overview](https://www.google.com/search?q=%231-overview) |
| [2. License (Open Core)](https://www.google.com/search?q=%232-license-open-core) |
| [3. Core Capabilities](https://www.google.com/search?q=%233-core-capabilities) |
| [4. The Entropy Engine & Explainability](https://www.google.com/search?q=%234-the-entropy-engine--explainability) |
| [5. Usage Examples](https://www.google.com/search?q=%235-usage-examples) |
| [6. Configuration Strategy](https://www.google.com/search?q=%236-configuration-strategy) |
| [7. Future Vision](https://www.google.com/search?q=%237-future-vision) |
| [8. Installation](https://www.google.com/search?q=%238-installation) |

---

## 1. Overview

`CleanSH` is a powerful and reliable command‑line utility designed to help you quickly and securely redact sensitive information from your terminal output.
Whether you're debugging, collaborating, or sharing logs, `CleanSH` ensures that confidential data like IP addresses, email addresses, and access tokens never leave your local environment unmasked. Piped directly from `stdin` or loaded from files, `CleanSH` provides a robust, pre‑configured solution for data sanitization, with flexible options for custom rules and output formats.

**Sanitize your terminal output. One tool. One purpose.**

---

## 2. License (Open Core)

**CleanSH is now Open Source.**

* **CLI & Core Library:** Licensed under **MIT OR Apache-2.0**. You are free to use, modify, and distribute the CLI tool for any purpose, including commercial use.
* **SaaS Integration (Future):** Advanced team features like centralized profile synchronization (`cleansh profiles sync`) will be part of the Relay Enterprise platform but are currently inactive stubs in the open-source CLI.

The restrictive "PolyForm" license has been retired for all versions v0.1.9+.

---

## 3. Core Capabilities

Based on our rigorously passing test suite, `CleanSH` accurately masks:

### 3.1. Enhanced Redaction Categories:

* **Emails:** Common email formats (e.g., `user@example.com`).
* **IP Addresses:** IPv4 and IPv6.
* **Tokens & Secrets:**
* **JWTs**
* **GitHub PATs** (`ghp_…`, `github_pat_…`)
* **Stripe keys** (`sk_live_…`)
* **Cloud Keys:** AWS, GCP, Azure.
* **SSH keys & Generic Hex/Tokens.**


* **PII:** Credit Cards, SSN (US), NINO (UK), South African IDs.
* **Paths:** OS-agnostic path redaction (`/home/user` -> `~/`).

### 3.2. Primary Commands:

* **`cleansh sanitize`:** The core redaction loop.
* **`cleansh scan`:** Audit files for secrets without modifying them (Exit code support for CI/CD).
* **`cleansh profiles`:** Manage local rule configurations.

---

## 4. The Entropy Engine & Explainability

**v0.1.12 Evolution:** `CleanSH` features a context-aware **Entropy Engine** that moves beyond simple sliding windows to provide surgical precision.

Standard regex rules require you to know the *format* of a secret. The Entropy Engine solves this by detecting **statistical anomalies**—tokens that are mathematically too random to be natural language or code.

### 4.1. Surgical Precision: The "Heat-Seeker" Algorithm

Most entropy scanners over-redact because they mask the entire fixed-size window. CleanSH solves "Locator Bleed" via:

1. **Semantic Boundary Anchoring:** Detection snaps to common delimiters (like `:` or `=`), protecting labels like `auth_key=`.
2. **Statistical Decay Walk:** The engine performs a character-by-character "walk" backward from the detection site, identifying exactly where randomness ends and English begins.
3. **Lowercase Run Heuristic:** Automatically recognizes and preserves predictable natural language suffixes like `_extra_padding`.

### 4.2. Explainability: Statistical Heatmaps

CleanSH solves the "Signal-to-Noise" crisis by providing transparency. Users can visualize the randomness intensity to understand *why* a redaction occurred.

* **Critical Heat:** Bright Red indicates high-entropy secret cores.
* **Predictable Baseline:** Dimmed text indicates safe natural language.

### 4.3. Enabling the Engine

**To enable redaction for a single run:**

```bash
cat production.log | cleansh sanitize --engine entropy

```

**To visualize the entropy heatmap (Explainability Mode):**

```bash
echo "8x9#bF2!kL0Z@mN9" | cleansh sanitize --engine entropy --heatmap

```

---

## 5. Usage Examples

**Basic Sanitization:**

```bash
echo "My email is test@example.com" | cleansh sanitize

```

**Surgical Entropy Redaction:**

```bash
cat unknown_logs.txt | cleansh sanitize --engine entropy

```

**CI/CD Scan (Fail if secrets found):**

```bash
cat build.log | cleansh scan --fail-over-threshold 0

```

**Docker Logs:**

```bash
docker logs my-container | cleansh sanitize

```

**Clipboard Copy:**

```bash
git config --list | cleansh sanitize -c

```

**Diff View:**

```bash
cat error.log | cleansh sanitize -d

```

---

## 6. Configuration Strategy

### Custom Rules (`--config`)

Define your own regex rules in a YAML file:

```yaml
rules:
  - name: emp_id
    pattern: 'EMP-\d{5}'
    replace_with: '[EMPLOYEE_ID]'
    pattern_type: "regex"
    opt_in: false

```

### Entropy Tuning

Fine-tune sensitivity directly in your configuration:

```yaml
engines:
  entropy:
    threshold: 0.3
    window_size: 16

```

---

## 7. Future Vision

CleanSH is evolving into an intelligent security assistant.

* **WASM Core:** Running directly in the browser for zero-install sanitization.
* **Tauri GUI:** A native desktop app for non-CLI workflows.
* **Deep-Packet-Inspection:** Future modular backends using the plug-and-play engine pattern.

---

## 8. Installation

### Prebuilt Binaries (Recommended):

Download from [GitHub Releases](https://github.com/KarmaYama/cleansh-workspace/releases).

### From crates.io:

```bash
cargo install cleansh

```

### From Source:

```bash
git clone https://github.com/KarmaYama/cleansh-workspace.git
cd cleansh
cargo build --release

```

---

**Precision redaction. Local‑only trust. Built for devs.**

*Copyright 2025 Relay.*