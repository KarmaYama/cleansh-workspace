# CleanSH – Sanitize Your Terminal Output, Securely.

[![Downloads from crates.io](https://img.shields.io/crates/d/cleansh.svg?style=for-the-badge&labelColor=334155&color=4FC3F7)](https://crates.io/crates/cleansh) [![CodeQL](https://github.com/KarmaYama/cleansh/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/github-code-scanning/codeql) [![CodeQL Advanced](https://github.com/KarmaYama/cleansh/actions/workflows/codeql.yml/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/codeql.yml) [![Dependabot Updates](https://github.com/KarmaYama/cleansh/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/dependabot/dependabot-updates) [![Release](https://github.com/KarmaYama/cleansh/actions/workflows/release.yml/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/release.yml) [![Rust CI](https://github.com/KarmaYama/cleansh/actions/workflows/rust.yml/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/rust.yml) [![Star](https://img.shields.io/github/stars/KarmaYama/cleansh.svg?style=social)](https://github.com/KarmaYama/cleansh/stargazers)

**[Contributing Guidelines](CONTRIBUTING.md)** | **[Code of Conduct](CODE_OF_CONDUCT.md)** | **[Changelog](CHANGELOG.md)** | **[Security Policy](SECURITY.md)** | **[Trademark Policy](TRADEMARK.md)** | **[Command Handbook](COMMANDS.md)**

> CleanSH (clean shell) is a high‑trust, single‑purpose CLI tool designed to sanitize terminal output for safe sharing.
> It prioritizes security by default, requires zero configuration to get started, and offers extendability when needed.
> The project is in active development, with **`v0.1.11`** bringing significant enhancements to redaction accuracy, security, and user control.
> We value your feedback. Please report any issues you encounter. Star the repository if you like it!

---

## Table of Contents

| Section |
| :---------------------------------------------------------------------- |
| [1. Overview](#1-overview) |
| [2. License (Open Core)](#2-license-open-core) |
| [3. Core Capabilities](#3-core-capabilities) |
| [4. The New Entropy Engine](#4-the-new-entropy-engine) |
| [5. Usage Examples](#5-usage-examples) |
| [6. Configuration Strategy](#6-configuration-strategy) |
| [7. Future Vision](#7-future-vision) |
| [8. Installation](#8-installation) |

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

## 4. The New Entropy Engine

**New in v0.1.9:** `CleanSH` now includes a context-aware **Entropy Engine** alongside its Regex core.

Standard regex rules require you to know the *format* of a secret (e.g., "starts with `sk_live_`"). But what about a random 32-character database password or a custom API key? If you don't have a regex for it, standard tools will miss it.

The Entropy Engine solves this by detecting **statistical anomalies**—tokens that are mathematically too random to be natural language or code.

### 4.1. The "False Positive" Problem (And How We Solved It)

Most entropy scanners fail because of the **Self-Reference Paradox**: when they calculate the "average randomness" of a text block to see if a token is an outlier, they include the token itself in that average. A high-entropy secret inflates the baseline, effectively hiding itself.

**The CleanSH Solution: "Leave-One-Out" Baseline**
Our engine uses a rigorous statistical approach:
1.  **Isolation:** When analyzing a candidate token (e.g., `8x9#bF2!kL`), we calculate the baseline entropy of the surrounding context *while mathematically excluding the token itself*.
2.  **Z-Score Analysis:** We calculate a Z-score (standard deviation from the mean). If the token is significantly more random than its isolated background, it is flagged.
3.  **Context Boosting:** We scan the preceding bytes for "danger words" (like `key`, `auth`, `secret`) using an Aho-Corasick automaton. A match here lowers the statistical threshold required to flag the secret.

### 4.2. Enabling the Engine

The Entropy Engine is opt-in because it is computationally more intensive than regex.

**To enable it for a single run:**
```bash
# Scan with BOTH Regex and Entropy engines
cat production.log | cleansh sanitize --engine entropy

```

**When to use it:**

* Scanning legacy codebases for hardcoded passwords.
* Auditing logs where the format of secrets is unknown.
* Sanitizing messy data dumps containing mixed binary/text content.

---

## 5. Usage Examples

**Basic Sanitization:**

```bash
echo "My email is test@example.com" | cleansh sanitize

```

**Using the Entropy Engine:**

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

### Enable/Disable

Control rules on the fly:

```bash
cleansh sanitize --enable "uk_nino,aws_secret_key" --disable "email"

```

---

## 7. Future Vision

CleanSH is evolving into an intelligent security assistant.

* **WASM Core:** Running directly in the browser for zero-install sanitization.
* **Tauri GUI:** A native desktop app for non-CLI workflows.
* **Entropy Tuning:** Interactive feedback loops to train the entropy engine on your specific data.

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
git clone [https://github.com/KarmaYama/cleansh-workspace.git](https://github.com/KarmaYama/cleansh-workspace.git)
cd cleansh
cargo build --release

```

---

**Precision redaction. Local‑only trust. Built for devs.**

*Copyright 2025 Relay.*

