# CleanSH Command Handbook: v0.1.12 Edition

Welcome to the updated **CleanSH Command Handbook**. With the release of **v0.1.12**, `CleanSH` has evolved from a pattern-matching tool into a **surgical statistical engine**. This guide covers the core capabilities, new explainability features, and strategic configuration options.

---

## 1. What is CleanSH?

`CleanSH` (pronounced "clean shell") is a **high-trust, local-first CLI tool** designed to redact sensitive data from text streams. It serves as a digital bouncer for your logs, terminal output, and CI/CD pipelines, ensuring that **PII, IP addresses, and unstructured secrets** never leak during collaboration.

### The v0.1.12 Milestone: Surgical Precision

Unlike traditional scanners that redact entire blocks of text, `CleanSH` v0.1.12 introduces **Entropy Gradient Extraction**. It identifies the "heat core" of a secret and surgically "shrink-wraps" the redaction, preserving the surrounding natural language.

---

## 2. Getting Started

### Installation

**From GitHub Releases:**
Download prebuilt binaries for your platform from the [Releases Page](https://github.com/KarmaYama/cleansh-workspace/releases).

**Via Cargo:**

```bash
cargo install cleansh

```

---

## 3. Command Architecture

`CleanSH` utilizes a modular subcommand structure to handle different stages of the data lifecycle.

| Command | Description | Use Case |
| --- | --- | --- |
| **`sanitize`** | The primary redaction engine. | Daily log cleaning and clipboard safety. |
| **`scan`** | Audit mode (report only). | Pre-shipment security audits. |
| **`profiles`** | Rule set management. | Creating and signing compliance sets. |
| **`uninstall`** | Clean system removal. | System maintenance. |

---

## 4. Core Capabilities (Open Source)

All core features are free under the **MIT OR Apache-2.0** licenses.

### 4.1. `cleansh sanitize` – Surgical Redaction

This command processes input via `stdin` or files and applies the selected engine.

**Basic Usage:**

```bash
echo "User login: admin@relay.africa" | cleansh sanitize

```

**New: The Heat-Seeker Engine**
To catch unstructured secrets (random tokens) with surgical precision:

```bash
cat app.log | cleansh sanitize --engine entropy --entropy-threshold 0.3

```

* **Surgical Extraction:** Automatically stops redacting when it hits English suffixes like `_padding` or `ing`.
* **Semantic Anchoring:** Recognizes delimiters like `=` or `:` to protect labels.

### 4.2. New: Entropy Heatmap (Explainability)

V0.1.12 introduces the **Heatmap Mode**. Instead of redacting, it visualizes the randomness of every character, proving *why* the engine flagged a specific string.

```bash
echo "key=8x9#bF2!kL0Z" | cleansh sanitize --engine entropy --heatmap

```

* **Red:** Critical randomness (likely a secret).
* **Yellow:** Suspicious noise.
* **Dimmed:** Predictable natural language.

### 4.3. `cleansh scan` – CI/CD Enforcement

Use `scan` to audit data without modification. It is ideal for build pipelines.

**Scenario:** Fail a GitHub Action if any secret is detected.

```bash
docker logs my-app | cleansh scan --fail-over-threshold 0

```

---

## 5. Global Flags & Tuning

| Flag | Shortcut | Description |
| --- | --- | --- |
| **`--engine`** | N/A | Switch between `regex` (default) or `entropy`. |
| **`--heatmap`** | N/A | Visualize statistical heat instead of redacting. |
| **`--diff`** | `-D` | Show a colored unified diff of changes. |
| **`--clipboard`** | `-c` | Instantly copy sanitized results to clipboard. |
| **`--entropy-threshold`** | N/A | Sensitivity (0.0 to 1.0). Default is 0.5. |
| **`--entropy-window`** | N/A | Sliding window size (e.g., 16 or 24). |

---

## 6. Configuration Strategy

### Custom YAML Rules

Create `rules.yaml` to define proprietary patterns:

```yaml
rules:
  - name: "internal_id"
    pattern: 'ID-[A-Z]{3}-\d{4}'
    replace_with: '[INTERNAL_ID]'

```

**Apply:**

```bash
cleansh sanitize input.txt --config ./rules.yaml

```

---

**Precision Redaction. Explainable Security. Local-Only Trust.**

*Copyright 2025 Relay. v0.1.12 Build.*
