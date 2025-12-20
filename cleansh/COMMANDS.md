# CleanSH Command Handbook

Welcome to the **CleanSH Command Handbook**! This guide dives deeper into `CleanSH`, your indispensable command-line utility for sanitizing sensitive information from terminal output.

We'll go beyond just listing commands, exploring scenarios, use cases, and how to harness `CleanSH`'s full potential.

---

## 1. What is CleanSH?

At its core, `CleanSH` (pronounced "clean shell") is a **high-trust, single-purpose CLI tool** designed to redact sensitive data from text streams. Think of it as your digital bouncer, ensuring confidential information like **IP addresses, email addresses, API keys, and even personal identifiers** never accidentally leak when you're sharing logs, debugging output, or collaborating with others.

It operates **locally**, requires zero configuration to get started with its robust default rules, and offers extensive flexibility for custom needs.

---

## 2. Getting Started with CleanSH

### Installation

**From GitHub Releases (Recommended):**
Download the latest prebuilt binaries for your platform from the [GitHub Releases](https://github.com/KarmaYama/cleansh-workspace/releases) page.

**Install Script:**
```bash
curl -sSf [https://github.com/KarmaYama/cleansh-workspace/releases/download/v0.1.8/cleansh-installer.sh](https://github.com/KarmaYama/cleansh-workspace/releases/download/v0.1.8/cleansh-installer.sh) | sh

```

**Via Cargo:**

```bash
cargo install cleansh

```

---

## 3. Cleansh's Command Architecture

`CleanSH` uses a subcommand-based architecture.

| Command | Description | Use Case |
| --- | --- | --- |
| **`cleansh sanitize`** | The primary command for redacting sensitive data. | Daily use, sanitizing logs or terminal output. |
| **`cleansh scan`** | Scans for sensitive data and provides a report without redacting. | Security auditing, pre-scan assessments. |
| **`cleansh profiles`** | Manages redaction profiles and rule sets. | Creating, signing, and verifying custom rules. |
| **`cleansh uninstall`** | Safely removes the `cleansh` CLI and its associated files. | System maintenance. |
| **`cleansh sync`** | (Enterprise) Synchronizes redaction profiles with a central server. | **Coming Soon:** Enterprise-grade policy management. |
| **`cleansh verify`** | (Enterprise) Cryptographically verifies artifacts. | **Coming Soon:** Auditable compliance workflows. |

---

## 4. Core Capabilities (Open Source)

All core commands are free and open source under the **MIT OR Apache-2.0** license.

### 4.1. `cleansh sanitize` – Redacting Sensitive Output

This command handles the core redaction logic. It reads from standard input (`stdin`) or a file and writes the sanitized content to standard output (`stdout`) by default.

**Basic Usage: Piping Content**

```bash
"User login attempt from test@example.com at 192.168.1.1." | cleansh sanitize

```

**Output:**

```
User login attempt from [EMAIL_REDACTED] at [IPV4_REDACTED].

```

**Using the Entropy Engine:**
To catch unstructured secrets (like random API keys) that don't match regex patterns, use the entropy engine:

```bash
cat unknown_logs.txt | cleansh sanitize --engine entropy

```

**Sanitizing File Content:**

```bash
cleansh sanitize ./application.log -o sanitized_application.log

```

### 4.2. `cleansh scan` – Auditing for Secrets

The `scan` command audits your files for secrets without modifying them.

**Scenario:** Audit a log file before sharing.

```bash
cleansh scan my_logfile.txt

```

**Output (example):**

```
Redaction Statistics Summary:
  EmailAddress: 1 match
  IPv4Address: 1 match

```

### 4.3. `cleansh scan` – CI/CD Enforcement

Use `scan` in your build pipeline to fail if secrets are found.

**Scenario:** Fail the build if more than 0 secrets are detected.

```bash
docker logs my-app | cleansh scan --fail-over-threshold 0

```

### 4.4. `cleansh profiles` – Managing Redaction Rules

* **`cleansh profiles list`:** Lists all available local redaction profiles.
* **`cleansh profiles sign`:** Signs a profile YAML file (useful for verifying integrity).

---

## 5. Global Flags

These flags work across most commands:

* **Copy to Clipboard (`-c` / `--clipboard`):** Instantly copy output.
* **Diff View (`-d` / `--diff`):** Show a colored diff of changes.
* **Custom Config (`--config <path>`):** Load custom rules.
* **Output File (`-o <path>`):** Write output to a file.
* **Suppress Summary (`--no-redaction-summary`):** Hide the summary footer.
* **Enable/Disable (`--enable`, `--disable`):** Toggle specific rules.
* **Engine (`--engine`):** Choose between `regex` (default) or `entropy`.
* **Quiet (`--quiet`):** Suppress informational logs.

---

## 6. Configuration Strategy

### Custom Rules

Create `my_rules.yaml`:

```yaml
rules:
  - name: "emp_id"
    pattern: 'EMP-\d{5}'
    replace_with: '[EMPLOYEE_ID]'

```

Run:

```bash
cat data.txt | cleansh sanitize --config ./my_rules.yaml

```

---

**Precision redaction. Local-only trust. Built for devs.**

*Copyright 2025 Relay.*

```

```