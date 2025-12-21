# CleanSH – The Terminal Security HUD

**[Contributing Guidelines](https://www.google.com/search?q=CONTRIBUTING.md)** | **[Code of Conduct](https://www.google.com/search?q=CODE_OF_CONDUCT.md)** | **[Changelog](CHANGELOG.md)** | **[Security Policy](SECURITY.md)** | **[Command Handbook](https://www.google.com/search?q=COMMANDS.md)**

> **CleanSH** (clean shell) is a **Terminal Heads-Up Display (HUD)** that secures your command output in real-time.
> Instead of just filtering text, it takes over your terminal window to provide a live cockpit: visualizing entropy, detecting secrets, and letting you approve or block sensitive data on the fly.
> **v0.2.0 Update:** Now features a full TUI dashboard, "Heat-Seeker" surgical extraction, and zero-latency streaming.

*(Replace this with a real screenshot of your new TUI!)*

---

## Table of Contents

| Section |
| --- |
| [1. Overview](https://www.google.com/search?q=%231-overview) |
| [2. The TUI Workflow](https://www.google.com/search?q=%232-the-tui-workflow) |
| [3. Core Capabilities](https://www.google.com/search?q=%233-core-capabilities) |
| [4. The Heat-Seeker Engine](https://www.google.com/search?q=%234-the-heat-seeker-engine) |
| [5. Installation](https://www.google.com/search?q=%235-installation) |
| [6. Usage Examples](https://www.google.com/search?q=%236-usage-examples) |
| [7. Configuration](https://www.google.com/search?q=%237-configuration) |
| [8. License](https://www.google.com/search?q=%238-license) |

---

## 1. Overview

Most security tools scan code *before* you commit it. **CleanSH protects you while you work.**

It sits in the pipe (`|`) between your command and your screen. Whether you are tailing production logs, running a Python script, or checking Docker containers, CleanSH intercepts the stream, identifies sensitive data (PII, API Keys, Secrets), and surgically redacts it before it hits your monitor.

**Sanitize your terminal output. One tool. One purpose.**

---

## 2. The TUI Workflow

In **v0.2.0**, CleanSH is no longer a passive filter. It is an interactive workspace.

### The Dashboard Panels

1. **📡 Live Stream:** The main view showing your logs (sanitized in real-time).
2. **🔥 Entropy Matrix:** A visual heatmap showing the statistical "danger level" of every character.
3. **🛡️ Remediation Log:** A history of every secret caught, allowing for audit and review.

### Interactive Controls

You control the security engine with your keyboard while the logs flow:

| Key | Action | Description |
| --- | --- | --- |
| **`[E]`** | **Switch Engine** | Swap between Regex, Entropy, or Hybrid engines instantly. |
| **`[H]`** | **Heatmap** | Toggle the visual entropy view to see *why* something was flagged. |
| **`[D]`** | **Diff View** | See a side-by-side comparison (Original vs. Redacted). |
| **`[A]`** | **Approve** | Whitelist a false positive for the current session. |
| **`[I]`** | **Ignore** | Dismiss a dashboard alert. |

---

## 3. Core Capabilities

Based on our rigorously passing test suite, `CleanSH` accurately masks:

* **Secrets:** GitHub PATs, AWS/GCP/Azure Keys, Stripe Keys, Slack Tokens.
* **PII:** Email addresses, IPv4/IPv6, Credit Cards, SSN/NINO.
* **System Info:** Absolute paths (normalized to `~/`), MAC addresses.

### Engines

* **Regex Engine:** Fast, deterministic blocking of known patterns (e.g., Email, IP).
* **Entropy Engine:** Statistical analysis to find *unknown* high-randomness secrets.

---

## 4. The Heat-Seeker Engine

**v0.2.0 Evolution:** The new **Surgical Entropy Engine** moves beyond simple window masking.

Standard entropy scanners are "blunt instruments"—they often redact the English words surrounding a secret. CleanSH uses a **Statistical Decay Walk** to fix this:

1. **Detection:** Identifies a high-entropy anomaly (Z-Score > Threshold).
2. **Semantic Anchoring:** Locks onto delimiters like `key=` or `"` to protect labels.
3. **Surgical Extraction:** "Walks" backwards from the peak heat to find the exact start/end of the randomness, preserving suffixes like `_padding` or `.json`.

**The Result:** `key=Af9!xK3#mP5_suffix` becomes `key=[ENTROPY_REDACTED]_suffix`.

---

## 5. Installation

### From crates.io (Recommended)

```powershell
cargo install cleansh

```

### From Source

```bash
git clone https://github.com/KarmaYama/cleansh-workspace.git
cd cleansh
cargo build --release

```

---

## 6. Usage Examples

**The "Pipe" Pattern:**
Just add `| cleansh` to the end of any command.

**Live Log Monitoring:**

```bash
tail -f /var/log/syslog | cleansh

```

**Docker Containers:**

```bash
docker logs -f my-app | cleansh

```

**Python Scripts:**

```bash
python server.py | cleansh

```

> **🪟 Windows Users Note:**
> PowerShell's pipe operator buffers output, causing delays. For instant streaming, use **Command Prompt (`cmd`)** or wrap the command:
> `cmd /c "python app.py | cleansh"`

---

## 7. Configuration

CleanSH works out-of-the-box, but you can tune it via `config.yaml`.

**Location:**

* **Linux/Mac:** `~/.config/cleansh/config.yaml`
* **Windows:** `%APPDATA%\cleansh\config.yaml`

**Example:**

```yaml
engines:
  entropy:
    threshold: 0.6  # Sensitivity (0.1 = Paranoid, 1.0 = Relaxed)

rules:
  - name: "internal_project_id"
    pattern: 'PROJ-[0-9]{5}'
    replace_with: '[PROJECT_ID]'

```

Load a custom config at runtime:

```bash
python app.py | cleansh --profile strict

```

---

## 8. License

**CleanSH is Open Source.**

* **Core Code:** Licensed under **MIT OR Apache-2.0**.
* **Restrictions:** The restrictive "PolyForm" license has been retired. You are free to use this tool commercially.

---

**Precision redaction. Local‑only trust. Built for devs.**

*Copyright 2025 Relay.*