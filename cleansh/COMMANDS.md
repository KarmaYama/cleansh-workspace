# CleanSH Command Handbook: v0.2.0 Edition

Welcome to the **CleanSH v0.2.0 Handbook**. This release transforms CleanSH from a passive text filter into an interactive **Terminal Heads-Up Display (HUD)**.

It serves as a real-time security dashboard for your terminal, allowing you to visualize entropy, approve false positives, and surgically redact secrets from live streams without breaking your flow.

---

## 1. What is CleanSH?

`CleanSH` is a **local-first Terminal HUD** designed to redact sensitive data from live text streams. It sits between your command output and your screen, acting as a "smart glass" layer that filters PII, API keys, and unstructured secrets in real-time.

### The v0.2.0 Milestone: The TUI Architecture

Unlike v0.1, which just printed cleaned text, v0.2.0 takes over your terminal window to provide a **Cockpit View**:

1. **Live Stream:** The sanitized logs.
2. **Entropy Matrix:** A visual heatmap of randomness.
3. **Remediation Dashboard:** A log of what was blocked and why.

---

## 2. Getting Started

### Installation

**Via Cargo:**

```powershell
cargo install cleansh

```

### The "Pipe" Workflow

CleanSH works by piping the output of **any** command into it.

**Basic Usage:**

```powershell
# Watch a log file
tail -f server.log | cleansh

# Monitor a script
python server.py | cleansh

# Check a Docker container
docker logs -f my-app | cleansh

```

> **🪟 Windows Users:**
> If you are using **PowerShell**, you may notice a delay because PowerShell buffers data.
> * **Fix:** Use `cmd /c` for instant streaming:
> `cmd /c "python server.py | cleansh"`
> * **Or:** Use the standard Command Prompt (`cmd.exe`).
> 
> 

---

## 3. The TUI Cockpit (Interactive Controls)

Once CleanSH is running, your keyboard controls the security engine. You do not need to restart the stream to change settings.

| Key | Action | Description |
| --- | --- | --- |
| **`[E]`** | **Engine Switcher** | Open the menu to swap between **Regex**, **Entropy**, or **Hybrid** engines on the fly. |
| **`[H]`** | **Heatmap View** | Toggles the **Entropy Matrix**. Visualizes the statistical "heat" of every character (Red = Danger, Dim = Safe). |
| **`[D]`** | **Diff View** | Toggles a side-by-side comparison of the **Original** vs. **Redacted** text. |
| **`[A]`** | **Approve** | Whitelists the currently selected match (stops redacting it for this session). |
| **`[I]`** | **Ignore** | Dismisses the alert from the dashboard without approving the secret. |
| **`[Q]`** | **Quit** | Exits the dashboard. |

---

## 4. Core Engines

You can select the engine at startup or switch dynamically using `[E]`.

### 4.1. The Regex Engine (Pattern Matching)

* **Best for:** Structured secrets (Credit Cards, Emails, IPv4, `AWS_ACCESS_KEY`).
* **Mechanism:** Uses pre-defined regex rules from your config.
* **Startup Command:** `cleansh --engine regex`

### 4.2. The Entropy Engine (Surgical Heat-Seeker)

* **Best for:** Unstructured/Random secrets (Custom API keys, proprietary tokens, passwords).
* **Mechanism:** Uses **Shannon Entropy + Contextual Z-Scores**.
* **Surgical Extraction:** v0.2.0 introduces a **Statistical Decay Walk**. It finds the "hottest" part of a string and "shrink-wraps" the redaction around it, preserving delimiters like `key=` or `"`.
* **Startup Command:** `cleansh --engine entropy` (Default)

---

## 5. Global Flags

Since v0.2.0 is interactive, many old flags (like `--clipboard`) have been removed in favor of TUI controls.

| Flag | Shortcut | Description |
| --- | --- | --- |
| **`--engine`** | `-e` | Select the startup engine (`regex`, `entropy`, `hybrid`). |
| **`--profile`** | `-p` | Load a specific rule profile (e.g., `--profile strict`). |
| **`--quiet`** | `-q` | Suppress internal debug logging (useful for CI). |

---

## 6. Configuration Strategy

CleanSH v0.2.0 still respects your YAML configuration for defining custom rules.

**File Location:**

* **Linux/Mac:** `~/.config/cleansh/config.yaml`
* **Windows:** `%APPDATA%\cleansh\config.yaml`

**Example `config.yaml`:**

```yaml
engines:
  entropy:
    threshold: 0.6  # Adjust sensitivity (0.1 = Paranoid, 1.0 = Relaxed)

rules:
  - name: "company_internal_token"
    pattern: 'RELAY-[A-Z0-9]{16}'
    replace_with: '[INTERNAL_TOKEN]'

```

---

**CleanSH v0.2.0**
*Surgical Precision. Terminal Transparency.*
*Copyright 2025 Relay.*