# CleanSH Workspace – A Monorepo for Secure Terminal Output Sanitization

**Stop relying on leaky regex. CleanSH (Clean Shell) is a high-trust, modular Rust utility designed to securely and programmatically sanitize sensitive data from your terminal output, logs, and text.**

---

## Overview

This repository (`cleansh-workspace`) is a **Rust monorepo** designed for the secure sanitization of terminal output. It houses a growing ecosystem of tools and libraries under a unified development environment, promoting modularity, reusability, and maintainability.

---

### Key Components

1. **`CleanSH` (CLI Application):**
* **Location:** [`/cleansh`](https://www.google.com/search?q=./cleansh/README.md)
* 
**Purpose:** The main user-facing command-line utility. It orchestrates scanning engines, manages configuration profiles, and handles I/O streams for real-time redaction.




2. **`CleanSH-core` (Core Library):**
* **Location:** [`/cleansh-core`](https://www.google.com/search?q=./cleansh-core/README.md)
* 
**Purpose:** A standalone library encapsulating business logic for redaction, rule compilation, and validation. It defines the `SanitizationEngine` trait that powers the multi-engine pipeline.




3. **`CleanSH-entropy` (Math Engine):**
* **Location:** [`/cleansh-entropy`](https://www.google.com/search?q=./cleansh-entropy/README.md)
* 
**Purpose:** A `no_std`, zero-copy engine focused on detecting high-randomness secrets that regex misses.





---

## Technical Principles: Beyond Fixed Thresholds

CleanSH solves the "signal-to-noise ratio crisis" common in traditional secret scanners. Most tools use fixed entropy thresholds that trigger on non-sensitive data like long UUIDs or hashes, leading to alert fatigue.

### 1. Dynamic Z-Score Thresholding

Instead of a static value, CleanSH calculates a **local entropy baseline** for your specific context. A token is only flagged if its Shannon entropy is a statistically significant number of **standard deviations** above the baseline mean.

* 
**Result:** We ignore high-entropy non-secrets (like UUIDs in a log full of UUIDs) while catching true secrets in low-randomness contexts.



### 2. Semantic Sliding Window

Traditional tokenizers are fragile; they often "shred" secrets containing symbols like `#`, `!`, or `@`. CleanSH uses a **Sliding Window** scanner that glides byte-by-byte across text streams to locate randomness regardless of delimiters.

### 3. Heuristic Extraction (Heat-Seeker)

Locating "heat" is only half the battle. CleanSH employs a surgical extraction pass that anchors to common semantic delimiters (like `:` or `=`) to "shrink-wrap" the redaction around the actual payload.

* **Before:** `auth_key=[ENTROPY_REDACTED]ing`
* **After:** `auth_key=[ENTROPY_REDACTED]_extra_padding`

---

### License (Open Source)

As of version **v0.1.9**, the `cleansh` workspace has transitioned to a fully Open Source model.

* **License:** All components (`cleansh`, `core`, and `entropy`) are dual-licensed under **MIT** or **Apache-2.0**.
* **Commercial Use:** You are free to use, modify, and distribute these tools for any purpose, including commercial applications, without restriction.

*The previous "PolyForm Noncommercial" license has been retired.*

---

### Getting Started

1. **Clone the Repository:**
```bash
git clone https://github.com/KarmaYama/cleansh-workspace.git
cd cleansh-workspace

```


2. **Build the Workspace:**
```bash
cargo build --release

```


3. **Run Tests:**
```bash
cargo test --workspace

```



---

### **Community and Support**

* **Ask a Question or Share an Idea:** Our **[GitHub Discussions](https://github.com/KarmaYama/cleansh-workspace/discussions)** page is the best place to connect.
* **Report a Bug:** Please open an issue on the **[Issues page](https://github.com/KarmaYama/cleansh-workspace/issues)**.

---

**CleanSH Workspace: Precision redaction through statistical anomaly detection.**

Would you like me to also update the individual README files in `/cleansh-core` or `/cleansh-entropy` to include their specific API documentation?