# CleanSH Workspace – A Monorepo for Secure Terminal Output Sanitization

[![CodeQL](https://github.com/KarmaYama/cleansh/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/github-code-scanning/codeql) [![CodeQL Advanced](https://github.com/KarmaYama/cleansh/actions/workflows/codeql.yml/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/codeql.yml) [![Dependabot Updates](https://github.com/KarmaYama/cleansh/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/dependabot/dependabot-updates) [![Release](https://github.com/KarmaYama/cleansh/actions/workflows/release.yml/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/release.yml) [![Rust CI](https://github.com/KarmaYama/cleansh/actions/workflows/rust.yml/badge.svg)](https://github.com/KarmaYama/cleansh/actions/workflows/rust.yml) [![Star](https://img.shields.io/github/stars/KarmaYama/cleansh.svg?style=social)](https://github.com/KarmaYama/cleansh/stargazers)

**Stop relying on leaky regex. CleanSH (Clean Shell) is a high-trust, modular Rust utility designed to securely and programmatically sanitize sensitive data from your terminal output, logs, and text.**

---

## Overview

This repository (`cleansh-workspace`) is a **Rust monorepo** designed for the secure sanitization of terminal output. It houses a growing ecosystem of tools and libraries under a unified development environment, promoting modularity, reusability, and maintainability.

---

### Key Components

1.  **`CleanSH` (CLI Application):**
    * **Location:** [`/cleansh`](./cleansh/README.md)
    * **Purpose:** The main user-facing command-line utility. It orchestrates the scanning engines, manages configuration profiles, and handles I/O streams for real-time redaction.

2.  **`CleanSH-core` (Core Library):**
    * **Location:** [`/cleansh-core`](./cleansh-core/README.md)
    * **Purpose:** A standalone, reusable Rust library that encapsulates the business logic for data redaction, rule compilation, and validation. It defines the `SanitizationEngine` trait that powers the CLI.

3.  **`CleanSH-entropy` (Math Engine):**
    * **Location:** [`/cleansh-entropy`](./cleansh-entropy/README.md)
    * **Purpose:** A `no_std`, zero-copy mathematical engine. It implements Shannon entropy calculation, Z-score statistical anomaly detection, and Aho-Corasick context scanning to detect unstructured secrets (like random API keys) that regex misses.

---

### License (Open Source)

As of version **v0.1.9**, the `cleansh` workspace has transitioned to a fully Open Source model.

* **License:** All components (`cleansh`, `core`, and `entropy`) are dual-licensed under **MIT** or **Apache-2.0**.
* **Commercial Use:** You are free to use, modify, and distribute these tools for any purpose, including commercial applications, without restriction.

*The previous "PolyForm Noncommercial" license has been retired.*

---

### Getting Started

To explore or contribute to the `CleanSH` project:

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/KarmaYama/cleansh-workspace.git](https://github.com/KarmaYama/cleansh-workspace.git)
    cd cleansh-workspace
    ```

2.  **Build the Workspace:**
    The project is a Rust workspace, so you can build all components from the root:
    ```bash
    cargo build --release
    ```

3.  **Run Tests:**
    Ensure everything is functioning correctly by running the full test suite across all crates:
    ```bash
    cargo test --workspace
    ```

---

### **Community and Support**

**We're building `CleanSH` together with our users and contributors!** If you have questions, feedback, or want to discuss a new feature, don't hesitate to reach out.

* **Ask a Question or Share an Idea:** Our **[GitHub Discussions](https://github.com/KarmaYama/cleansh-workspace/discussions)** page is the best place to connect with us directly.
* **Report a Bug:** Please open an issue on the **[Issues page](https://github.com/KarmaYama/cleansh-workspace/issues)**. We appreciate detailed bug reports!

---

**CleanSH Workspace: Modular design for secure and adaptable terminal output sanitization.**