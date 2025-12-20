# Security Policy for CleanSH

We take the security of `CleanSH` very seriously. We are committed to protecting our users and ensuring the integrity of the tool. This policy outlines our approach to security, including supported versions and how to report vulnerabilities.

---

## Supported Versions

`CleanSH` is currently in active development, and we aim to provide security updates for the **latest stable release**. As a command-line utility, `CleanSH` does not have "versions" in the traditional sense of long-term support branches. Instead, we follow a rapid release cycle, with each new version enhancing the previous one.

**Therefore, we recommend all users update to the latest available version to ensure they receive all security patches and bug fixes.** You can find the latest version on [crates.io](https://crates.io/crates/cleansh).

At this stage of development (pre-v1.0), only the **most recent published version** is actively supported with security fixes.

| Version | Supported |
| :------ | :--- |
| **0.1.x (latest)** | ✅ |
| 0.1.x (older) | ❌ |
| < 0.1.x | ❌ |

*Note: The table above reflects the current `v0.1.x` series. As `CleanSH` matures and reaches `v1.0` and beyond, this policy will be updated to reflect a more structured long-term support model if applicable.*

---

## Reporting a Vulnerability

We deeply appreciate the efforts of security researchers and the open-source community. If you discover a security vulnerability in `CleanSH`, we ask that you report it responsibly to give us an opportunity to address it before public disclosure.

### How to Report a Vulnerability:

1.  **Direct Email:** Please report vulnerabilities by sending an email to `security@relay.africa`.
2.  **Encryption (Optional but Recommended):** For sensitive disclosures, we strongly recommend encrypting your report. Our PGP public key is available on common key servers (e.g., `keys.openpgp.org`, `pgp.mit.edu`) by searching for `security@relay.africa`.
3.  **Provide Details:** In your report, please include as much detail as possible:
    * A clear and concise description of the vulnerability.
    * Steps to reproduce the vulnerability.
    * The version of `CleanSH` affected (e.g., `v0.1.8`).
    * The operating system and Rust toolchain version you used.
    * Any potential impact or exploit scenario.

**Please do not open public GitHub issues for security vulnerabilities.**

---

## 🔐 Key Security Concerns

We recognize that `CleanSH` operates in environments where sensitive information is present, and we take potential security risks seriously. Below are the core concerns we’ve evaluated and the measures taken to address them.

### 1. Regular Expression Denial of Service (ReDoS)

**Concern:** Excessively complex regex patterns can lead to exponential backtracking, causing performance degradation or denial of service.

**Our Response:**
* `CleanSH` compiles **trusted patterns at startup**, sourced from user-defined YAML or internal rules. It does **not** accept untrusted patterns at runtime.
* We use the [`regex`](https://docs.rs/regex) crate, which is designed to **avoid catastrophic backtracking** and has received [specific hardening updates](https://github.com/advisories/GHSA-m5pq-gvj9-9vr8).
* Still, users are advised to avoid unsafe constructs like `(a+)+` when writing their own patterns. Future versions may introduce static pattern validation and fail-safe limits for high-load scenarios.

---

### 2. Shell Output Processing and Command History

**Concern:** Processing output from shells (e.g., Bash, Zsh, PowerShell) might inadvertently expose sensitive data or behave unexpectedly.

**Our Response:**
* `CleanSH` only operates on the **captured output**, not live shells. It does not interact with environment variables, user history, or shell internals.
* ANSI escape sequences are stripped safely before processing, reducing risks of visual obfuscation attacks or hidden input.

---

### 3. AI-Assisted Codebase (Full Transparency)

**Concern:** The codebase of `CleanSH` was developed in close collaboration with AI, raising questions about trust, correctness, and originality.

**Our Response:**
* All code was generated **under direct supervision and review** by the project maintainer, who remains responsible for the logic, architecture, and decisions behind every component.
* Every generated segment was **manually validated, tested, and iterated on** to ensure correctness, security, and maintainability.
* `CleanSH` is not a copy-paste artifact — it is an intentionally built CLI tool with test coverage, clear design principles, and continuous refinement.
* We believe that AI is a tool — not a substitute for ownership — and we stand by the quality and originality of the final product.

---

### 4. File System & Clipboard Safety

**Concern:** As a sanitization tool, users may expect `CleanSH` to handle clipboard or file input/output securely.

**Our Response:**
* Clipboard support is **optional and explicit**, requiring user interaction.
* We do **not read or write arbitrary files** unless specified. Future features will adopt the principle of least privilege and warn before performing irreversible actions.

---

### 5. Trust Boundaries

`CleanSH` is a **stateless utility**—it does not:
* Connect to the network or send telemetry.
* Write configuration data silently.
* Persist logs without user opt-in.

This design minimizes risk by keeping the tool **predictable, inspectable, and local-first**.

---

If you identify a concern not addressed here, or believe a threat model has been overlooked, please reach out directly. We value collaboration with the security community.

---

### Our Response Process:

1.  **Acknowledgement:** You can expect an acknowledgment of your report within **2 business days**.
2.  **Assessment:** We will investigate the reported vulnerability promptly. Our team will assess the severity and potential impact.
3.  **Status Updates:** We aim to provide regular updates on the progress of our investigation, typically within **5 business days** of the initial acknowledgment and then as significant progress is made.
4.  **Resolution & Disclosure:**
    * If the vulnerability is confirmed, we will work to develop a fix as quickly as possible.
    * Once a fix is ready, we will coordinate with you on the disclosure timeline. We typically aim for a public disclosure after the fix has been released in a new `CleanSH` version.
    * We believe in responsible disclosure and will credit you for your discovery in our release notes and/or security advisory, unless you prefer to remain anonymous.
    * If the vulnerability is declined (e.g., deemed not a security issue or out of scope), we will provide a clear explanation for our decision.

**Please do not disclose potential vulnerabilities publicly until we have had an opportunity to address them.** We are committed to addressing valid concerns promptly and openly.

---

*Copyright 2025 Relay.*