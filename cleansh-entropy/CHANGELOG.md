# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.3] - 2025-12-20

### Fixed
* **Outlier Detection Sensitivity:** Adjusted the `Scanner` behavior to better distinguish high-entropy tokens from natural language baselines.
* **Test Reliability:** Updated internal integration tests to use high-entropy tokens that are statistically distinct from common English text, ensuring consistent CI passes.

### Changed
* **Default Thresholds:** Refined the default Z-score calculation to handle low-variance contexts (like repetitive text) more gracefully without triggering false positives.

---

## [0.1.2] - 2025-12-19

### Added
* **High-Level Scanner:** Introduced the `Scanner` struct and `Iterator` implementation for ergonomic whitespace-aware token scanning.
* **Baseline Sampling:** Added a chunking mechanism to established entropy baselines for larger text contexts.

### Fixed
* **Floating Point Accuracy:** Improved standard deviation calculations in the `statistics` module to prevent precision loss on very small datasets.

---

## [0.1.1] - 2025-12-19

### Changed
* **`no_std` Refinement:** Switched from standard math functions to `libm` for improved compatibility across embedded targets.
* **Performance:** Optimized Shannon entropy byte-frequency counting.

---

## [0.1.0] - 2025-12-19

### Added
* **Initial Release:** First public release of the `cleansh-entropy` crate.
* **Shannon Entropy:** Core implementation of `calculate_shannon_entropy` for byte slices.
* **Z-Score Calculation:** Statistical anomaly detection logic to compare token entropy against a local baseline.
* **Context Scanner:** Integration of `daachorse` (Double-Array Aho-Corasick) for `O(n)` scanning of suspicious keywords.