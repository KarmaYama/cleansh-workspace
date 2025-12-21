# `cleansh-entropy`

**A no_std, zero-copy entropy detection engine for high-performance secret scanning.**

This crate provides the mathematical core for the `CleanSH` CLI's entropy detection capabilities. It uses Shannon entropy calculation combined with contextual keyword analysis to identify high-randomness strings that likely represent unstructured secrets (e.g., custom API keys, internal auth tokens) which regular expressions often miss.

---

## Features

* **Shannon Entropy Calculation:** Efficiently computes the entropy of byte slices in bits per symbol.
* **Contextual Analysis:** High-performance Aho-Corasick pattern matching to detect suspicious context keywords (e.g., `key=`, `secret:`) near high-entropy tokens.
* **Heat-Seeker Extraction (v0.1.4):** A multi-stage pipeline that identifies statistical anomalies and surgically extracts the secret core using an aggressive 3-byte decay walk.
* **Lowercase Run Heuristic:** Distinguishes between random high-entropy bytes and predictable natural language suffixes (e.g., `_padding` or `ing`), effectively eliminating "locator bleed."
* **`no_std` Support:** Designed to be embedded in environments without the standard library (requires `alloc`).
* **Zero-Copy:** Optimized to work on byte slices without unnecessary allocations during the scanning phase.

---

## Technical Architecture: The Heat-Seeker Pipeline

The engine operates in three distinct phases to ensure surgical precision:

1. **Statistical Locator:** A sliding window scans the input to identify regions where Shannon entropy significantly exceeds the local baseline (Z-score analysis).
2. **Semantic Anchoring:** Once "heat" is detected, the engine snaps the match start to the nearest semantic delimiter (e.g., `:`, `=`).
3. **Aggressive Decay Walk:** The engine walks backward from the end of the window character-by-character. It stops redacting as soon as it hits a "cold" zone—defined by lowercase runs, underscores, or low-entropy clusters.

---

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
cleansh-entropy = "0.1.4"

```

### Full Engine Usage

For identifying secrets in a larger text stream:

```rust
use cleansh_entropy::engine::EntropyEngine;

fn main() {
    let text = b"auth_key=8x9#bF2!kL0Z@mN9_extra_padding";
    
    // Initialize engine with a confidence threshold and window size
    let engine = EntropyEngine::new(0.3, 16);
    
    let matches = engine.scan(text);
    
    for m in matches {
        // Output will be surgically isolated to the high-entropy payload
        println!("Found secret at {:?} with confidence {:.2}", 
            m.start..m.end, m.confidence);
    }
}

```

---

## License

This project is licensed under the **MIT License** or **Apache License 2.0**, at your option.

See [LICENSE-MIT](https://www.google.com/search?q=LICENSE-MIT) and [LICENSE-APACHE](https://www.google.com/search?q=LICENSE-APACHE) for details.