# `cleansh-entropy`

[![Crates.io](https://img.shields.io/crates/v/cleansh-entropy.svg)](https://crates.io/crates/cleansh-entropy)
[![Documentation](https://docs.rs/cleansh-entropy/badge.svg)](https://docs.rs/cleansh-entropy)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

**A no_std, zero-copy entropy detection engine for high-performance secret scanning.**

This crate provides the mathematical core for the `CleanSH` CLI's entropy detection capabilities. It uses Shannon entropy calculation combined with contextual keyword analysis (via Aho-Corasick) to identify high-randomness strings that likely represent unstructured secrets (e.g., custom API keys, internal auth tokens) which regular expressions often miss.

## Features

* **Shannon Entropy Calculation:** Efficiently computes the entropy of byte slices in bits per symbol.
* **Contextual Analysis:** Uses the `daachorse` crate for high-performance, double-array Aho-Corasick pattern matching to detect suspicious context keywords (e.g., `key=`, `secret:`) near high-entropy tokens.
* **Statistical Anomaly Detection:** Calculates Z-scores to determine if a token's entropy is a statistically significant outlier compared to the surrounding text.
* **`no_std` Support:** Designed to be embedded in environments without the standard library (requires `alloc`).
* **Zero-Copy:** Optimized to work on byte slices without unnecessary allocations during the scanning phase.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
cleansh-entropy = "0.1.0"

```

### Basic Example

```rust
use cleansh_entropy::entropy::calculate_shannon_entropy;

fn main() {
    let low_entropy = b"aaaaaaaa";
    let high_entropy = b"7f8a9b2c"; // Random hex string

    let e1 = calculate_shannon_entropy(low_entropy);
    let e2 = calculate_shannon_entropy(high_entropy);

    println!("Entropy of 'aaaaaaaa': {:.4}", e1); // ~0.0
    println!("Entropy of '7f8a9b2c': {:.4}", e2); // ~2.5+
}

```

### Full Engine Usage

For identifying secrets in a larger text stream:

```rust
use cleansh_entropy::engine::EntropyEngine;

fn main() {
    let text = b"My secret api key is 8x9#bF2!kL and it should be hidden.";
    
    // Initialize engine with a confidence threshold (e.g., 4.0)
    let engine = EntropyEngine::new(4.0);
    
    let matches = engine.scan(text);
    
    for m in matches {
        println!("Found potential secret at {:?} with confidence {:.2}", 
            m.start..m.end, m.confidence);
    }
}

```

## Architecture

1. **Scanner:** Iterates over the input text to tokenize words.
2. **Entropy Calc:** Computes Shannon entropy for candidate tokens.
3. **Context Check:** Scans the preceding bytes for "trigger words" using a fast state machine.
4. **Scoring:** Combines the entropy Z-score and context presence into a final confidence score.

## License

This project is licensed under the **MIT License** or **Apache License 2.0**, at your option.

See [LICENSE-MIT](https://www.google.com/search?q=LICENSE-MIT) and [LICENSE-APACHE](https://www.google.com/search?q=LICENSE-APACHE) for details.


