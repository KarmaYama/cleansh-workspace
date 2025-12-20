// cleansh-entropy/src/entropy/mod.rs
use libm::log2;

/// Calculates the Shannon entropy of a byte slice.
/// 
/// Returns the entropy in bits per symbol.
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0usize; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in frequencies.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * log2(p);
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(calculate_shannon_entropy(b""), 0.0);
    }

    #[test]
    fn test_entropy_zero_randomness() {
        assert_eq!(calculate_shannon_entropy(b"aaaaa"), 0.0);
    }

    #[test]
    fn test_entropy_high_randomness() {
        let entropy = calculate_shannon_entropy(b"abcdefgh");
        assert!((entropy - 3.0).abs() < 1e-10);
    }
}