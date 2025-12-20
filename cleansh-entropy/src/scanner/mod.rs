// cleansh-entropy/src/scanner/mod.rs
use crate::entropy::calculate_shannon_entropy;
use crate::statistics::{compute_stats, EntropyStats};

/// Configuration for the dynamic entropy scanner.
#[derive(Debug, Clone)]
pub struct AnomalyScannerConfig {
    pub z_score_threshold: f64,
    pub window_chunk_size: usize, 
}

impl Default for AnomalyScannerConfig {
    fn default() -> Self {
        Self {
            z_score_threshold: 3.0,
            window_chunk_size: 0,
        }
    }
}

/// Result of an anomaly check.
#[derive(Debug, Clone)]
pub struct AnomalyResult {
    pub is_anomaly: bool,
    pub token_entropy: f64,
    pub baseline_stats: EntropyStats,
    pub z_score: f64,
}

/// Checks if a token is a statistical anomaly compared to its context.
pub fn scan_token_against_context(
    token: &[u8],
    context: &[u8],
    config: &AnomalyScannerConfig,
) -> AnomalyResult {
    let token_entropy = calculate_shannon_entropy(token);
    let token_len = token.len();
    
    if token_len == 0 || context.len() < token_len {
        return AnomalyResult {
            is_anomaly: false,
            token_entropy,
            baseline_stats: EntropyStats { mean: 0.0, std_dev: 0.0 },
            z_score: 0.0,
        };
    }

    let mut context_entropies = [0.0; 128]; 
    let mut sample_count = 0;

    let step = if config.window_chunk_size > 0 { config.window_chunk_size } else { token_len };
    let mut chunks = context.chunks(step);
    
    while let Some(chunk) = chunks.next() {
        if sample_count >= 128 { break; }
        if chunk.len() >= token_len / 2 {
             context_entropies[sample_count] = calculate_shannon_entropy(chunk);
             sample_count += 1;
        }
    }

    let stats = compute_stats(&context_entropies[0..sample_count]);

    let z_score = if stats.std_dev > 0.0 {
        (token_entropy - stats.mean) / stats.std_dev
    } else {
        if token_entropy > stats.mean { 100.0 } else { 0.0 }
    };

    AnomalyResult {
        is_anomaly: z_score > config.z_score_threshold,
        token_entropy,
        baseline_stats: stats,
        z_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_detection_natural_language() {
        let context = b"The quick brown fox jumps over the lazy dog. This is normal text with low randomness.";
        let token = b"8x9#bF2!kL"; 

        let config = AnomalyScannerConfig {
            z_score_threshold: 2.0,
            window_chunk_size: 10,
        };

        let result = scan_token_against_context(token, context, &config);
        assert!(result.is_anomaly);
    }

    #[test]
    fn test_anomaly_rejection_high_entropy_context() {
        let context = b"a4f5b2c1 d9e8f7a6 1b2c3d4e 5f6a7b8c 9d0e1f2a 3b4c5d6e";
        let token = b"7a8b9c0d"; 

        let config = AnomalyScannerConfig {
            z_score_threshold: 2.0,
            window_chunk_size: 8,
        };

        let result = scan_token_against_context(token, context, &config);
        assert!(!result.is_anomaly);
    }
}