// cleansh-entropy/src/statistics/mod.rs
use libm::sqrt;

/// Statistics for a set of entropy values.
#[derive(Debug, Clone, Copy)]
pub struct EntropyStats {
    pub mean: f64,
    pub std_dev: f64,
}

/// Calculates mean and standard deviation for a slice of values.
pub fn compute_stats(values: &[f64]) -> EntropyStats {
    if values.is_empty() {
        return EntropyStats { mean: 0.0, std_dev: 0.0 };
    }

    let len = values.len() as f64;
    let mean = values.iter().sum::<f64>() / len;

    let variance = values.iter()
        .map(|value| {
            let diff = mean - value;
            diff * diff
        })
        .sum::<f64>() / len;

    EntropyStats {
        mean,
        std_dev: sqrt(variance),
    }
}