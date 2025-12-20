// cleansh-entropy/src/statistics/mod.rs
use libm::sqrt;

/// Statistics for a set of entropy values used to determine baseline randomness.
#[derive(Debug, Clone, Copy)]
pub struct EntropyStats {
    /// The arithmetic mean of the sampled entropy values.
    pub mean: f64,
    /// The unbiased sample standard deviation.
    pub std_dev: f64,
    /// The number of samples used to calculate this baseline.
    pub sample_count: usize,
}

/// Calculates mean and unbiased sample standard deviation for a slice of values.
pub fn compute_stats(values: &[f64]) -> EntropyStats {
    let n = values.len();
    if n == 0 {
        return EntropyStats { mean: 0.0, std_dev: 0.0, sample_count: 0 };
    }

    let n_f64 = n as f64;
    let mean = values.iter().sum::<f64>() / n_f64;

    if n == 1 {
        return EntropyStats { mean, std_dev: 0.0, sample_count: 1 };
    }

    let sum_sq_diff: f64 = values.iter()
        .map(|&x| {
            let diff = x - mean;
            diff * diff
        })
        .sum();

    // Use Bessel's correction (n - 1) for unbiased sample variance.
    // This is more conservative and accurate for small window sizes.
    let variance = sum_sq_diff / (n_f64 - 1.0);

    // Guard against floating point noise: if variance is essentially zero,
    // clamp SD to zero to avoid precision-induced Z-score spikes.
    let std_dev = if variance < 1e-12 {
        0.0
    } else {
        sqrt(variance)
    };

    EntropyStats {
        mean,
        std_dev,
        sample_count: n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

    #[test]
    fn test_compute_stats_unbiased() {
        // Simple range where population SD is 2.0.
        // Sample SD (N-1) will be ~2.138
        let values = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let stats = compute_stats(&values);
        
        assert!((stats.mean - 5.0).abs() < 1e-10);
        assert!(stats.std_dev > 2.13); // Confirms Bessel correction is active
        assert_eq!(stats.sample_count, 8);
    }
}