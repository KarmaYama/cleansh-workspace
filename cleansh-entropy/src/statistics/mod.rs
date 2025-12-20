use libm::sqrt;

/// Statistics for a set of entropy values used to determine baseline randomness.
#[derive(Debug, Clone, Copy)]
pub struct EntropyStats {
    /// The arithmetic mean of the sampled entropy values.
    pub mean: f64,
    /// The standard deviation, representing the variance in the sampled context.
    pub std_dev: f64,
}

/// Calculates mean and standard deviation for a slice of values.
///
/// This is used to establish a "normal" range of entropy for a given text
/// so that high-entropy outliers (potential secrets) can be identified.
pub fn compute_stats(values: &[f64]) -> EntropyStats {
    if values.is_empty() {
        return EntropyStats { mean: 0.0, std_dev: 0.0 };
    }

    let len = values.len() as f64;
    
    // 1. Calculate the Arithmetic Mean
    let mean = values.iter().sum::<f64>() / len;

    // 2. Calculate Variance
    // Variance is the average of the squared differences from the Mean.
    let variance = values.iter()
        .map(|value| {
            let diff = mean - value;
            diff * diff
        })
        .sum::<f64>() / len;

    // 3. Standard Deviation is the square root of Variance
    EntropyStats {
        mean,
        std_dev: sqrt(variance),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // FIX: Explicitly import vec macro from alloc for no_std tests
    extern crate alloc;
    use alloc::vec;

    // Using a small epsilon for floating point comparisons in tests
    const EPSILON: f64 = 1e-10;

    #[test]
    fn test_compute_stats_empty() {
        let stats = compute_stats(&[]);
        assert_eq!(stats.mean, 0.0);
        assert_eq!(stats.std_dev, 0.0);
    }

    #[test]
    fn test_compute_stats_single_value() {
        let stats = compute_stats(&[5.0]);
        assert_eq!(stats.mean, 5.0);
        assert_eq!(stats.std_dev, 0.0);
    }

    #[test]
    fn test_compute_stats_identical_values() {
        let stats = compute_stats(&[4.0, 4.0, 4.0]);
        assert_eq!(stats.mean, 4.0);
        assert_eq!(stats.std_dev, 0.0);
    }

    #[test]
    fn test_compute_stats_simple_range() {
        // Values: 2, 4, 4, 4, 5, 5, 7, 9
        // Mean: 5.0
        // Variance: (9+1+1+1+0+0+4+16)/8 = 32/8 = 4.0
        // Std Dev: 2.0
        let values = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let stats = compute_stats(&values);
        
        assert!((stats.mean - 5.0).abs() < EPSILON);
        assert!((stats.std_dev - 2.0).abs() < EPSILON);
    }
}