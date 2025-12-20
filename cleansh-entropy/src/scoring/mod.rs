// cleansh-entropy/src/scoring/mod.rs

/// Weights for the confidence calculation.
#[derive(Debug, Clone)] // <--- Added Debug (just to be safe)
pub struct ScoringWeights {
    pub z_score_weight: f64,
    pub keyword_match_weight: f64,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            z_score_weight: 1.0,
            keyword_match_weight: 2.0, 
        }
    }
}

/// Calculates a confidence score (0.0 - 1.0+) for a candidate token.
pub fn calculate_confidence(
    z_score: f64,
    has_keyword_context: bool,
    weights: &ScoringWeights,
) -> f64 {
    let entropy_contribution = (z_score / 5.0).min(1.0) * weights.z_score_weight;
    
    let context_contribution = if has_keyword_context {
        weights.keyword_match_weight
    } else {
        0.0
    };

    entropy_contribution + context_contribution
}