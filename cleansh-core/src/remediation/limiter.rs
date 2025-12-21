// cleansh-core/src/remediation/limiter.rs
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Instant, Duration};

/// A thread-safe Token Bucket rate limiter to prevent remediation "storms".
#[derive(Debug)]
pub struct RemediationLimiter {
    max_tokens: f64,
    tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl RemediationLimiter {
    /// Creates a new limiter. 
    /// e.g., max_tokens: 5.0, refill_rate: 0.016 (1 token per minute)
    pub fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            max_tokens,
            tokens: max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Attempts to consume a token. Returns true if permitted.
    pub fn try_consume(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }
}

pub type SharedLimiter = Arc<Mutex<RemediationLimiter>>;