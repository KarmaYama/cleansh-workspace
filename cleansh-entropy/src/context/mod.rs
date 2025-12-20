// cleansh-entropy/src/context/mod.rs
use daachorse::DoubleArrayAhoCorasick;
use alloc::vec;
use core::fmt;

/// Scans for keywords surrounding a potential secret.
pub struct ContextScanner {
    automaton: DoubleArrayAhoCorasick<usize>,
}

// Manual implementation of Debug because DoubleArrayAhoCorasick doesn't support it.
impl fmt::Debug for ContextScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContextScanner")
         .field("automaton", &"<DoubleArrayAhoCorasick>")
         .finish()
    }
}

impl ContextScanner {
    /// Creates a new scanner with a default list of suspicious keywords.
    pub fn new() -> Self {
        let patterns = vec![
            "key", "api", "token", "secret", "password", "passwd", "pwd", 
            "auth", "bearer", "access", "id", "credential", "private", 
            "client", "aws", "gcp", "azure", "stripe", "ghp"
        ];
        
        let automaton = DoubleArrayAhoCorasick::new(patterns)
            .expect("Failed to build Aho-Corasick automaton for context scanning");
            
        Self { automaton }
    }

    pub fn scan_preceding_context(&self, text: &[u8], token_start: usize, window_size: usize) -> bool {
        if token_start == 0 { return false; }
        
        let start = token_start.saturating_sub(window_size);
        let window = &text[start..token_start];
        
        self.automaton.find_iter(window).next().is_some()
    }
}