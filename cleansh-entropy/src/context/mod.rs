// cleansh-entropy/src/context/mod.rs
use daachorse::DoubleArrayAhoCorasick;
extern crate alloc;
use alloc::vec;
use core::fmt;

/// Scans for keywords surrounding a potential secret with word-boundary awareness.
pub struct ContextScanner {
    automaton: DoubleArrayAhoCorasick<usize>,
}

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

    /// Scans the preceding context for keywords.
    /// Employs word-boundary checks to ensure "key" doesn't match "monkey".
    pub fn scan_preceding_context(&self, text: &[u8], token_start: usize, window_size: usize) -> bool {
        if token_start == 0 { return false; }
        
        let start = token_start.saturating_sub(window_size);
        let window = &text[start..token_start];
        
        for matched in self.automaton.find_iter(window) {
            let m_start = matched.start();
            let m_end = matched.end();

            // Word boundary check: ensure keyword is not surrounded by alphanumeric chars
            let prefix_ok = m_start == 0 || !window[m_start - 1].is_ascii_alphanumeric();
            let suffix_ok = m_end == window.len() || !window[m_end].is_ascii_alphanumeric();

            if prefix_ok && suffix_ok {
                return true;
            }
        }
        false
    }
}