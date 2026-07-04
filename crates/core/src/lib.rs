//! Core business logic for DNS filtering

use dashmap::DashSet;
use std::sync::Arc;

/// A trait for implementing different rule matching strategies
pub trait Matcher: Send + Sync {
    /// Check if a domain should be blocked
    fn is_blocked(&self, domain: &str) -> bool;

    /// Get the matcher name for logging/debugging
    fn name(&self) -> &'static str;
}

/// Exact domain matcher - O(1) lookup
#[derive(Clone)]
pub struct ExactMatcher {
    blocked: Arc<DashSet<String>>,
}

impl ExactMatcher {
    /// Create a new exact matcher
    pub fn new(domains: impl IntoIterator<Item = String>) -> Self {
        let blocked = Arc::new(DashSet::new());
        for domain in domains {
            blocked.insert(domain.to_lowercase());
        }
        Self { blocked }
    }

    /// Add a domain to block
    pub fn add(&self, domain: String) {
        self.blocked.insert(domain.to_lowercase());
    }

    /// Get the number of blocked domains
    pub fn count(&self) -> usize {
        self.blocked.len()
    }
}

impl Matcher for ExactMatcher {
    fn is_blocked(&self, domain: &str) -> bool {
        self.blocked.contains(&domain.to_lowercase())
    }

    fn name(&self) -> &'static str {
        "ExactMatcher"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_matcher() {
        let matcher = ExactMatcher::new(vec!["ads.example.com".to_string()]);
        assert!(matcher.is_blocked("ads.example.com"));
        assert!(!matcher.is_blocked("foo.ads.example.com"));
        assert!(!matcher.is_blocked("example.com"));
    }

    #[test]
    fn test_exact_matcher_case_insensitive() {
        let matcher = ExactMatcher::new(vec!["ADS.EXAMPLE.COM".to_string()]);
        assert!(matcher.is_blocked("ads.example.com"));
        assert!(matcher.is_blocked("ADS.EXAMPLE.COM"));
    }
}
