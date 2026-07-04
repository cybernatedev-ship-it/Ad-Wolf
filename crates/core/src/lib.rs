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

/// Suffix domain matcher - efficient multi-level suffix matching
///
/// Matches domains and all subdomains. For example, "ads.example.com" will match:
/// - ads.example.com (exact)
/// - foo.ads.example.com (subdomain)
/// - bar.foo.ads.example.com (deeper subdomain)
///
/// Uses a reversed-label approach for efficient O(k) lookup where k is domain depth.
#[derive(Clone)]
pub struct SuffixMatcher {
    /// Reversed domain labels for efficient suffix matching
    /// "ads.example.com" becomes ["com", "example", "ads"]
    suffixes: Arc<DashSet<Vec<String>>>,
}

impl SuffixMatcher {
    /// Create a new suffix matcher from an iterator of domains
    pub fn new(domains: impl IntoIterator<Item = String>) -> Self {
        let suffixes = Arc::new(DashSet::new());
        for domain in domains {
            let domain_lower = domain.to_lowercase();
            let labels: Vec<String> = domain_lower.split('.').map(|s| s.to_string()).collect();
            if !labels.is_empty() {
                suffixes.insert(labels);
            }
        }
        Self { suffixes }
    }

    /// Add a domain to block
    pub fn add(&self, domain: String) {
        let domain_lower = domain.to_lowercase();
        let labels: Vec<String> = domain_lower.split('.').map(|s| s.to_string()).collect();
        if !labels.is_empty() {
            self.suffixes.insert(labels);
        }
    }

    /// Get the number of suffix rules
    pub fn count(&self) -> usize {
        self.suffixes.len()
    }
}

impl Matcher for SuffixMatcher {
    fn is_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        let query_labels: Vec<&str> = domain_lower.split('.').collect();

        // Check all possible suffixes
        for (idx, _) in query_labels.iter().enumerate() {
            let suffix: Vec<String> = query_labels[idx..].iter().map(|s| s.to_string()).collect();

            if self.suffixes.contains(&suffix) {
                return true;
            }
        }

        false
    }

    fn name(&self) -> &'static str {
        "SuffixMatcher"
    }
}

#[cfg(test)]
mod suffix_tests {
    use super::*;

    #[test]
    fn test_suffix_matcher_exact() {
        let matcher = SuffixMatcher::new(vec!["ads.example.com".to_string()]);
        assert!(matcher.is_blocked("ads.example.com"));
    }

    #[test]
    fn test_suffix_matcher_subdomain() {
        let matcher = SuffixMatcher::new(vec!["ads.example.com".to_string()]);
        assert!(matcher.is_blocked("foo.ads.example.com"));
        assert!(matcher.is_blocked("bar.foo.ads.example.com"));
    }

    #[test]
    fn test_suffix_matcher_no_match() {
        let matcher = SuffixMatcher::new(vec!["ads.example.com".to_string()]);
        assert!(!matcher.is_blocked("example.com"));
        assert!(!matcher.is_blocked("other.com"));
        assert!(!matcher.is_blocked("ads.example.org"));
    }

    #[test]
    fn test_suffix_matcher_case_insensitive() {
        let matcher = SuffixMatcher::new(vec!["ADS.EXAMPLE.COM".to_string()]);
        assert!(matcher.is_blocked("foo.ADS.EXAMPLE.COM"));
        assert!(matcher.is_blocked("foo.ads.example.com"));
    }

    #[test]
    fn test_suffix_matcher_multiple_levels() {
        let matcher = SuffixMatcher::new(vec![
            "example.com".to_string(),
            "ads.another.org".to_string(),
        ]);
        assert!(matcher.is_blocked("example.com"));
        assert!(matcher.is_blocked("foo.example.com"));
        assert!(matcher.is_blocked("ads.another.org"));
        assert!(matcher.is_blocked("foo.ads.another.org"));
        assert!(!matcher.is_blocked("another.org"));
    }
}
