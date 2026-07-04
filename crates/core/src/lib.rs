//! Core business logic for DNS filtering

use dashmap::DashSet;
use std::sync::Arc;

pub mod stats;

pub use stats::{QueryLogEntry, QueryLogger, QueryStats};

/// A trait for implementing different rule matching strategies
pub trait Matcher: Send + Sync {
    /// Check if a domain should be blocked
    fn is_blocked(&self, domain: &str) -> bool;

    /// Get the matcher name for logging/debugging
    fn name(&self) -> &'static str;

    /// Get the number of rules in this matcher
    fn rule_count(&self) -> usize {
        0
    }
}

/// Exact domain matcher - O(1) lookup
///
/// Matches only the exact domain (no subdomains).
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

    fn rule_count(&self) -> usize {
        self.blocked.len()
    }
}

/// Suffix domain matcher - blocks a domain and all its subdomains
///
/// For a rule `ads.example.com`:
/// - Matches `ads.example.com` (exact)
/// - Matches `foo.ads.example.com` (subdomain)
/// - Matches `bar.foo.ads.example.com` (deeper subdomain)
/// - Does NOT match `example.com` or `other.com`
///
/// Uses a reversed-label approach for efficient O(k) lookup where k is domain depth.
#[derive(Clone)]
pub struct SuffixMatcher {
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

    /// Add a domain to block (including all subdomains)
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

    fn rule_count(&self) -> usize {
        self.suffixes.len()
    }
}

/// Wildcard matcher - handles patterns with `*` glob-style wildcards
///
/// Supports patterns like `ads.*.example.com` which matches:
/// - `ads.foo.example.com`
/// - `ads.bar.example.com`
/// - Does NOT match `ads.example.com` (no subdomain between ads and example)
/// - Does NOT match `ads.foo.bar.example.com`
///
/// Each `*` matches exactly one label level.
#[derive(Clone)]
pub struct WildcardMatcher {
    patterns: Arc<DashSet<Vec<Option<String>>>>,
}

impl WildcardMatcher {
    /// Create a new wildcard matcher from patterns
    ///
    /// Each pattern is a domain-like string where `*` matches a single label.
    pub fn new(patterns: impl IntoIterator<Item = String>) -> Self {
        let patterns_set = Arc::new(DashSet::new());
        for pattern in patterns {
            if pattern.contains('*') {
                let compiled = Self::compile_pattern(&pattern);
                patterns_set.insert(compiled);
            }
        }
        Self {
            patterns: patterns_set,
        }
    }

    /// Add a wildcard pattern
    pub fn add(&self, pattern: String) {
        if pattern.contains('*') {
            let compiled = Self::compile_pattern(&pattern);
            self.patterns.insert(compiled);
        }
    }

    /// Get the number of patterns
    pub fn count(&self) -> usize {
        self.patterns.len()
    }

    /// Compile a pattern string into label segments.
    /// Each segment is `Some(label)` for a literal or `None` for a `*` wildcard.
    fn compile_pattern(pattern: &str) -> Vec<Option<String>> {
        let pattern_lower = pattern.to_lowercase();
        pattern_lower
            .split('.')
            .map(|label| {
                if label == "*" {
                    None
                } else {
                    Some(label.to_string())
                }
            })
            .collect()
    }
}

impl Matcher for WildcardMatcher {
    fn is_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        let query_labels: Vec<&str> = domain_lower.split('.').collect();

        for pattern in self.patterns.iter() {
            if pattern.len() != query_labels.len() {
                continue;
            }

            let matched = pattern
                .iter()
                .zip(query_labels.iter())
                .all(|(segment, label)| match segment {
                    None => true,
                    Some(literal) => literal == label,
                });

            if matched {
                return true;
            }
        }

        false
    }

    fn name(&self) -> &'static str {
        "WildcardMatcher"
    }

    fn rule_count(&self) -> usize {
        self.patterns.len()
    }
}

/// Exception matcher - marks domains that should NOT be blocked
///
/// Checked first by the RuleEngine. If an exception is matched,
/// the domain is allowed regardless of other matchers.
///
/// Supports both exact and suffix-style exceptions.
#[derive(Clone)]
pub struct ExceptionMatcher {
    exact: Arc<DashSet<String>>,
    suffixes: Arc<DashSet<Vec<String>>>,
}

impl ExceptionMatcher {
    /// Create a new exception matcher
    pub fn new() -> Self {
        Self {
            exact: Arc::new(DashSet::new()),
            suffixes: Arc::new(DashSet::new()),
        }
    }

    /// Add an exact-match exception (only this domain)
    pub fn add_exact(&self, domain: String) {
        self.exact.insert(domain.to_lowercase());
    }

    /// Add a suffix-match exception (domain and all subdomains)
    pub fn add_suffix(&self, domain: String) {
        let domain_lower = domain.to_lowercase();
        let labels: Vec<String> = domain_lower.split('.').map(|s| s.to_string()).collect();
        if !labels.is_empty() {
            self.suffixes.insert(labels);
        }
    }

    /// Check if a domain matches any exception
    pub fn is_exception(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        if self.exact.contains(&domain_lower) {
            return true;
        }

        let query_labels: Vec<&str> = domain_lower.split('.').collect();
        for (idx, _) in query_labels.iter().enumerate() {
            let suffix: Vec<String> = query_labels[idx..].iter().map(|s| s.to_string()).collect();
            if self.suffixes.contains(&suffix) {
                return true;
            }
        }

        false
    }

    /// Get total number of exception rules
    pub fn count(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }
}

impl Default for ExceptionMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Hosts matcher - handles hosts file format entries
///
/// Parses lines like `0.0.0.0 example.com` and matches the domain exactly.
#[derive(Clone)]
pub struct HostsMatcher {
    blocked: Arc<DashSet<String>>,
}

impl HostsMatcher {
    /// Create a new hosts matcher
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

impl Matcher for HostsMatcher {
    fn is_blocked(&self, domain: &str) -> bool {
        self.blocked.contains(&domain.to_lowercase())
    }

    fn name(&self) -> &'static str {
        "HostsMatcher"
    }

    fn rule_count(&self) -> usize {
        self.blocked.len()
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

    #[test]
    fn test_wildcard_matcher() {
        let matcher = WildcardMatcher::new(vec!["ads.*.example.com".to_string()]);
        assert!(matcher.is_blocked("ads.foo.example.com"));
        assert!(!matcher.is_blocked("ads.example.com"));
        assert!(!matcher.is_blocked("ads.foo.bar.example.com"));
        assert!(!matcher.is_blocked("other.com"));
    }

    #[test]
    fn test_wildcard_matcher_no_wildcard() {
        let matcher = WildcardMatcher::new(vec!["example.com".to_string()]);
        assert!(!matcher.is_blocked("example.com"));
    }

    #[test]
    fn test_wildcard_matcher_multiple_wildcards() {
        let matcher = WildcardMatcher::new(vec!["*.*.example.com".to_string()]);
        assert!(matcher.is_blocked("foo.bar.example.com"));
        assert!(!matcher.is_blocked("foo.bar.baz.example.com"));
        assert!(!matcher.is_blocked("foo.example.com"));
    }

    #[test]
    fn test_exception_matcher_exact() {
        let matcher = ExceptionMatcher::new();
        matcher.add_exact("allowed.example.com".to_string());
        assert!(matcher.is_exception("allowed.example.com"));
        assert!(!matcher.is_exception("sub.allowed.example.com"));
        assert!(!matcher.is_exception("example.com"));
    }

    #[test]
    fn test_exception_matcher_suffix() {
        let matcher = ExceptionMatcher::new();
        matcher.add_suffix("allowed.example.com".to_string());
        assert!(matcher.is_exception("allowed.example.com"));
        assert!(matcher.is_exception("sub.allowed.example.com"));
        assert!(!matcher.is_exception("example.com"));
    }

    #[test]
    fn test_hosts_matcher() {
        let matcher = HostsMatcher::new(vec!["ads.example.com".to_string()]);
        assert!(matcher.is_blocked("ads.example.com"));
        assert!(!matcher.is_blocked("sub.ads.example.com"));
        assert!(!matcher.is_blocked("example.com"));
    }

    #[test]
    fn test_hosts_matcher_case_insensitive() {
        let matcher = HostsMatcher::new(vec!["ADS.EXAMPLE.COM".to_string()]);
        assert!(matcher.is_blocked("ads.example.com"));
        assert!(matcher.is_blocked("ADS.EXAMPLE.COM"));
    }
}
