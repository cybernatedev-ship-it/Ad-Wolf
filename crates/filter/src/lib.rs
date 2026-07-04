//! Filter engine with modular matcher system

pub use dns_filter_core::{ExactMatcher, Matcher, SuffixMatcher};
use std::sync::Arc;

/// Rule engine combining multiple matchers with priority-based matching
pub struct RuleEngine {
    matchers: Vec<(String, Arc<dyn Matcher>)>,
}

impl RuleEngine {
    /// Create a new rule engine with the given matchers
    pub fn new(matchers: Vec<(String, Arc<dyn Matcher>)>) -> Self {
        Self { matchers }
    }

    /// Check if a domain should be blocked
    pub fn is_blocked(&self, domain: &str) -> bool {
        for (_, matcher) in &self.matchers {
            if matcher.is_blocked(domain) {
                return true;
            }
        }
        false
    }

    /// Get matcher count
    pub fn matcher_count(&self) -> usize {
        self.matchers.len()
    }

    /// Get matchers info for logging
    pub fn matchers_info(&self) -> Vec<(String, &'static str)> {
        self.matchers
            .iter()
            .map(|(name, matcher)| (name.clone(), matcher.name()))
            .collect()
    }
}

/// Parser for different rule formats
pub mod parser {
    /// Parse a single line from a rules file.
    ///
    /// Supports:
    /// - Plain domains: `ads.example.com`
    /// - uBlock-style rules: `||ads.example.com^`
    /// - Comments: `! comment`
    /// - Empty lines
    pub fn parse_line(line: &str) -> Option<String> {
        let line = line.trim();

        if line.is_empty() || line.starts_with('!') {
            return None;
        }

        // Parse uBlock-style rules: ||domain.com^
        let domain = if let Some(stripped) = line.strip_prefix("||") {
            stripped.strip_suffix('^').unwrap_or(stripped)
        } else {
            line
        };

        // Return lowercase domain
        if !domain.is_empty() {
            Some(domain.to_lowercase())
        } else {
            None
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_plain_domain() {
            assert_eq!(
                parse_line("ads.example.com"),
                Some("ads.example.com".to_string())
            );
        }

        #[test]
        fn test_ublock_rule() {
            assert_eq!(
                parse_line("||ads.example.com^"),
                Some("ads.example.com".to_string())
            );
        }

        #[test]
        fn test_comment() {
            assert_eq!(parse_line("! this is a comment"), None);
        }

        #[test]
        fn test_empty_line() {
            assert_eq!(parse_line(""), None);
            assert_eq!(parse_line("   "), None);
        }
    }
}

/// Loader for rule files
pub mod loader {
    use super::parser::parse_line;
    use super::RuleEngine;
    use crate::Matcher;
    use dns_filter_core::{ExactMatcher, SuffixMatcher};
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    /// Load rules from a directory containing .txt files
    ///
    /// Creates both an ExactMatcher and SuffixMatcher, splitting rules appropriately.
    /// This provides optimal performance for both exact and suffix matching.
    pub fn load_rules<P: AsRef<Path>>(dir: P) -> anyhow::Result<RuleEngine> {
        let mut exact_domains = Vec::new();
        let mut suffix_domains = Vec::new();

        // Try to read directory, but don't fail if it doesn't exist yet
        let entries = match fs::read_dir(dir.as_ref()) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(
                    "Rules directory {} not found, starting with empty rules",
                    dir.as_ref().display()
                );
                let exact_matcher = ExactMatcher::new(vec![]);
                return Ok(RuleEngine::new(vec![(
                    "exact".to_string(),
                    Arc::new(exact_matcher),
                )]));
            }
            Err(e) => return Err(e.into()),
        };

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) != Some("txt") {
                continue;
            }

            let contents = fs::read_to_string(&path)?;
            let file_name = path
                .file_stem()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            let mut file_exact_count = 0;
            let mut file_suffix_count = 0;

            for line in contents.lines() {
                if let Some(rule) = parse_line(line) {
                    // Categorize: if it looks like a domain pattern (multiple labels), use suffix
                    // Otherwise use exact matching
                    let label_count = rule.split('.').count();
                    if label_count > 1 {
                        suffix_domains.push(rule);
                        file_suffix_count += 1;
                    } else {
                        exact_domains.push(rule);
                        file_exact_count += 1;
                    }
                }
            }

            tracing::info!(
                "Loaded {} rules from {} ({} exact, {} suffix)",
                file_exact_count + file_suffix_count,
                file_name,
                file_exact_count,
                file_suffix_count
            );
        }

        let mut matchers: Vec<(String, Arc<dyn Matcher>)> = Vec::new();

        // Add exact matcher (higher priority)
        if !exact_domains.is_empty() {
            let exact_matcher = ExactMatcher::new(exact_domains);
            tracing::info!("Created ExactMatcher with {} rules", exact_matcher.count());
            matchers.push(("exact".to_string(), Arc::new(exact_matcher)));
        }

        // Add suffix matcher (lower priority, checked after exact)
        if !suffix_domains.is_empty() {
            let suffix_matcher = SuffixMatcher::new(suffix_domains);
            tracing::info!(
                "Created SuffixMatcher with {} rules",
                suffix_matcher.count()
            );
            matchers.push(("suffix".to_string(), Arc::new(suffix_matcher)));
        }

        // Ensure at least one matcher exists
        if matchers.is_empty() {
            let empty_exact = ExactMatcher::new(vec![]);
            matchers.push(("exact".to_string(), Arc::new(empty_exact)));
        }

        Ok(RuleEngine::new(matchers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_engine() {
        let matcher = Arc::new(dns_filter_core::ExactMatcher::new(vec![
            "ads.example.com".to_string()
        ]));
        let engine = RuleEngine::new(vec![("test".to_string(), matcher)]);
        assert!(engine.is_blocked("ads.example.com"));
        assert!(!engine.is_blocked("example.com"));
    }
}
