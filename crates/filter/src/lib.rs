//! Filter engine with modular matcher system

use dns_filter_core::Matcher;
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
    use dns_filter_core::ExactMatcher;
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    /// Load rules from a directory containing .txt files
    pub fn load_rules<P: AsRef<Path>>(dir: P) -> anyhow::Result<RuleEngine> {
        let mut domains = Vec::new();

        // Try to read directory, but don't fail if it doesn't exist yet
        let entries = match fs::read_dir(dir.as_ref()) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(
                    "Rules directory {} not found, starting with empty rules",
                    dir.as_ref().display()
                );
                let matcher = ExactMatcher::new(vec![]);
                return Ok(RuleEngine::new(vec![(
                    "empty".to_string(),
                    Arc::new(matcher),
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

            for line in contents.lines() {
                if let Some(rule) = parse_line(line) {
                    domains.push(rule);
                }
            }

            tracing::info!("Loaded {} rules from {}", domains.len(), file_name);
        }

        let matcher = ExactMatcher::new(domains.clone());
        Ok(RuleEngine::new(vec![(
            "exact".to_string(),
            Arc::new(matcher),
        )]))
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
