//! Filter engine with modular matcher system

pub use dns_filter_core::{
    ExactMatcher, ExceptionMatcher, Matcher, SuffixMatcher, WildcardMatcher,
};
use std::sync::Arc;

/// A parsed rule line with its matching semantics
#[derive(Debug, Clone)]
pub struct ParsedRule {
    /// The domain or pattern to match
    pub domain: String,
    /// Whether this is an exception (allow instead of block)
    pub is_exception: bool,
    /// Whether this pattern contains wildcards
    pub is_wildcard: bool,
    /// Whether this should match subdomains too (suffix style)
    pub match_subdomains: bool,
}

/// Rule engine combining multiple matchers with priority-based matching
///
/// Matching priority:
/// 1. Exception rules (if matched → ALLOW, skip all blocking checks)
/// 2. Exact rules
/// 3. Wildcard rules
/// 4. Suffix rules
/// 5. Hosts rules
pub struct RuleEngine {
    exception_matcher: Arc<ExceptionMatcher>,
    block_matchers: Vec<(String, Arc<dyn Matcher>)>,
}

impl RuleEngine {
    /// Create a new rule engine
    ///
    /// `exception_matcher` is checked first — if matched, the domain is allowed.
    /// `block_matchers` are checked in priority order — first match blocks the domain.
    pub fn new(
        exception_matcher: Arc<ExceptionMatcher>,
        block_matchers: Vec<(String, Arc<dyn Matcher>)>,
    ) -> Self {
        Self {
            exception_matcher,
            block_matchers,
        }
    }

    /// Check if a domain should be blocked
    ///
    /// Returns `true` if the domain is blocked, `false` if allowed (or no rule matches).
    pub fn is_blocked(&self, domain: &str) -> bool {
        // 1. Check exceptions first (highest priority)
        if self.exception_matcher.is_exception(domain) {
            return false;
        }

        // 2. Check block matchers in priority order
        for (_, matcher) in &self.block_matchers {
            if matcher.is_blocked(domain) {
                return true;
            }
        }

        false
    }

    /// Get the number of block matchers
    pub fn matcher_count(&self) -> usize {
        self.block_matchers.len()
    }

    /// Get total rule count across all matchers
    pub fn total_rule_count(&self) -> usize {
        let raw: usize = self.exception_matcher.count();
        raw + self
            .block_matchers
            .iter()
            .map(|(_, m)| m.rule_count())
            .sum::<usize>()
    }

    /// Get matchers info for logging
    pub fn matchers_info(&self) -> Vec<(String, &'static str)> {
        self.block_matchers
            .iter()
            .map(|(name, matcher)| (name.clone(), matcher.name()))
            .collect()
    }
}

/// Parser for different rule formats
///
/// Supports:
/// - Plain domains: `example.com`
/// - uBlock Origin: `||example.com^`, `@@||allowed.example.com^`
/// - AdGuard-style: `||example.com^$third-party`
/// - Hosts file: `0.0.0.0 example.com`
/// - Comments: `! comment`, `# comment`
/// - Empty lines
pub mod parser {
    use super::ParsedRule;

    /// Parse a single line from a rules file.
    ///
    /// Returns `None` for empty lines, comments, or unparseable lines.
    /// Returns `Some(ParsedRule)` with the extracted domain and matching semantics.
    pub fn parse_line(line: &str) -> Option<ParsedRule> {
        let line = line.trim();

        if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
            return None;
        }

        // Determine if this is an exception rule
        let (rest, is_exception) = if let Some(s) = line.strip_prefix("@@") {
            (s, true)
        } else {
            (line, false)
        };

        // Determine if this has wildcards
        let has_wildcard = rest.contains('*');

        // Check for uBlock/AdGuard format: ||domain^ or ||domain
        let domain_str = if let Some(stripped) = rest.strip_prefix("||") {
            stripped
        } else {
            rest
        };

        // Strip $options (AdGuard format) first, then trailing ^ (uBlock anchor)
        let domain_str = if let Some(pos) = domain_str.find('$') {
            &domain_str[..pos]
        } else {
            domain_str
        };
        let domain_str = domain_str.strip_suffix('^').unwrap_or(domain_str);

        // Strip leading and trailing whitespace again
        let domain_str = domain_str.trim();

        if domain_str.is_empty() {
            return None;
        }

        // Check if it's a hosts-file format: "IP domain" or "IP\tdomain"
        let (domain_str, _is_hosts) = {
            let first_char = domain_str.chars().next().unwrap_or(' ');
            if first_char.is_ascii_digit() || domain_str.starts_with("::") {
                // Likely "1.2.3.4 domain" or "::1 domain"
                let parts: Vec<&str> = domain_str.splitn(2, char::is_whitespace).collect();
                if parts.len() == 2 {
                    (parts[1].trim(), true)
                } else {
                    (domain_str, false)
                }
            } else {
                (domain_str, false)
            }
        };

        let domain_lower = domain_str.to_lowercase();
        if domain_lower.is_empty() {
            return None;
        }

        // Determine match semantics
        // uBlock `||` prefix = match subdomains (suffix style)
        // Plain domain (no prefix) = exact match unless it has wildcards
        let match_subdomains = has_wildcard || rest.starts_with("||");

        Some(ParsedRule {
            domain: domain_lower,
            is_exception,
            is_wildcard: has_wildcard,
            match_subdomains,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_plain_domain() {
            let rule = parse_line("ads.example.com").unwrap();
            assert_eq!(rule.domain, "ads.example.com");
            assert!(!rule.is_exception);
            assert!(!rule.is_wildcard);
            assert!(!rule.match_subdomains);
        }

        #[test]
        fn test_ublock_rule() {
            let rule = parse_line("||ads.example.com^").unwrap();
            assert_eq!(rule.domain, "ads.example.com");
            assert!(!rule.is_exception);
            assert!(!rule.is_wildcard);
            assert!(rule.match_subdomains);
        }

        #[test]
        fn test_exception_ublock() {
            let rule = parse_line("@@||allowed.example.com^").unwrap();
            assert_eq!(rule.domain, "allowed.example.com");
            assert!(rule.is_exception);
            assert!(!rule.is_wildcard);
            assert!(rule.match_subdomains);
        }

        #[test]
        fn test_exception_plain() {
            let rule = parse_line("@@allowed.example.com").unwrap();
            assert_eq!(rule.domain, "allowed.example.com");
            assert!(rule.is_exception);
            assert!(!rule.is_wildcard);
            assert!(!rule.match_subdomains);
        }

        #[test]
        fn test_hosts_format() {
            let rule = parse_line("0.0.0.0 ads.example.com").unwrap();
            assert_eq!(rule.domain, "ads.example.com");
            assert!(!rule.is_exception);
            assert!(!rule.is_wildcard);
            assert!(!rule.match_subdomains);
        }

        #[test]
        fn test_hosts_format_with_tab() {
            let rule = parse_line("0.0.0.0\tads.example.com").unwrap();
            assert_eq!(rule.domain, "ads.example.com");
            assert!(!rule.is_exception);
        }

        #[test]
        fn test_wildcard_pattern() {
            let rule = parse_line("ads.*.example.com").unwrap();
            assert_eq!(rule.domain, "ads.*.example.com");
            assert!(!rule.is_exception);
            assert!(rule.is_wildcard);
            assert!(rule.match_subdomains);
        }

        #[test]
        fn test_comment_exclamation() {
            assert!(parse_line("! this is a comment").is_none());
        }

        #[test]
        fn test_comment_hash() {
            assert!(parse_line("# this is a comment").is_none());
        }

        #[test]
        fn test_empty_line() {
            assert!(parse_line("").is_none());
            assert!(parse_line("   ").is_none());
        }

        #[test]
        fn test_adguard_options() {
            let rule = parse_line("||ads.example.com^$third-party").unwrap();
            assert_eq!(rule.domain, "ads.example.com");
            assert!(!rule.is_exception);
            assert!(rule.match_subdomains);
        }

        #[test]
        fn test_no_ip_for_exception() {
            let rule = parse_line("@@0.0.0.0 allowed.example.com").unwrap();
            assert_eq!(rule.domain, "allowed.example.com");
            assert!(rule.is_exception);
        }
    }
}

/// Loader for rule files
pub mod loader {
    use super::parser::parse_line;
    use super::{
        ExactMatcher, ExceptionMatcher, Matcher, RuleEngine, SuffixMatcher, WildcardMatcher,
    };
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;

    /// Load rules from a directory containing .txt files
    ///
    /// Parses each file and categorizes rules into the appropriate matchers:
    /// - Exception rules → `ExceptionMatcher` (checked first)
    /// - Wildcard patterns → `WildcardMatcher`
    /// - uBlock `||domain^` style → `SuffixMatcher`
    /// - Plain/hosts domains → `ExactMatcher`
    pub fn load_rules<P: AsRef<Path>>(dir: P) -> anyhow::Result<RuleEngine> {
        let exception_matcher = ExceptionMatcher::new();
        let mut exact_domains = Vec::new();
        let mut suffix_domains = Vec::new();
        let mut wildcard_patterns = Vec::new();

        let entries = match fs::read_dir(dir.as_ref()) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(
                    "Rules directory {} not found, starting with empty rules",
                    dir.as_ref().display()
                );
                return Ok(RuleEngine::new(
                    Arc::new(ExceptionMatcher::new()),
                    vec![(
                        "exact".to_string(),
                        Arc::new(ExactMatcher::new(Vec::new())) as Arc<dyn Matcher>,
                    )],
                ));
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

            let mut file_exception = 0u64;
            let mut file_exact = 0u64;
            let mut file_suffix = 0u64;
            let mut file_wildcard = 0u64;

            for line in contents.lines() {
                let parsed = match parse_line(line) {
                    Some(r) => r,
                    None => continue,
                };

                if parsed.is_exception {
                    if parsed.match_subdomains {
                        exception_matcher.add_suffix(parsed.domain);
                    } else {
                        exception_matcher.add_exact(parsed.domain);
                    }
                    file_exception += 1;
                } else if parsed.is_wildcard {
                    wildcard_patterns.push(parsed.domain);
                    file_wildcard += 1;
                } else if parsed.match_subdomains {
                    suffix_domains.push(parsed.domain);
                    file_suffix += 1;
                } else {
                    // Check if the original line had an IP prefix (hosts format)
                    // We can detect this by checking if the line starts with digits/IP
                    exact_domains.push(parsed.domain);
                    file_exact += 1;
                }
            }

            tracing::info!(
                "Loaded {} rules from {} ({} exception, {} exact, {} suffix, {} wildcard)",
                file_exception + file_exact + file_suffix + file_wildcard,
                file_name,
                file_exception,
                file_exact,
                file_suffix,
                file_wildcard,
            );
        }

        let mut block_matchers: Vec<(String, Arc<dyn Matcher>)> = Vec::new();

        if !exact_domains.is_empty() {
            let m = ExactMatcher::new(exact_domains);
            tracing::info!("Created ExactMatcher with {} rules", m.count());
            block_matchers.push(("exact".to_string(), Arc::new(m)));
        }

        if !wildcard_patterns.is_empty() {
            let m = WildcardMatcher::new(wildcard_patterns);
            tracing::info!("Created WildcardMatcher with {} rules", m.count());
            block_matchers.push(("wildcard".to_string(), Arc::new(m)));
        }

        if !suffix_domains.is_empty() {
            let m = SuffixMatcher::new(suffix_domains);
            tracing::info!("Created SuffixMatcher with {} rules", m.count());
            block_matchers.push(("suffix".to_string(), Arc::new(m)));
        }

        if block_matchers.is_empty() {
            let empty_exact = ExactMatcher::new(Vec::<String>::new());
            block_matchers.push(("exact".to_string(), Arc::new(empty_exact)));
        }

        Ok(RuleEngine::new(Arc::new(exception_matcher), block_matchers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_engine_block() {
        let matcher =
            Arc::new(ExactMatcher::new(vec!["ads.example.com".to_string()])) as Arc<dyn Matcher>;
        let engine = RuleEngine::new(
            Arc::new(ExceptionMatcher::new()),
            vec![("exact".to_string(), matcher)],
        );
        assert!(engine.is_blocked("ads.example.com"));
        assert!(!engine.is_blocked("example.com"));
    }

    #[test]
    fn test_rule_engine_exception_wins() {
        let block =
            Arc::new(ExactMatcher::new(vec!["example.com".to_string()])) as Arc<dyn Matcher>;

        let exceptions = Arc::new(ExceptionMatcher::new());
        exceptions.add_exact("example.com".to_string());

        let engine = RuleEngine::new(exceptions, vec![("exact".to_string(), block)]);
        assert!(!engine.is_blocked("example.com"));
    }

    #[test]
    fn test_rule_engine_priority() {
        let exact =
            Arc::new(ExactMatcher::new(vec!["example.com".to_string()])) as Arc<dyn Matcher>;
        let suffix =
            Arc::new(SuffixMatcher::new(vec!["ads.example.com".to_string()])) as Arc<dyn Matcher>;

        let engine = RuleEngine::new(
            Arc::new(ExceptionMatcher::new()),
            vec![("exact".to_string(), exact), ("suffix".to_string(), suffix)],
        );

        // Exact blocks the exact domain
        assert!(engine.is_blocked("example.com"));
        // Suffix blocks the domain and its subdomains
        assert!(engine.is_blocked("ads.example.com"));
        assert!(engine.is_blocked("sub.ads.example.com"));
        // Not blocked
        assert!(!engine.is_blocked("other.com"));
    }

    #[test]
    fn test_rule_engine_empty() {
        let engine = RuleEngine::new(Arc::new(ExceptionMatcher::new()), vec![]);
        assert!(!engine.is_blocked("anything.com"));
    }

    #[test]
    fn test_matcher_info() {
        let matcher =
            Arc::new(ExactMatcher::new(vec!["example.com".to_string()])) as Arc<dyn Matcher>;
        let engine = RuleEngine::new(
            Arc::new(ExceptionMatcher::new()),
            vec![("test".to_string(), matcher)],
        );
        let info = engine.matchers_info();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].1, "ExactMatcher");
    }
}
