use dashmap::DashSet;
use std::sync::Arc;

pub struct RuleEngine {
    blocked_domains: Arc<DashSet<String>>,
}

impl RuleEngine {
    pub fn new(domains: impl IntoIterator<Item = String>) -> Self {
        let blocked_domains = Arc::new(DashSet::new());
        for domain in domains {
            blocked_domains.insert(domain);
        }
        RuleEngine { blocked_domains }
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // Exact match
        if self.blocked_domains.contains(&domain_lower) {
            return true;
        }

        // Suffix match (e.g., ads.example.com blocks foo.ads.example.com)
        for entry in self.blocked_domains.iter() {
            if domain_lower.ends_with(&format!(".{}", entry.value())) {
                return true;
            }
        }

        false
    }

    pub fn count(&self) -> usize {
        self.blocked_domains.len()
    }
}
