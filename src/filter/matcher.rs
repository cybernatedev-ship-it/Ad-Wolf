use dashmap::DashSet;

#[derive(Clone)]
pub struct RuleMatcher {
    pub blocked: DashSet<String>,
}

impl RuleMatcher {
    pub fn new() -> Self {
        Self {
            blocked: DashSet::new(),
        }
    }

    pub fn add(&self, domain: String) {
        self.blocked.insert(domain);
    }

    pub fn is_blocked(&self, domain: &str) -> bool {
        if self.blocked.contains(domain) {
            return true;
        }

        for entry in self.blocked.iter() {
            if domain.ends_with(entry.as_str()) {
                return true;
            }
        }

        false
    }
}
