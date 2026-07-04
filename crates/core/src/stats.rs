//! Query statistics and logging

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

/// Query statistics
#[derive(Clone, Debug)]
pub struct QueryStats {
    /// Total queries processed
    pub total_queries: u64,
    /// Total queries blocked
    pub total_blocked: u64,
    /// Total queries allowed
    pub total_allowed: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Queries by result (domain -> count)
    pub blocked_by_domain: Vec<(String, u64)>,
}

/// Global query logger
pub struct QueryLogger {
    total_queries: Arc<AtomicU64>,
    total_blocked: Arc<AtomicU64>,
    total_allowed: Arc<AtomicU64>,
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    /// Track blocked domains with frequency
    blocked_domains: Arc<DashMap<String, u64>>,
}

impl QueryLogger {
    /// Create a new query logger
    pub fn new() -> Self {
        Self {
            total_queries: Arc::new(AtomicU64::new(0)),
            total_blocked: Arc::new(AtomicU64::new(0)),
            total_allowed: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            blocked_domains: Arc::new(DashMap::new()),
        }
    }

    /// Record a query that was blocked
    pub fn record_blocked(&self, domain: &str) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        self.total_blocked.fetch_add(1, Ordering::Relaxed);
        self.blocked_domains
            .entry(domain.to_string())
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    /// Record a query that was allowed
    pub fn record_allowed(&self) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        self.total_allowed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache hit
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current statistics
    pub fn get_stats(&self) -> QueryStats {
        let total = self.total_queries.load(Ordering::Relaxed);
        let blocked = self.total_blocked.load(Ordering::Relaxed);
        let allowed = self.total_allowed.load(Ordering::Relaxed);

        // Get top blocked domains
        let mut blocked_vec: Vec<_> = self
            .blocked_domains
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect();
        blocked_vec.sort_by_key(|b| std::cmp::Reverse(b.1));
        blocked_vec.truncate(100); // Top 100 blocked domains

        QueryStats {
            total_queries: total,
            total_blocked: blocked,
            total_allowed: allowed,
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            blocked_by_domain: blocked_vec,
        }
    }

    /// Reset statistics
    pub fn reset(&self) {
        self.total_queries.store(0, Ordering::Relaxed);
        self.total_blocked.store(0, Ordering::Relaxed);
        self.total_allowed.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.blocked_domains.clear();
    }
}

impl Default for QueryLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Query log entry with timestamp
#[derive(Clone, Debug)]
pub struct QueryLogEntry {
    /// Timestamp when query was processed
    pub timestamp: SystemTime,
    /// Domain that was queried
    pub domain: String,
    /// Whether query was blocked
    pub blocked: bool,
    /// Protocol used: "UDP" or "TCP"
    pub protocol: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_logger_blocked() {
        let logger = QueryLogger::new();
        logger.record_blocked("ads.example.com");
        logger.record_blocked("ads.example.com");
        logger.record_blocked("tracker.example.com");

        let stats = logger.get_stats();
        assert_eq!(stats.total_queries, 3);
        assert_eq!(stats.total_blocked, 3);
        assert_eq!(stats.total_allowed, 0);
    }

    #[test]
    fn test_query_logger_allowed() {
        let logger = QueryLogger::new();
        logger.record_allowed();
        logger.record_allowed();
        logger.record_blocked("ads.example.com");

        let stats = logger.get_stats();
        assert_eq!(stats.total_queries, 3);
        assert_eq!(stats.total_blocked, 1);
        assert_eq!(stats.total_allowed, 2);
    }

    #[test]
    fn test_query_logger_cache() {
        let logger = QueryLogger::new();
        logger.record_cache_hit();
        logger.record_cache_hit();
        logger.record_cache_miss();

        let stats = logger.get_stats();
        assert_eq!(stats.cache_hits, 2);
        assert_eq!(stats.cache_misses, 1);
    }

    #[test]
    fn test_query_logger_domain_tracking() {
        let logger = QueryLogger::new();
        logger.record_blocked("ads.example.com");
        logger.record_blocked("ads.example.com");
        logger.record_blocked("tracker.example.com");

        let stats = logger.get_stats();
        assert_eq!(stats.blocked_by_domain.len(), 2);
        assert_eq!(
            stats.blocked_by_domain[0],
            ("ads.example.com".to_string(), 2)
        );
        assert_eq!(
            stats.blocked_by_domain[1],
            ("tracker.example.com".to_string(), 1)
        );
    }

    #[test]
    fn test_query_logger_reset() {
        let logger = QueryLogger::new();
        logger.record_blocked("ads.example.com");
        logger.record_allowed();
        logger.record_cache_hit();

        let stats_before = logger.get_stats();
        assert!(stats_before.total_queries > 0);

        logger.reset();
        let stats_after = logger.get_stats();
        assert_eq!(stats_after.total_queries, 0);
        assert_eq!(stats_after.total_blocked, 0);
        assert_eq!(stats_after.cache_hits, 0);
    }
}
