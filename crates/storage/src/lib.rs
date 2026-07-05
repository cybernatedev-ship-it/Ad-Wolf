use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

/// Action taken for a DNS query
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum QueryAction {
    Blocked,
    Allowed,
    Cached,
    Error,
}

/// A single query log entry
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    pub id: i64,
    pub timestamp: i64,
    pub domain: String,
    pub query_type: String,
    pub action: String,
    pub upstream_ms: Option<i64>,
    pub client_ip: Option<String>,
}

/// Query store backed by SQLite
pub struct QueryStore {
    conn: Mutex<Connection>,
}

impl QueryStore {
    /// Open or create a database at the given path
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.initialize()?;
        Ok(store)
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> anyhow::Result<()> {
        self.conn.lock().unwrap().execute_batch(
            "CREATE TABLE IF NOT EXISTS query_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   INTEGER NOT NULL,
                domain      TEXT    NOT NULL,
                query_type  TEXT    NOT NULL DEFAULT 'A',
                action      TEXT    NOT NULL,
                upstream_ms INTEGER,
                client_ip   TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_query_log_timestamp
                ON query_log(timestamp DESC);

            CREATE INDEX IF NOT EXISTS idx_query_log_domain
                ON query_log(domain);

            CREATE INDEX IF NOT EXISTS idx_query_log_action
                ON query_log(action);",
        )?;
        Ok(())
    }

    /// Log a DNS query
    pub fn log_query(
        &self,
        domain: &str,
        query_type: &str,
        action: QueryAction,
        upstream_ms: Option<u64>,
        client_ip: Option<&str>,
    ) -> anyhow::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let action_str = match action {
            QueryAction::Blocked => "blocked",
            QueryAction::Allowed => "allowed",
            QueryAction::Cached => "cached",
            QueryAction::Error => "error",
        };
        self.conn.lock().unwrap().execute(
            "INSERT INTO query_log (timestamp, domain, query_type, action, upstream_ms, client_ip)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                now,
                domain,
                query_type,
                action_str,
                upstream_ms.map(|v| v as i64),
                client_ip
            ],
        )?;
        Ok(())
    }

    /// Get the most recent log entries
    pub fn recent(&self, limit: usize) -> anyhow::Result<Vec<LogEntry>> {
        let guard = self.conn.lock().unwrap();
        let mut stmt = guard.prepare(
            "SELECT id, timestamp, domain, query_type, action, upstream_ms, client_ip
             FROM query_log
             ORDER BY timestamp DESC, id DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(LogEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                domain: row.get(2)?,
                query_type: row.get(3)?,
                action: row.get(4)?,
                upstream_ms: row.get(5)?,
                client_ip: row.get(6)?,
            })
        })?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Get the top N most blocked domains
    pub fn top_blocked(&self, limit: usize) -> anyhow::Result<Vec<(String, i64)>> {
        let guard = self.conn.lock().unwrap();
        let mut stmt = guard.prepare(
            "SELECT domain, COUNT(*) as count
             FROM query_log
             WHERE action = 'blocked'
             GROUP BY domain
             ORDER BY count DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Get query counts by action since a given timestamp (epoch seconds)
    pub fn stats_since(&self, since: i64) -> anyhow::Result<StatsSummary> {
        let guard = self.conn.lock().unwrap();
        let mut stmt = guard.prepare(
            "SELECT action, COUNT(*) as count
             FROM query_log
             WHERE timestamp >= ?1
             GROUP BY action",
        )?;
        let rows = stmt.query_map(params![since], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;

        let mut total = 0i64;
        let mut blocked = 0i64;
        let mut allowed = 0i64;
        let mut cached = 0i64;
        let mut errors = 0i64;

        for row in rows {
            let (action, count) = row?;
            total += count;
            match action.as_str() {
                "blocked" => blocked += count,
                "allowed" => allowed += count,
                "cached" => cached += count,
                "error" => errors += count,
                _ => {}
            }
        }

        Ok(StatsSummary {
            total,
            blocked,
            allowed,
            cached,
            errors,
        })
    }

    /// Delete log entries older than the given duration
    pub fn prune(&self, older_than: Duration) -> anyhow::Result<usize> {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(older_than.as_secs());
        let deleted = self.conn.lock().unwrap().execute(
            "DELETE FROM query_log WHERE timestamp <= ?1",
            params![cutoff as i64],
        )?;
        Ok(deleted)
    }
}

/// Summary statistics for a time range
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct StatsSummary {
    pub total: i64,
    pub blocked: i64,
    pub allowed: i64,
    pub cached: i64,
    pub errors: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory() {
        let store = QueryStore::in_memory().unwrap();
        store
            .log_query("example.com", "A", QueryAction::Blocked, None, None)
            .unwrap();
        assert_eq!(store.recent(10).unwrap().len(), 1);
    }

    #[test]
    fn test_recent_orders_by_timestamp_desc() {
        let store = QueryStore::in_memory().unwrap();
        store
            .log_query("first.com", "A", QueryAction::Allowed, None, None)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        store
            .log_query("second.com", "A", QueryAction::Blocked, None, None)
            .unwrap();
        let recent = store.recent(10).unwrap();
        assert_eq!(recent.len(), 2);
        // second should come first (more recent timestamp)
        assert_eq!(recent[0].domain, "second.com");
        assert_eq!(recent[1].domain, "first.com");
    }

    #[test]
    fn test_top_blocked() {
        let store = QueryStore::in_memory().unwrap();
        for _ in 0..3 {
            store
                .log_query("ads.com", "A", QueryAction::Blocked, None, None)
                .unwrap();
        }
        for _ in 0..1 {
            store
                .log_query("tracker.com", "A", QueryAction::Blocked, None, None)
                .unwrap();
        }
        let top = store.top_blocked(5).unwrap();
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "ads.com");
        assert_eq!(top[0].1, 3);
        assert_eq!(top[1].0, "tracker.com");
        assert_eq!(top[1].1, 1);
    }

    #[test]
    fn test_stats_since() {
        let store = QueryStore::in_memory().unwrap();
        store
            .log_query("a.com", "A", QueryAction::Blocked, None, None)
            .unwrap();
        store
            .log_query("b.com", "A", QueryAction::Allowed, None, None)
            .unwrap();
        store
            .log_query("c.com", "A", QueryAction::Cached, None, None)
            .unwrap();
        store
            .log_query("d.com", "A", QueryAction::Error, None, None)
            .unwrap();
        let stats = store.stats_since(0).unwrap();
        assert_eq!(stats.total, 4);
        assert_eq!(stats.blocked, 1);
        assert_eq!(stats.allowed, 1);
        assert_eq!(stats.cached, 1);
        assert_eq!(stats.errors, 1);
    }

    #[test]
    fn test_empty_stats() {
        let store = QueryStore::in_memory().unwrap();
        let stats = store.stats_since(0).unwrap();
        assert_eq!(stats.total, 0);
        assert_eq!(stats.blocked, 0);
    }

    #[test]
    fn test_prune() {
        let store = QueryStore::in_memory().unwrap();
        store
            .log_query("old.com", "A", QueryAction::Blocked, None, None)
            .unwrap();
        // Prune with zero duration should remove everything (now <= now is true)
        let deleted = store.prune(Duration::from_secs(0)).unwrap();
        assert!(deleted >= 1);
        assert_eq!(store.recent(10).unwrap().len(), 0);
    }

    #[test]
    fn test_client_ip() {
        let store = QueryStore::in_memory().unwrap();
        store
            .log_query(
                "example.com",
                "A",
                QueryAction::Blocked,
                Some(42),
                Some("192.168.1.1"),
            )
            .unwrap();
        let recent = store.recent(10).unwrap();
        assert_eq!(recent[0].client_ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(recent[0].upstream_ms, Some(42));
    }

    #[test]
    fn test_multiple_query_types() {
        let store = QueryStore::in_memory().unwrap();
        store
            .log_query("example.com", "AAAA", QueryAction::Allowed, None, None)
            .unwrap();
        store
            .log_query("example.com", "MX", QueryAction::Allowed, None, None)
            .unwrap();
        let recent = store.recent(10).unwrap();
        assert_eq!(recent.len(), 2);
        // Both have the same timestamp but MX was inserted second (higher id)
        assert_eq!(recent[0].query_type, "MX");
        assert_eq!(recent[1].query_type, "AAAA");
    }
}
