//! Configuration and settings management

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Listening address (e.g., "127.0.0.1:53")
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Enable DNS response caching
    #[serde(default = "default_true")]
    pub cache: bool,
    /// Cache TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,
    /// Log all DNS queries
    #[serde(default)]
    pub log_queries: bool,
    /// Log file path (optional)
    pub log_file: Option<String>,
    /// Upstream resolvers
    #[serde(default = "default_upstream")]
    pub upstream: Vec<UpstreamConfig>,
    /// Rule list directory (default: "lists")
    #[serde(default = "default_lists_dir")]
    pub lists_dir: String,
    /// Rule lists
    #[serde(default)]
    pub lists: Vec<ListConfig>,
    /// Path to query log database (empty = in-memory only)
    #[serde(default)]
    pub storage_path: Option<String>,
    /// Prometheus metrics listen address (empty = disabled)
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: String,
    /// Prune query log entries older than this many days (0 = never prune)
    #[serde(default)]
    pub prune_days: u64,
}

fn default_listen() -> String {
    "127.0.0.1:53".to_string()
}

fn default_true() -> bool {
    true
}

fn default_cache_ttl() -> u64 {
    300
}

fn default_upstream() -> Vec<UpstreamConfig> {
    vec![UpstreamConfig {
        protocol: "udp".to_string(),
        address: "1.1.1.1:53".to_string(),
    }]
}

fn default_lists_dir() -> String {
    "lists".to_string()
}

fn default_metrics_addr() -> String {
    "127.0.0.1:9120".to_string()
}

/// Upstream resolver configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Protocol: "udp", "tcp", "https", "tls"
    pub protocol: String,
    /// Server address (e.g., "1.1.1.1:53")
    pub address: String,
}

/// Rule list configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListConfig {
    /// List name (e.g., "adblock", "tracking")
    pub name: String,
    /// Local file path or remote URL
    pub path: String,
    /// Whether this list is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            cache: true,
            cache_ttl: default_cache_ttl(),
            log_queries: false,
            log_file: None,
            upstream: default_upstream(),
            lists_dir: default_lists_dir(),
            lists: vec![],
            storage_path: None,
            metrics_addr: default_metrics_addr(),
            prune_days: 0,
        }
    }
}

impl Config {
    /// Find an existing config file in common locations.
    ///
    /// Checks (in order):
    /// 1. `./config.toml`
    /// 2. `./dns-filter.toml`
    /// 3. `$HOME/.config/dns-filter/config.toml`
    /// 4. `/etc/dns-filter/config.toml`
    pub fn find() -> Option<PathBuf> {
        Self::candidate_paths()
            .into_iter()
            .find(|path| path.exists())
    }

    /// Return all candidate config file paths in priority order.
    pub fn candidate_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Current directory
        paths.push(PathBuf::from("config.toml"));
        paths.push(PathBuf::from("dns-filter.toml"));

        // User config directory
        if let Some(home) = dirs_or_none() {
            let user_dir = home.join(".config").join("dns-filter");
            paths.push(user_dir.join("config.toml"));
        }

        // System config directory
        paths.push(PathBuf::from("/etc/dns-filter/config.toml"));

        paths
    }

    /// Load config from a file path.
    pub fn load_file(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Try to load config from common locations, falling back to defaults.
    ///
    /// If an explicit path is given, loads from that path.
    /// Otherwise searches `find()` paths.
    /// If no config file is found, returns `Config::default()`.
    pub fn load(path: Option<&str>) -> Self {
        let config_path = match path {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => match Self::find() {
                Some(p) => p,
                None => {
                    tracing::info!("No config file found, using defaults");
                    return Self::default();
                }
            },
        };

        match Self::load_file(config_path.to_str().unwrap_or("")) {
            Ok(config) => {
                tracing::info!("Loaded config from {}", config_path.display());
                config
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to load config from {}: {}; using defaults",
                    config_path.display(),
                    e
                );
                Self::default()
            }
        }
    }

    /// Save configuration to a TOML file.
    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        tracing::info!("Config saved to {}", path);
        Ok(())
    }
}

/// Return `$HOME` as a `PathBuf`, or `None` if not set.
fn dirs_or_none() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.listen, "127.0.0.1:53");
        assert!(config.cache);
        assert_eq!(config.cache_ttl, 300);
        assert_eq!(config.lists_dir, "lists");
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(toml_str.contains("listen"));
        assert!(toml_str.contains("cache"));
        assert!(toml_str.contains("lists_dir"));
    }

    #[test]
    fn test_config_roundtrip() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.listen, parsed.listen);
        assert_eq!(config.cache, parsed.cache);
        assert_eq!(config.cache_ttl, parsed.cache_ttl);
        assert_eq!(config.lists_dir, parsed.lists_dir);
        assert_eq!(config.upstream.len(), parsed.upstream.len());
        assert_eq!(config.metrics_addr, parsed.metrics_addr);
    }

    #[test]
    fn test_candidate_paths() {
        let paths = Config::candidate_paths();
        assert!(!paths.is_empty());
        assert!(paths.iter().any(|p| p.ends_with("config.toml")));
    }

    #[test]
    fn test_load_nonexistent_falls_back() {
        let config = Config::load(Some("/nonexistent/path/config.toml"));
        assert_eq!(config.listen, "127.0.0.1:53");
    }

    #[test]
    fn test_load_file() {
        let tmpdir = std::env::temp_dir().join("dns-filter-test-config.toml");
        let toml_content = r#"
listen = "0.0.0.0:5353"
cache = false
cache_ttl = 60
upstream = []
"#;
        std::fs::write(&tmpdir, toml_content).unwrap();
        let config = Config::load_file(tmpdir.to_str().unwrap()).unwrap();
        std::fs::remove_file(&tmpdir).ok();
        assert_eq!(config.listen, "0.0.0.0:5353");
        assert!(!config.cache);
        assert_eq!(config.cache_ttl, 60);
        assert!(config.upstream.is_empty());
    }

    #[test]
    fn test_custom_listen_port() {
        let toml_str = r#"
listen = "0.0.0.0:5353"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.listen, "0.0.0.0:5353");
    }

    #[test]
    fn test_upstream_config() {
        let toml_str = r#"
[[upstream]]
protocol = "udp"
address = "1.1.1.1:53"

[[upstream]]
protocol = "https"
address = "https://dns.cloudflare.com/dns-query"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.upstream.len(), 2);
        assert_eq!(config.upstream[0].protocol, "udp");
        assert_eq!(config.upstream[1].protocol, "https");
    }

    #[test]
    fn test_list_config() {
        let toml_str = r#"
[[lists]]
name = "adblock"
path = "lists/adblock.txt"
enabled = true

[[lists]]
name = "tracking"
path = "lists/tracking.txt"
enabled = false
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.lists.len(), 2);
        assert!(config.lists[0].enabled);
        assert!(!config.lists[1].enabled);
    }

    #[test]
    fn test_lists_dir_default() {
        let toml_str = r#"
listen = "127.0.0.1:53"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.lists_dir, "lists");
    }

    #[test]
    fn test_metrics_addr_default() {
        let config = Config::default();
        assert_eq!(config.metrics_addr, "127.0.0.1:9120");
    }

    #[test]
    fn test_metrics_addr_custom() {
        let toml_str = r#"
metrics_addr = "0.0.0.0:9090"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.metrics_addr, "0.0.0.0:9090");
    }
}
