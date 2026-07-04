//! Configuration and settings management

use serde::{Deserialize, Serialize};

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Listening address (e.g., "127.0.0.1:53")
    pub listen: String,
    /// Enable DNS response caching
    pub cache: bool,
    /// Cache TTL in seconds
    pub cache_ttl: u64,
    /// Log all DNS queries
    pub log_queries: bool,
    /// Log file path (optional)
    pub log_file: Option<String>,
    /// Upstream resolvers
    pub upstream: Vec<UpstreamConfig>,
    /// Rule lists
    pub lists: Vec<ListConfig>,
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
    pub enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:53".to_string(),
            cache: true,
            cache_ttl: 300,
            log_queries: false,
            log_file: None,
            upstream: vec![UpstreamConfig {
                protocol: "udp".to_string(),
                address: "1.1.1.1:53".to_string(),
            }],
            lists: vec![],
        }
    }
}

/// Load configuration from TOML file
pub fn load_config(path: &str) -> anyhow::Result<Config> {
    let contents = std::fs::read_to_string(path)?;
    let config: Config = toml::from_str(&contents)?;
    Ok(config)
}

/// Save configuration to TOML file
pub fn save_config(path: &str, config: &Config) -> anyhow::Result<()> {
    let contents = toml::to_string_pretty(config)?;
    std::fs::write(path, contents)?;
    Ok(())
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
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        assert!(toml_str.contains("listen"));
        assert!(toml_str.contains("cache"));
    }
}
