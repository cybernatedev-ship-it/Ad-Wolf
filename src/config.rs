use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context};
use tokio::fs;

const DEFAULT_LISTEN: &str = "127.0.0.1:5353";
const DEFAULT_CACHE: bool = true;
const DEFAULT_CACHE_TTL_SECONDS: u64 = 300;
const DEFAULT_LOG_QUERIES: bool = true;
const DEFAULT_LIST_DIR: &str = "lists";
const DEFAULT_UPSTREAM_ADDRESS: &str = "1.1.1.1:53";

/// Application configuration loaded from TOML.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppConfig {
    /// UDP socket address the local DNS server listens on.
    pub listen: String,
    /// Enables or disables DNS response caching.
    pub cache: bool,
    /// Cache lifetime in seconds for upstream DNS responses.
    pub cache_ttl_seconds: u64,
    /// Enables query logging.
    pub log_queries: bool,
    /// Directory containing local rule lists.
    pub list_dir: String,
    /// Ordered upstream resolver definitions.
    pub upstream: Vec<UpstreamConfig>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.to_string(),
            cache: DEFAULT_CACHE,
            cache_ttl_seconds: DEFAULT_CACHE_TTL_SECONDS,
            log_queries: DEFAULT_LOG_QUERIES,
            list_dir: DEFAULT_LIST_DIR.to_string(),
            upstream: vec![UpstreamConfig::default()],
        }
    }
}

impl AppConfig {
    /// Loads configuration from a TOML file or returns defaults when the file is missing.
    pub async fn load_or_default(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let content = match fs::read_to_string(path).await {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(
                    "Configuration file {} not found, using defaults",
                    path.display()
                );
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to read config file {}", path.display()));
            }
        };

        Self::from_toml(&content)
            .with_context(|| format!("failed to parse config file {}", path.display()))
    }

    /// Parses application configuration from TOML text.
    pub fn from_toml(content: &str) -> anyhow::Result<Self> {
        let config = parse_toml_config(content)?;
        config.validate()?;
        Ok(config)
    }

    /// Returns the validated listen socket address.
    pub fn listen_addr(&self) -> anyhow::Result<SocketAddr> {
        self.listen
            .parse()
            .with_context(|| format!("invalid listen address '{}'", self.listen))
    }

    /// Returns the cache TTL as a duration.
    pub fn cache_ttl(&self) -> Duration {
        Duration::from_secs(self.cache_ttl_seconds)
    }

    /// Returns the first UDP upstream address supported by the current server.
    pub fn first_udp_upstream_addr(&self) -> anyhow::Result<SocketAddr> {
        let upstream = self
            .upstream
            .iter()
            .find(|upstream| upstream.protocol == UpstreamProtocol::Udp)
            .context("at least one UDP upstream resolver must be configured")?;

        upstream.socket_addr()
    }

    fn validate(&self) -> anyhow::Result<()> {
        self.listen_addr()?;

        if self.cache_ttl_seconds == 0 {
            bail!("cache_ttl_seconds must be greater than zero");
        }

        if self.list_dir.trim().is_empty() {
            bail!("list_dir must not be empty");
        }

        if self.upstream.is_empty() {
            bail!("at least one upstream resolver must be configured");
        }

        self.first_udp_upstream_addr()?;

        Ok(())
    }
}

/// Supported upstream DNS transport protocols.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamProtocol {
    /// Plain DNS over UDP.
    Udp,
}

/// Configuration for an upstream resolver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamConfig {
    /// Transport protocol used by this upstream.
    pub protocol: UpstreamProtocol,
    /// Socket address of the upstream resolver.
    pub address: String,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            protocol: UpstreamProtocol::Udp,
            address: DEFAULT_UPSTREAM_ADDRESS.to_string(),
        }
    }
}

impl UpstreamConfig {
    /// Returns the validated upstream socket address.
    pub fn socket_addr(&self) -> anyhow::Result<SocketAddr> {
        self.address
            .parse()
            .with_context(|| format!("invalid upstream address '{}'", self.address))
    }
}

fn parse_toml_config(content: &str) -> anyhow::Result<AppConfig> {
    let mut config = AppConfig::default();
    let mut upstreams = Vec::new();
    let mut current_upstream: Option<UpstreamConfig> = None;
    let mut saw_upstream_array = false;

    for (line_index, raw_line) in content.lines().enumerate() {
        let line_number = line_index + 1;
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        if line == "[[upstream]]" {
            saw_upstream_array = true;
            if let Some(upstream) = current_upstream.take() {
                upstreams.push(upstream);
            }
            current_upstream = Some(UpstreamConfig::default());
            continue;
        }

        let (key, value) = line.split_once('=').with_context(|| {
            format!(
                "invalid TOML assignment on line {}: expected key = value",
                line_number
            )
        })?;

        if let Some(upstream) = current_upstream.as_mut() {
            parse_upstream_field(upstream, key.trim(), value.trim(), line_number)?;
        } else {
            parse_root_field(
                &mut config,
                key.trim(),
                value.trim(),
                &mut upstreams,
                line_number,
            )?;
        }
    }

    if let Some(upstream) = current_upstream {
        upstreams.push(upstream);
    }

    if saw_upstream_array {
        config.upstream = upstreams;
    }

    Ok(config)
}

fn parse_root_field(
    config: &mut AppConfig,
    key: &str,
    value: &str,
    upstreams: &mut Vec<UpstreamConfig>,
    line_number: usize,
) -> anyhow::Result<()> {
    match key {
        "listen" => config.listen = parse_string(value, line_number)?.to_string(),
        "cache" => config.cache = parse_bool(value, line_number)?,
        "cache_ttl_seconds" => config.cache_ttl_seconds = parse_u64(value, line_number)?,
        "log_queries" => config.log_queries = parse_bool(value, line_number)?,
        "list_dir" => config.list_dir = parse_string(value, line_number)?.to_string(),
        "upstream" if value == "[]" => {
            upstreams.clear();
            config.upstream.clear();
        }
        unknown => bail!(
            "unknown configuration key '{}' on line {}",
            unknown,
            line_number
        ),
    }

    Ok(())
}

fn parse_upstream_field(
    upstream: &mut UpstreamConfig,
    key: &str,
    value: &str,
    line_number: usize,
) -> anyhow::Result<()> {
    match key {
        "protocol" => {
            upstream.protocol = match parse_string(value, line_number)? {
                "udp" => UpstreamProtocol::Udp,
                protocol => bail!(
                    "unsupported upstream protocol '{}' on line {}",
                    protocol,
                    line_number
                ),
            };
        }
        "address" => upstream.address = parse_string(value, line_number)?.to_string(),
        unknown => bail!(
            "unknown upstream configuration key '{}' on line {}",
            unknown,
            line_number
        ),
    }

    Ok(())
}

fn parse_string(value: &str, line_number: usize) -> anyhow::Result<&str> {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .with_context(|| format!("expected quoted string on line {}", line_number))
}

fn parse_bool(value: &str, line_number: usize) -> anyhow::Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => bail!("expected boolean on line {}", line_number),
    }
}

fn parse_u64(value: &str, line_number: usize) -> anyhow::Result<u64> {
    value
        .parse()
        .with_context(|| format!("expected unsigned integer on line {}", line_number))
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#')
        .map_or(line, |(before_comment, _)| before_comment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_existing_runtime_behavior() {
        let config = AppConfig::default();

        assert_eq!(config.listen, "127.0.0.1:5353");
        assert!(config.cache);
        assert_eq!(config.cache_ttl_seconds, 300);
        assert!(config.log_queries);
        assert_eq!(config.list_dir, "lists");
        assert_eq!(
            config.upstream,
            vec![UpstreamConfig {
                protocol: UpstreamProtocol::Udp,
                address: "1.1.1.1:53".to_string()
            }]
        );
    }

    #[test]
    fn parses_toml_configuration() {
        let config = AppConfig::from_toml(
            r#"
listen = "0.0.0.0:5353"
cache = false
cache_ttl_seconds = 60
log_queries = false
list_dir = "blocklists"

[[upstream]]
protocol = "udp"
address = "9.9.9.9:53"
"#,
        )
        .expect("configuration should parse");

        assert_eq!(
            config.listen_addr().unwrap(),
            "0.0.0.0:5353".parse().unwrap()
        );
        assert!(!config.cache);
        assert_eq!(config.cache_ttl(), Duration::from_secs(60));
        assert!(!config.log_queries);
        assert_eq!(config.list_dir, "blocklists");
        assert_eq!(
            config.first_udp_upstream_addr().unwrap(),
            "9.9.9.9:53".parse().unwrap()
        );
    }

    #[test]
    fn rejects_missing_upstreams() {
        let error = AppConfig::from_toml(
            r#"
upstream = []
"#,
        )
        .expect_err("configuration without upstreams should fail");

        assert!(error.to_string().contains("at least one upstream"));
    }

    #[test]
    fn rejects_invalid_listen_address() {
        let error = AppConfig::from_toml(
            r#"
listen = "not-a-socket"
"#,
        )
        .expect_err("invalid listen socket should fail");

        assert!(error.to_string().contains("invalid listen address"));
    }
}
