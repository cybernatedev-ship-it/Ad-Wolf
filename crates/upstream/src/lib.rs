//! Upstream resolver handling
//!
//! Supports multiple upstream DNS servers with automatic failover.
//! Protocols: UDP, TCP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH).

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_PORT: u16 = 53;
const TLS_PORT: u16 = 853;

/// Supported upstream protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Plain UDP (traditional DNS)
    Udp,
    /// Plain TCP (traditional DNS)
    Tcp,
    /// DNS-over-TLS (RFC 7858)
    Tls,
    /// DNS-over-HTTPS (RFC 8484)
    Https,
}

impl Protocol {
    /// Parse a protocol string. Accepts "udp", "tcp", "tls", "https".
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "udp" => Some(Self::Udp),
            "tcp" => Some(Self::Tcp),
            "tls" => Some(Self::Tls),
            "https" | "doh" => Some(Self::Https),
            _ => None,
        }
    }

    /// Default port for this protocol
    pub fn default_port(&self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => DNS_PORT,
            Self::Tls => TLS_PORT,
            Self::Https => 443,
        }
    }
}

/// Configuration for a single upstream server
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Protocol to use
    pub protocol: Protocol,
    /// Server address (host or host:port, or full URL for DoH)
    pub address: String,
    /// Request timeout
    pub timeout: Duration,
}

impl UpstreamConfig {
    /// Create a new upstream config with default timeout
    pub fn new(protocol: Protocol, address: impl Into<String>) -> Self {
        Self {
            protocol,
            address: address.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Create a new upstream config with custom timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Manages multiple upstream DNS resolvers with automatic failover.
///
/// Upstreams are tried in order. If one fails (timeout, connection error),
/// the next upstream is tried automatically.
#[derive(Clone)]
pub struct UpstreamManager {
    clients: Arc<Vec<UpstreamClient>>,
}

impl UpstreamManager {
    /// Create a new upstream manager from a list of configs
    pub fn new(configs: Vec<UpstreamConfig>) -> Self {
        let clients: Vec<UpstreamClient> = configs.into_iter().map(UpstreamClient::new).collect();
        Self {
            clients: Arc::new(clients),
        }
    }

    /// Forward a DNS query to the first available upstream.
    ///
    /// Tries each configured upstream in order. Returns the first successful
    /// response, or an error if all upstreams fail.
    pub async fn forward(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let last_err = {
            let mut err = None;
            for client in self.clients.iter() {
                match client.forward(query).await {
                    Ok(resp) => return Ok(resp),
                    Err(e) => {
                        tracing::warn!(
                            "Upstream {} ({:?}) failed: {}",
                            client.label(),
                            client.config.protocol,
                            e
                        );
                        err = Some(e);
                    }
                }
            }
            err
        };

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no upstreams configured")))
    }

    /// Number of configured upstreams
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    /// Whether no upstreams are configured
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }
}

/// A single upstream client for a specific protocol
struct UpstreamClient {
    config: UpstreamConfig,
}

impl UpstreamClient {
    fn new(config: UpstreamConfig) -> Self {
        Self { config }
    }

    fn label(&self) -> &str {
        &self.config.address
    }

    async fn forward(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.config.protocol {
            Protocol::Udp => forward_udp(query, &self.config.address, self.config.timeout).await,
            Protocol::Tcp => forward_tcp(query, &self.config.address, self.config.timeout).await,
            Protocol::Tls => forward_tls(query, &self.config.address, self.config.timeout).await,
            Protocol::Https => {
                forward_https(query, &self.config.address, self.config.timeout).await
            }
        }
    }
}

// Forwarding implementations

/// Forward via UDP
async fn forward_udp(query: &[u8], addr: &str, timeout_dur: Duration) -> anyhow::Result<Vec<u8>> {
    let addr = resolve_addr(addr, DNS_PORT)?;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(query, addr).await?;

    let mut buf = vec![0; 4096];
    let (len, _) = timeout(timeout_dur, socket.recv_from(&mut buf)).await??;
    buf.truncate(len);
    Ok(buf)
}

/// Forward via TCP
async fn forward_tcp(query: &[u8], addr: &str, timeout_dur: Duration) -> anyhow::Result<Vec<u8>> {
    let addr = resolve_addr(addr, DNS_PORT)?;
    let mut stream = timeout(timeout_dur, TcpStream::connect(addr)).await??;

    // Write 2-byte length prefix + query
    let len_be = (query.len() as u16).to_be_bytes();
    stream.write_all(&[len_be[0], len_be[1]]).await?;
    stream.write_all(query).await?;
    stream.flush().await?;

    // Read 2-byte response length
    let mut len_buf = [0; 2];
    timeout(timeout_dur, stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    // Read response body
    let mut response = vec![0; resp_len];
    timeout(timeout_dur, stream.read_exact(&mut response)).await??;
    Ok(response)
}

/// Forward via DNS-over-TLS (RFC 7858)
async fn forward_tls(query: &[u8], addr: &str, timeout_dur: Duration) -> anyhow::Result<Vec<u8>> {
    use rustls::ClientConfig;
    use tokio_rustls::TlsConnector;

    // Extract hostname for TLS SNI and address for connection
    let host = addr.split(':').next().unwrap_or(addr).to_string();
    let connect_addr = resolve_addr(addr, TLS_PORT)?;

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = timeout(timeout_dur, TcpStream::connect(connect_addr)).await??;

    let server_name = rustls_pki_types::ServerName::try_from(host.clone())
        .map_err(|_| anyhow::anyhow!("invalid DNS name for TLS: {}", host))?;
    let mut stream = timeout(timeout_dur, connector.connect(server_name, tcp)).await??;

    // DNS-over-TLS uses the same 2-byte length prefix as TCP DNS
    let len_be = (query.len() as u16).to_be_bytes();
    stream.write_all(&len_be).await?;
    stream.write_all(query).await?;
    stream.flush().await?;

    let mut len_buf = [0; 2];
    timeout(timeout_dur, stream.read_exact(&mut len_buf)).await??;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut response = vec![0; resp_len];
    timeout(timeout_dur, stream.read_exact(&mut response)).await??;
    Ok(response)
}

/// Forward via DNS-over-HTTPS (RFC 8484)
async fn forward_https(query: &[u8], addr: &str, timeout_dur: Duration) -> anyhow::Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(timeout_dur)
        .use_rustls_tls()
        .build()?;

    // Build the URL: if it's already a full URL, use it; otherwise construct one
    let url = if addr.starts_with("https://") || addr.starts_with("http://") {
        addr.to_string()
    } else {
        format!("https://{}/dns-query", addr)
    };

    let resp = client
        .post(&url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(query.to_vec())
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("DoH request to {} returned HTTP {}", url, resp.status());
    }

    let bytes = resp.bytes().await?;
    Ok(bytes.to_vec())
}

// Helpers

/// Parse an address string into a SocketAddr, applying a default port if not specified.
fn resolve_addr(addr: &str, default_port: u16) -> anyhow::Result<std::net::SocketAddr> {
    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
        return Ok(sa);
    }
    // Wrap bare IPv6 addresses in brackets
    let normalized = if addr.contains(':') && !addr.starts_with('[') {
        format!("[{}]:{}", addr, default_port)
    } else {
        format!("{}:{}", addr, default_port)
    };
    normalized
        .parse::<std::net::SocketAddr>()
        .map_err(|e| anyhow::anyhow!("invalid address '{}': {}", addr, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_parse() {
        assert_eq!(Protocol::parse("udp"), Some(Protocol::Udp));
        assert_eq!(Protocol::parse("UDP"), Some(Protocol::Udp));
        assert_eq!(Protocol::parse("tcp"), Some(Protocol::Tcp));
        assert_eq!(Protocol::parse("tls"), Some(Protocol::Tls));
        assert_eq!(Protocol::parse("https"), Some(Protocol::Https));
        assert_eq!(Protocol::parse("doh"), Some(Protocol::Https));
        assert_eq!(Protocol::parse("unknown"), None);
    }

    #[test]
    fn test_protocol_default_port() {
        assert_eq!(Protocol::Udp.default_port(), 53);
        assert_eq!(Protocol::Tcp.default_port(), 53);
        assert_eq!(Protocol::Tls.default_port(), 853);
        assert_eq!(Protocol::Https.default_port(), 443);
    }

    #[test]
    fn test_upstream_config() {
        let cfg = UpstreamConfig::new(Protocol::Udp, "1.1.1.1:53");
        assert_eq!(cfg.protocol, Protocol::Udp);
        assert_eq!(cfg.address, "1.1.1.1:53");
        assert_eq!(cfg.timeout, DEFAULT_TIMEOUT);

        let cfg =
            UpstreamConfig::new(Protocol::Udp, "1.1.1.1:53").with_timeout(Duration::from_secs(3));
        assert_eq!(cfg.timeout, Duration::from_secs(3));
    }

    #[test]
    fn test_upstream_manager_empty() {
        let mgr = UpstreamManager::new(vec![]);
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_upstream_manager_with_configs() {
        let mgr = UpstreamManager::new(vec![
            UpstreamConfig::new(Protocol::Udp, "1.1.1.1:53"),
            UpstreamConfig::new(Protocol::Udp, "8.8.8.8:53"),
        ]);
        assert!(!mgr.is_empty());
        assert_eq!(mgr.len(), 2);
    }

    #[test]
    fn test_resolve_addr_with_port() {
        let addr = resolve_addr("1.1.1.1:53", 53).unwrap();
        assert_eq!(addr.to_string(), "1.1.1.1:53");
    }

    #[test]
    fn test_resolve_addr_default_port() {
        let addr = resolve_addr("1.1.1.1", 53).unwrap();
        assert_eq!(addr.to_string(), "1.1.1.1:53");
    }

    #[test]
    fn test_resolve_addr_invalid() {
        assert!(resolve_addr("", 53).is_err());
        assert!(resolve_addr("not-an-address:abc", 53).is_err());
    }

    #[test]
    fn test_resolve_addr_ipv6() {
        let addr = resolve_addr("[::1]:53", 53).unwrap();
        assert_eq!(addr.to_string(), "[::1]:53");
    }

    #[test]
    fn test_resolve_addr_ipv6_default_port() {
        let addr = resolve_addr("::1", 53).unwrap();
        assert_eq!(addr.port(), 53);
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_forward_udp_timeout() {
        // Should fail fast (no DNS server on this address)
        let fut = forward_udp(
            b"\x00\x01\x00\x00\x00\x00\x00\x00",
            "127.0.0.1:1",
            Duration::from_millis(100),
        );
        let result = tokio::runtime::Runtime::new().unwrap().block_on(fut);
        assert!(result.is_err());
    }

    #[test]
    fn test_forward_tcp_timeout() {
        let fut = forward_tcp(
            b"\x00\x01\x00\x00\x00\x00\x00\x00",
            "127.0.0.1:1",
            Duration::from_millis(100),
        );
        let result = tokio::runtime::Runtime::new().unwrap().block_on(fut);
        assert!(result.is_err());
    }

    #[test]
    fn test_forward_tls_timeout() {
        let fut = forward_tls(
            b"\x00\x01\x00\x00\x00\x00\x00\x00",
            "127.0.0.1:1",
            Duration::from_millis(100),
        );
        let result = tokio::runtime::Runtime::new().unwrap().block_on(fut);
        assert!(result.is_err());
    }

    #[test]
    fn test_forward_https_invalid_url() {
        let fut = forward_https(
            b"\x00\x01\x00\x00\x00\x00\x00\x00",
            "not-a-valid-url",
            Duration::from_millis(100),
        );
        let result = tokio::runtime::Runtime::new().unwrap().block_on(fut);
        assert!(result.is_err());
    }

    #[test]
    fn test_forward_https_bad_host() {
        let fut = forward_https(
            b"\x00\x01\x00\x00\x00\x00\x00\x00",
            "https://nonexistent.invalid/dns-query",
            Duration::from_millis(500),
        );
        let result = tokio::runtime::Runtime::new().unwrap().block_on(fut);
        assert!(result.is_err());
    }

    #[test]
    fn test_upstream_manager_single_fails() {
        let mgr = UpstreamManager::new(vec![UpstreamConfig::new(Protocol::Udp, "127.0.0.1:1")]);
        let fut = mgr.forward(b"\x00\x01\x00\x00\x00\x00\x00\x00");
        let result = tokio::runtime::Runtime::new().unwrap().block_on(fut);
        assert!(result.is_err());
    }

    #[test]
    fn test_upstream_manager_all_fail() {
        let mgr = UpstreamManager::new(vec![
            UpstreamConfig::new(Protocol::Udp, "127.0.0.1:1"),
            UpstreamConfig::new(Protocol::Udp, "127.0.0.1:2"),
        ]);
        let fut = mgr.forward(b"\x00\x01\x00\x00\x00\x00\x00\x00");
        let result = tokio::runtime::Runtime::new().unwrap().block_on(fut);
        assert!(result.is_err());
    }
}
