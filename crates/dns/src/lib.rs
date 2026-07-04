//! DNS server and protocol handling

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

use dns_filter_cache::ResponseCache;
use dns_filter_filter::RuleEngine;
use dns_filter_upstream::Upstream;

const DEFAULT_UPSTREAM: &str = "1.1.1.1:53";
const CACHE_TTL: Duration = Duration::from_secs(300);

/// DNS server configuration
pub struct DnsServer {
    /// Rule engine for filtering
    pub rules: Arc<RuleEngine>,
    /// DNS response cache
    pub cache: Arc<ResponseCache>,
    /// Upstream resolver
    pub upstream: Arc<Upstream>,
    /// Query statistics logger
    pub stats: Arc<dns_filter_core::QueryLogger>,
}

/// Run the DNS server on both UDP and TCP
pub async fn run_server(addr: &str, rules: Arc<RuleEngine>) -> anyhow::Result<()> {
    let upstream = Arc::new(Upstream::new(DEFAULT_UPSTREAM.parse::<SocketAddr>()?));
    let cache = Arc::new(ResponseCache::new(CACHE_TTL));
    let stats = Arc::new(dns_filter_core::QueryLogger::new());

    let server = DnsServer {
        rules,
        cache,
        upstream,
        stats,
    };

    tracing::info!("DNS server listening on {} (UDP + TCP)", addr);
    tracing::info!("Forwarding allowed queries to {}", DEFAULT_UPSTREAM);

    // Spawn UDP server
    let udp_addr = addr.to_string();
    let server_udp = DnsServer {
        rules: Arc::clone(&server.rules),
        cache: Arc::clone(&server.cache),
        upstream: Arc::clone(&server.upstream),
        stats: Arc::clone(&server.stats),
    };
    tokio::spawn(async move {
        if let Err(e) = run_udp_server(&udp_addr, server_udp).await {
            tracing::error!("UDP server error: {}", e);
        }
    });

    // Run TCP server in main thread
    run_tcp_server(addr, server).await?;

    Ok(())
}

/// Run UDP DNS server
async fn run_udp_server(
    addr: &str,
    server: DnsServer,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    tracing::info!("UDP server bound to {}", addr);

    loop {
        let mut buf = vec![0; 512];
        let (n, peer_addr) = socket.recv_from(&mut buf).await?;

        let server = DnsServer {
            rules: Arc::clone(&server.rules),
            cache: Arc::clone(&server.cache),
            upstream: Arc::clone(&server.upstream),
            stats: Arc::clone(&server.stats),
        };
        let socket = Arc::clone(&socket);

        tokio::spawn(async move {
            if let Err(e) = handle_udp_query(&buf[..n], &server, &socket, peer_addr).await {
                tracing::debug!("UDP query error: {}", e);
            }
        });
    }
}

/// Run TCP DNS server
async fn run_tcp_server(
    addr: &str,
    server: DnsServer,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("TCP server bound to {}", addr);

    loop {
        let (mut socket, _peer_addr) = listener.accept().await?;

        let server = DnsServer {
            rules: Arc::clone(&server.rules),
            cache: Arc::clone(&server.cache),
            upstream: Arc::clone(&server.upstream),
            stats: Arc::clone(&server.stats),
        };

        tokio::spawn(async move {
            if let Err(e) = handle_tcp_client(&mut socket, &server).await {
                tracing::debug!("TCP client error: {}", e);
            }
        });
    }
}

/// Handle UDP query
async fn handle_udp_query(
    buf: &[u8],
    server: &DnsServer,
    socket: &UdpSocket,
    peer_addr: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let response = handle_dns_query(buf, server).await?;
    socket.send_to(&response, peer_addr).await?;
    Ok(())
}

/// Handle a TCP DNS client connection
async fn handle_tcp_client(
    socket: &mut tokio::net::TcpStream,
    server: &DnsServer,
) -> anyhow::Result<()> {
    loop {
        // Read DNS query length (2 bytes, big-endian)
        let mut len_buf = [0; 2];
        match socket.read_exact(&mut len_buf).await {
            Ok(0) => break, // Connection closed
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let query_len = u16::from_be_bytes(len_buf) as usize;
        if query_len > 65535 {
            tracing::warn!("Query too large: {} bytes", query_len);
            break;
        }

        // Read the DNS query
        let mut query_buf = vec![0; query_len];
        socket.read_exact(&mut query_buf).await?;

        // Handle the query
        match handle_dns_query(&query_buf, server).await {
            Ok(response) => {
                // Write response length
                let response_len = (response.len() as u16).to_be_bytes();
                socket.write_all(&response_len).await?;
                // Write response
                socket.write_all(&response).await?;
            }
            Err(e) => {
                tracing::debug!("TCP query error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single DNS query (shared logic for UDP and TCP)
async fn handle_dns_query(
    buf: &[u8],
    server: &DnsServer,
) -> anyhow::Result<Vec<u8>> {
    let req = Message::from_bytes(buf)?;

    if should_block(&req, &server.rules) {
        // Log blocked query
        for query in req.queries() {
            let domain = query.name().to_utf8();
            server.stats.record_blocked(&domain);
        }
        let response_bytes = blocked_response(&req).to_bytes()?;
        return Ok(response_bytes);
    }

    if let Some(cached) = server.cache.get(&req)? {
        server.stats.record_cache_hit();
        tracing::debug!("Cache hit for query id {}", req.id());
        return Ok(cached);
    }

    server.stats.record_cache_miss();
    let response = server.upstream.forward(buf).await?;
    server.cache.insert(&req, response.clone());

    // Log allowed query
    for query in req.queries() {
        let _domain = query.name().to_utf8();
        server.stats.record_allowed();
    }

    Ok(response)
}

fn should_block(req: &Message, rules: &RuleEngine) -> bool {
    req.queries().iter().any(|query| {
        let domain = query.name().to_utf8();
        tracing::debug!("Query: {}", domain);

        if rules.is_blocked(&domain) {
            tracing::info!("BLOCKED: {}", domain);
            true
        } else {
            tracing::debug!("ALLOWED: {}", domain);
            false
        }
    })
}

fn blocked_response(req: &Message) -> Message {
    let mut resp = Message::new();
    resp.set_id(req.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(req.op_code());
    resp.set_recursion_desired(req.recursion_desired());
    resp.set_recursion_available(true);
    resp.set_response_code(ResponseCode::NXDomain);

    for query in req.queries() {
        resp.add_query(query.clone());
    }

    resp
}
