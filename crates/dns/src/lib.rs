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

/// Run the DNS server on both UDP and TCP
pub async fn run_server(addr: &str, rules: Arc<RuleEngine>) -> anyhow::Result<()> {
    let upstream = Arc::new(Upstream::new(DEFAULT_UPSTREAM.parse::<SocketAddr>()?));
    let cache = Arc::new(ResponseCache::new(CACHE_TTL));

    tracing::info!("DNS server listening on {} (UDP + TCP)", addr);
    tracing::info!("Forwarding allowed queries to {}", DEFAULT_UPSTREAM);

    // Spawn UDP server
    let udp_addr = addr.to_string();
    let udp_rules = Arc::clone(&rules);
    let udp_upstream = Arc::clone(&upstream);
    let udp_cache = Arc::clone(&cache);
    tokio::spawn(async move {
        if let Err(e) = run_udp_server(&udp_addr, udp_rules, udp_upstream, udp_cache).await {
            tracing::error!("UDP server error: {}", e);
        }
    });

    // Run TCP server in main thread
    run_tcp_server(addr, rules, upstream, cache).await?;

    Ok(())
}

/// Run UDP DNS server
async fn run_udp_server(
    addr: &str,
    rules: Arc<RuleEngine>,
    upstream: Arc<Upstream>,
    cache: Arc<ResponseCache>,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    tracing::info!("UDP server bound to {}", addr);

    loop {
        let mut buf = vec![0; 512];
        let (n, peer_addr) = socket.recv_from(&mut buf).await?;

        let rules = Arc::clone(&rules);
        let socket = Arc::clone(&socket);
        let upstream = Arc::clone(&upstream);
        let cache = Arc::clone(&cache);

        tokio::spawn(async move {
            if let Err(e) = handle_query(
                &buf[..n],
                &rules,
                &socket,
                peer_addr,
                &upstream,
                &cache,
                false,
            )
            .await
            {
                tracing::debug!("UDP query error: {}", e);
            }
        });
    }
}

/// Run TCP DNS server
async fn run_tcp_server(
    addr: &str,
    rules: Arc<RuleEngine>,
    upstream: Arc<Upstream>,
    cache: Arc<ResponseCache>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("TCP server bound to {}", addr);

    loop {
        let (mut socket, peer_addr) = listener.accept().await?;

        let rules = Arc::clone(&rules);
        let upstream = Arc::clone(&upstream);
        let cache = Arc::clone(&cache);

        tokio::spawn(async move {
            if let Err(e) =
                handle_tcp_client(&mut socket, peer_addr, &rules, &upstream, &cache).await
            {
                tracing::debug!("TCP client error: {}", e);
            }
        });
    }
}

/// Handle a TCP DNS client connection
async fn handle_tcp_client(
    socket: &mut tokio::net::TcpStream,
    peer_addr: SocketAddr,
    rules: &RuleEngine,
    upstream: &Upstream,
    cache: &ResponseCache,
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
        match handle_dns_query(&query_buf, rules, upstream, cache, true).await {
            Ok(response) => {
                // Write response length
                let response_len = (response.len() as u16).to_be_bytes();
                socket.write_all(&response_len).await?;
                // Write response
                socket.write_all(&response).await?;
            }
            Err(e) => {
                tracing::debug!("TCP query error from {}: {}", peer_addr, e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_query(
    buf: &[u8],
    rules: &RuleEngine,
    socket: &UdpSocket,
    peer_addr: std::net::SocketAddr,
    upstream: &Upstream,
    cache: &ResponseCache,
    _is_tcp: bool,
) -> anyhow::Result<()> {
    let response = handle_dns_query(buf, rules, upstream, cache, false).await?;
    socket.send_to(&response, peer_addr).await?;
    Ok(())
}

/// Handle a single DNS query (shared logic for UDP and TCP)
async fn handle_dns_query(
    buf: &[u8],
    rules: &RuleEngine,
    upstream: &Upstream,
    cache: &ResponseCache,
    _is_tcp: bool,
) -> anyhow::Result<Vec<u8>> {
    let req = Message::from_bytes(buf)?;

    if should_block(&req, rules) {
        let response_bytes = blocked_response(&req).to_bytes()?;
        return Ok(response_bytes);
    }

    if let Some(cached) = cache.get(&req)? {
        tracing::debug!("Cache hit for query id {}", req.id());
        return Ok(cached);
    }

    let response = upstream.forward(buf).await?;
    cache.insert(&req, response.clone());
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
