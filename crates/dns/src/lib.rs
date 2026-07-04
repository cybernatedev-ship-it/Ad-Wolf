//! DNS server and protocol handling

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

use dns_filter_cache::ResponseCache;
use dns_filter_filter::RuleEngine;
use dns_filter_upstream::Upstream;

const DEFAULT_UPSTREAM: &str = "1.1.1.1:53";
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Run the DNS server
pub async fn run_server(addr: &str, rules: Arc<RuleEngine>) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    let upstream = Arc::new(Upstream::new(DEFAULT_UPSTREAM.parse::<SocketAddr>()?));
    let cache = Arc::new(ResponseCache::new(CACHE_TTL));
    tracing::info!("DNS server listening on {}", addr);
    tracing::info!("Forwarding allowed queries to {}", DEFAULT_UPSTREAM);

    loop {
        let mut buf = vec![0; 512];
        let (n, peer_addr) = socket.recv_from(&mut buf).await?;

        let rules = Arc::clone(&rules);
        let socket = Arc::clone(&socket);
        let upstream = Arc::clone(&upstream);
        let cache = Arc::clone(&cache);

        tokio::spawn(async move {
            if let Err(e) =
                handle_query(&buf[..n], &rules, &socket, peer_addr, &upstream, &cache).await
            {
                tracing::error!("Error handling query: {}", e);
            }
        });
    }
}

async fn handle_query(
    buf: &[u8],
    rules: &RuleEngine,
    socket: &UdpSocket,
    peer_addr: std::net::SocketAddr,
    upstream: &Upstream,
    cache: &ResponseCache,
) -> anyhow::Result<()> {
    let req = Message::from_bytes(buf)?;

    if should_block(&req, rules) {
        let response_bytes = blocked_response(&req).to_bytes()?;
        socket.send_to(&response_bytes, peer_addr).await?;
        return Ok(());
    }

    if let Some(cached) = cache.get(&req)? {
        tracing::debug!("Cache hit for query id {}", req.id());
        socket.send_to(&cached, peer_addr).await?;
        return Ok(());
    }

    let response = upstream.forward(buf).await?;
    cache.insert(&req, response.clone());
    socket.send_to(&response, peer_addr).await?;

    Ok(())
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
