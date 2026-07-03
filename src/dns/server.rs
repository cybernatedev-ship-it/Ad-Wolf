use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

use crate::dns::cache::ResponseCache;
use crate::dns::upstream::Upstream;
use crate::filter::engine::RuleEngine;

const DEFAULT_UPSTREAM: &str = "1.1.1.1:53";
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Runtime options for the UDP DNS server.
#[derive(Clone, Debug)]
pub struct ServerOptions {
    /// UDP socket address the server binds to.
    pub listen_addr: SocketAddr,
    /// UDP socket address of the upstream resolver.
    pub upstream_addr: SocketAddr,
    /// Enables or disables response caching.
    pub cache_enabled: bool,
    /// Enables or disables per-query logging.
    pub log_queries: bool,
    /// Lifetime for cached upstream responses.
    pub cache_ttl: Duration,
}

struct QueryContext {
    upstream: Arc<Upstream>,
    cache: Arc<ResponseCache>,
    cache_enabled: bool,
    log_queries: bool,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:5353"
                .parse()
                .expect("default listen address must be valid"),
            upstream_addr: DEFAULT_UPSTREAM
                .parse()
                .expect("default upstream address must be valid"),
            cache_enabled: true,
            log_queries: true,
            cache_ttl: CACHE_TTL,
        }
    }
}

/// Runs the UDP DNS server with default options.
pub async fn run_server(addr: &str, rules: Arc<RuleEngine>) -> anyhow::Result<()> {
    let options = ServerOptions {
        listen_addr: addr.parse()?,
        ..ServerOptions::default()
    };

    run_server_with_options(options, rules).await
}

/// Runs the UDP DNS server with explicit runtime options.
pub async fn run_server_with_options(
    options: ServerOptions,
    rules: Arc<RuleEngine>,
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(options.listen_addr).await?);
    let context = Arc::new(QueryContext {
        upstream: Arc::new(Upstream::new(options.upstream_addr)),
        cache: Arc::new(ResponseCache::new(options.cache_ttl)),
        cache_enabled: options.cache_enabled,
        log_queries: options.log_queries,
    });
    tracing::info!("DNS server listening on {}", options.listen_addr);
    tracing::info!("Forwarding allowed queries to {}", options.upstream_addr);

    loop {
        let mut buf = vec![0; 512];
        let (n, peer_addr) = socket.recv_from(&mut buf).await?;

        let rules = Arc::clone(&rules);
        let socket = Arc::clone(&socket);
        let context = Arc::clone(&context);

        tokio::spawn(async move {
            if let Err(e) = handle_query(&buf[..n], &rules, &socket, peer_addr, &context).await {
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
    context: &QueryContext,
) -> anyhow::Result<()> {
    let req = Message::from_bytes(buf)?;

    if should_block(&req, rules, context.log_queries) {
        let response_bytes = blocked_response(&req).to_bytes()?;
        socket.send_to(&response_bytes, peer_addr).await?;
        return Ok(());
    }

    if context.cache_enabled {
        if let Some(cached) = context.cache.get(&req)? {
            tracing::debug!("Cache hit for query id {}", req.id());
            socket.send_to(&cached, peer_addr).await?;
            return Ok(());
        }
    }

    let response = context.upstream.forward(buf).await?;
    if context.cache_enabled {
        context.cache.insert(&req, response.clone());
    }
    socket.send_to(&response, peer_addr).await?;

    Ok(())
}

fn should_block(req: &Message, rules: &RuleEngine, log_queries: bool) -> bool {
    req.queries().iter().any(|query| {
        let domain = query.name().to_utf8();
        if log_queries {
            tracing::debug!("Query: {}", domain);
        }

        if rules.is_blocked(&domain) {
            if log_queries {
                tracing::info!("BLOCKED: {}", domain);
            }
            true
        } else {
            if log_queries {
                tracing::debug!("ALLOWED: {}", domain);
            }
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
