//! DNS server and protocol handling

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_proto::op::{Message, MessageType, ResponseCode};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

use dns_filter_cache::ResponseCache;
use dns_filter_filter::RuleEngine;
use dns_filter_metrics::{Metrics, QueryLabels};
use dns_filter_storage::{QueryAction, QueryStore};
use dns_filter_upstream::UpstreamManager;

const MAX_UDP_PACKET: usize = 4096;
const MAX_TCP_MESSAGE: u16 = 65535;

/// DNS server configuration
pub struct DnsServer {
    /// Listening address (e.g., "127.0.0.1:53")
    pub listen: String,
    /// Rule engine for filtering (hot-swappable)
    pub rules: Arc<ArcSwap<RuleEngine>>,
    /// DNS response cache
    pub cache: Arc<ResponseCache>,
    /// Upstream resolver
    pub upstream: Arc<UpstreamManager>,
    /// Query statistics logger
    pub stats: Arc<dns_filter_core::QueryLogger>,
    /// Persistent query log store
    pub store: Arc<QueryStore>,
    /// Optional Prometheus metrics
    pub metrics: Option<Arc<Metrics>>,
    /// Enable query logging to the store
    pub log_queries: bool,
}

/// Run the DNS server on both UDP and TCP
pub async fn run_server(server: DnsServer) -> anyhow::Result<()> {
    let addr = &server.listen;

    tracing::info!("DNS server listening on {} (UDP + TCP)", addr);

    let server_udp = DnsServer {
        listen: addr.clone(),
        rules: Arc::clone(&server.rules),
        cache: Arc::clone(&server.cache),
        upstream: Arc::clone(&server.upstream),
        stats: Arc::clone(&server.stats),
        store: Arc::clone(&server.store),
        metrics: server.metrics.clone(),
        log_queries: server.log_queries,
    };
    tokio::spawn(async move {
        if let Err(e) = run_udp_server(&server_udp).await {
            tracing::error!("UDP server error: {}", e);
        }
    });

    run_tcp_server(server).await?;

    Ok(())
}

/// Run UDP DNS server
async fn run_udp_server(server: &DnsServer) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(&server.listen).await?);
    tracing::info!("UDP server bound to {}", server.listen);

    loop {
        let mut buf = vec![0; MAX_UDP_PACKET];
        let (n, peer_addr) = socket.recv_from(&mut buf).await?;

        let server = DnsServer {
            listen: server.listen.clone(),
            rules: Arc::clone(&server.rules),
            cache: Arc::clone(&server.cache),
            upstream: Arc::clone(&server.upstream),
            stats: Arc::clone(&server.stats),
            store: Arc::clone(&server.store),
            metrics: server.metrics.clone(),
            log_queries: server.log_queries,
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
async fn run_tcp_server(server: DnsServer) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&server.listen).await?;
    tracing::info!("TCP server bound to {}", server.listen);

    loop {
        let (mut socket, _peer_addr) = listener.accept().await?;

        let server = DnsServer {
            listen: server.listen.clone(),
            rules: Arc::clone(&server.rules),
            cache: Arc::clone(&server.cache),
            upstream: Arc::clone(&server.upstream),
            stats: Arc::clone(&server.stats),
            store: Arc::clone(&server.store),
            metrics: server.metrics.clone(),
            log_queries: server.log_queries,
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
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }

    let response = match handle_dns_query(buf, server, Some(&peer_addr.ip().to_string())).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::debug!("DNS query error: {}", e);
            return Ok(());
        }
    };

    socket.send_to(&response, peer_addr).await?;
    Ok(())
}

/// Handle a TCP DNS client connection
async fn handle_tcp_client(
    socket: &mut tokio::net::TcpStream,
    server: &DnsServer,
) -> anyhow::Result<()> {
    let client_ip = socket.peer_addr().ok().map(|a| a.ip().to_string());
    loop {
        let mut len_buf = [0; 2];
        match socket.read_exact(&mut len_buf).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        let query_len = u16::from_be_bytes(len_buf) as usize;
        if query_len == 0 || query_len > MAX_TCP_MESSAGE as usize {
            tracing::warn!("Invalid TCP query length: {}", query_len);
            break;
        }

        let mut query_buf = vec![0; query_len];
        if let Err(e) = socket.read_exact(&mut query_buf).await {
            tracing::debug!("Failed to read TCP query body: {}", e);
            break;
        }

        match handle_dns_query(&query_buf, server, client_ip.as_deref()).await {
            Ok(response) => {
                let response_len = (response.len() as u16).to_be_bytes();
                if let Err(e) = socket.write_all(&response_len).await {
                    tracing::debug!("Failed to write TCP response length: {}", e);
                    break;
                }
                if let Err(e) = socket.write_all(&response).await {
                    tracing::debug!("Failed to write TCP response body: {}", e);
                    break;
                }
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
    client_ip: Option<&str>,
) -> anyhow::Result<Vec<u8>> {
    let req = match Message::from_bytes(buf) {
        Ok(msg) => msg,
        Err(_) => {
            return Ok(formerr_response().to_bytes()?);
        }
    };

    if !is_valid_query(&req) {
        return Ok(formerr_response().to_bytes()?);
    }

    let domain = req
        .queries()
        .first()
        .map(|q| domain_from_name(q.name()))
        .unwrap_or_default();
    let query_type = req
        .queries()
        .first()
        .map(|q| format!("{}", q.query_type()))
        .unwrap_or_default();

    let rules = server.rules.load();
    if should_block(&req, &rules) {
        for query in req.queries() {
            server.stats.record_blocked(&domain_from_name(query.name()));
        }
        if server.log_queries {
            let _ =
                server
                    .store
                    .log_query(&domain, &query_type, QueryAction::Blocked, None, client_ip);
        }
        if let Some(ref m) = server.metrics {
            m.queries_total
                .get_or_create(&QueryLabels {
                    action: "blocked".into(),
                })
                .inc();
        }
        let response_bytes = blocked_response(&req).to_bytes()?;
        return Ok(response_bytes);
    }
    drop(rules);

    if let Some(cached) = server.cache.get(&req)? {
        server.stats.record_cache_hit();
        if server.log_queries {
            let _ =
                server
                    .store
                    .log_query(&domain, &query_type, QueryAction::Cached, None, client_ip);
        }
        if let Some(ref m) = server.metrics {
            m.cache_hits.inc();
            m.queries_total
                .get_or_create(&QueryLabels {
                    action: "cached".into(),
                })
                .inc();
        }
        return Ok(cached);
    }

    server.stats.record_cache_miss();
    if let Some(ref m) = server.metrics {
        m.cache_misses.inc();
    }

    let start = std::time::Instant::now();
    match server.upstream.forward(buf).await {
        Ok(response) => {
            let elapsed = start.elapsed().as_millis() as u64;
            server.cache.insert(&req, response.clone());
            server.stats.record_allowed();
            if server.log_queries {
                let _ = server.store.log_query(
                    &domain,
                    &query_type,
                    QueryAction::Allowed,
                    Some(elapsed),
                    client_ip,
                );
            }
            if let Some(ref m) = server.metrics {
                m.queries_total
                    .get_or_create(&QueryLabels {
                        action: "allowed".into(),
                    })
                    .inc();
                m.query_duration_ms.observe(elapsed as f64);
            }
            Ok(response)
        }
        Err(e) => {
            tracing::debug!("Upstream error: {}", e);
            if server.log_queries {
                let _ = server.store.log_query(
                    &domain,
                    &query_type,
                    QueryAction::Error,
                    None,
                    client_ip,
                );
            }
            if let Some(ref m) = server.metrics {
                m.queries_total
                    .get_or_create(&QueryLabels {
                        action: "error".into(),
                    })
                    .inc();
            }
            Ok(servfail_response(&req).to_bytes()?)
        }
    }
}

/// Extract domain from a DNS query name, stripping trailing dot (FQDN)
fn domain_from_name(name: &trust_dns_proto::rr::Name) -> String {
    let s = name.to_utf8();
    s.strip_suffix('.').unwrap_or(&s).to_string()
}

/// Validate a DNS query message
fn is_valid_query(req: &Message) -> bool {
    if req.message_type() != MessageType::Query {
        return false;
    }
    if req.queries().is_empty() {
        return false;
    }
    true
}

/// Check if a DNS message should be blocked
pub fn should_block(req: &Message, rules: &RuleEngine) -> bool {
    req.queries().iter().any(|query| {
        let domain = domain_from_name(query.name());
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

/// Create a blocked (NXDOMAIN) response
pub fn blocked_response(req: &Message) -> Message {
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

/// Create a SERVFAIL response for upstream failures
pub fn servfail_response(req: &Message) -> Message {
    let mut resp = Message::new();
    resp.set_id(req.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(req.op_code());
    resp.set_recursion_desired(req.recursion_desired());
    resp.set_recursion_available(true);
    resp.set_response_code(ResponseCode::ServFail);

    for query in req.queries() {
        resp.add_query(query.clone());
    }

    resp
}

/// Create a FORMERR response for malformed queries
pub fn formerr_response() -> Message {
    let mut resp = Message::new();
    resp.set_id(0);
    resp.set_message_type(MessageType::Response);
    resp.set_recursion_available(true);
    resp.set_response_code(ResponseCode::FormErr);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_filter_core::ExactMatcher;
    use dns_filter_filter::ExceptionMatcher;
    use dns_filter_storage::QueryStore;
    use std::time::Duration;
    use trust_dns_proto::op::Query;
    use trust_dns_proto::rr::record_type::RecordType;
    use trust_dns_proto::rr::Name;

    fn create_query(domain: &str) -> Message {
        let mut msg = Message::new();
        msg.set_id(42);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(trust_dns_proto::op::OpCode::Query);
        msg.set_recursion_desired(true);

        let mut query = Query::new();
        query.set_name(Name::from_ascii(domain).unwrap());
        query.set_query_type(RecordType::A);
        msg.add_query(query);

        msg
    }

    fn test_server() -> DnsServer {
        let rules = Arc::new(ArcSwap::new(Arc::new(RuleEngine::new(
            Arc::new(ExceptionMatcher::new()),
            vec![(
                "exact".to_string(),
                Arc::new(ExactMatcher::new(vec![
                    "ads.example.com".to_string(),
                    "tracker.example.com".to_string(),
                ])) as Arc<dyn dns_filter_core::Matcher>,
            )],
        ))));
        let cache = Arc::new(ResponseCache::new(Duration::from_secs(300)));
        let upstream = Arc::new(UpstreamManager::new(vec![
            dns_filter_upstream::UpstreamConfig::new(
                dns_filter_upstream::Protocol::Udp,
                "1.1.1.1:53",
            ),
        ]));
        let stats = Arc::new(dns_filter_core::QueryLogger::new());
        let store = Arc::new(QueryStore::in_memory().unwrap());

        DnsServer {
            listen: "127.0.0.1:0".to_string(),
            rules,
            cache,
            upstream,
            stats,
            store,
            metrics: None,
            log_queries: false,
        }
    }

    // blocked_response tests

    #[test]
    fn test_blocked_response_creates_nxdomain() {
        let req = create_query("ads.example.com");
        let resp = blocked_response(&req);
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
    }

    #[test]
    fn test_blocked_response_preserves_id() {
        let req = create_query("ads.example.com");
        assert_eq!(req.id(), 42);
        let resp = blocked_response(&req);
        assert_eq!(resp.id(), 42);
    }

    #[test]
    fn test_blocked_response_is_response() {
        let req = create_query("ads.example.com");
        let resp = blocked_response(&req);
        assert_eq!(resp.message_type(), MessageType::Response);
    }

    #[test]
    fn test_blocked_response_preserves_query() {
        let req = create_query("example.com");
        let resp = blocked_response(&req);
        assert_eq!(resp.queries().len(), 1);
        let domain = resp.queries().first().unwrap().name().to_utf8();
        assert!(domain == "example.com" || domain == "example.com.");
    }

    #[test]
    fn test_blocked_response_sets_ra() {
        let req = create_query("ads.example.com");
        let resp = blocked_response(&req);
        assert!(resp.recursion_available());
    }

    #[test]
    fn test_blocked_response_preserves_opcode() {
        let req = create_query("ads.example.com");
        let resp = blocked_response(&req);
        assert_eq!(resp.op_code(), trust_dns_proto::op::OpCode::Query);
    }

    #[test]
    fn test_blocked_response_serializes() {
        let req = create_query("ads.example.com");
        let resp = blocked_response(&req);
        let bytes = resp.to_bytes().unwrap();
        assert!(!bytes.is_empty());
        let parsed = Message::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::NXDomain);
    }

    // should_block tests

    #[test]
    fn test_should_block_returns_true_for_blocked_domain() {
        let rules = Arc::new(RuleEngine::new(
            Arc::new(ExceptionMatcher::new()),
            vec![(
                "exact".to_string(),
                Arc::new(ExactMatcher::new(vec!["ads.example.com".to_string()]))
                    as Arc<dyn dns_filter_core::Matcher>,
            )],
        ));
        let req = create_query("ads.example.com");
        assert!(should_block(&req, &rules));
    }

    #[test]
    fn test_should_block_returns_false_for_allowed_domain() {
        let rules = Arc::new(RuleEngine::new(
            Arc::new(ExceptionMatcher::new()),
            vec![(
                "exact".to_string(),
                Arc::new(ExactMatcher::new(vec!["ads.example.com".to_string()]))
                    as Arc<dyn dns_filter_core::Matcher>,
            )],
        ));
        let req = create_query("safe.example.com");
        assert!(!should_block(&req, &rules));
    }

    #[test]
    fn test_should_block_matches_any_query() {
        let rules = Arc::new(RuleEngine::new(
            Arc::new(ExceptionMatcher::new()),
            vec![(
                "exact".to_string(),
                Arc::new(ExactMatcher::new(vec!["blocked.com".to_string()]))
                    as Arc<dyn dns_filter_core::Matcher>,
            )],
        ));

        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Query);

        let mut q1 = Query::new();
        q1.set_name(Name::from_ascii("allowed.com").unwrap());
        q1.set_query_type(RecordType::A);
        msg.add_query(q1);

        let mut q2 = Query::new();
        q2.set_name(Name::from_ascii("blocked.com").unwrap());
        q2.set_query_type(RecordType::AAAA);
        msg.add_query(q2);

        assert!(should_block(&msg, &rules));
    }

    // is_valid_query tests

    #[test]
    fn test_is_valid_query_accepts_query() {
        let req = create_query("example.com");
        assert!(is_valid_query(&req));
    }

    #[test]
    fn test_is_valid_query_rejects_response() {
        let req = create_query("example.com");
        let resp = blocked_response(&req);
        assert!(!is_valid_query(&resp));
    }

    #[test]
    fn test_is_valid_query_rejects_empty_queries() {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Query);
        assert!(!is_valid_query(&msg));
    }

    // formerr_response tests

    #[test]
    fn test_formerr_response() {
        let resp = formerr_response();
        assert_eq!(resp.message_type(), MessageType::Response);
        assert_eq!(resp.response_code(), ResponseCode::FormErr);
        assert!(resp.recursion_available());
    }

    // servfail_response tests

    #[test]
    fn test_servfail_response() {
        let req = create_query("example.com");
        let resp = servfail_response(&req);
        assert_eq!(resp.message_type(), MessageType::Response);
        assert_eq!(resp.response_code(), ResponseCode::ServFail);
        assert_eq!(resp.id(), 42);
        assert_eq!(resp.queries().len(), 1);
    }

    // handle_dns_query tests (synchronous part, no real I/O)

    #[tokio::test]
    async fn test_handle_dns_query_blocks_filtered_domain() {
        let server = test_server();
        let req = create_query("ads.example.com");
        let bytes = req.to_bytes().unwrap();
        let response = handle_dns_query(&bytes, &server, None).await.unwrap();
        let parsed = Message::from_bytes(&response).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn test_handle_dns_query_allows_unfiltered() {
        let server = test_server();
        let req = create_query("example.com");
        let bytes = req.to_bytes().unwrap();
        let response = handle_dns_query(&bytes, &server, None).await.unwrap();
        let parsed = Message::from_bytes(&response).unwrap();
        assert_eq!(parsed.message_type(), MessageType::Response);
        assert_ne!(parsed.response_code(), ResponseCode::FormErr);
        assert_eq!(parsed.id(), 42);
    }

    #[tokio::test]
    async fn test_handle_dns_query_formerr_on_garbage() {
        let server = test_server();
        let garbage = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let response = handle_dns_query(&garbage, &server, None).await.unwrap();
        let parsed = Message::from_bytes(&response).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::FormErr);
    }

    #[tokio::test]
    async fn test_handle_dns_query_formerr_on_empty() {
        let server = test_server();
        let response = handle_dns_query(&[], &server, None).await.unwrap();
        let parsed = Message::from_bytes(&response).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::FormErr);
    }

    #[tokio::test]
    async fn test_handle_dns_query_formerr_on_response() {
        let server = test_server();
        let req = create_query("example.com");
        let resp = blocked_response(&req);
        let bytes = resp.to_bytes().unwrap();
        let response = handle_dns_query(&bytes, &server, None).await.unwrap();
        let parsed = Message::from_bytes(&response).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::FormErr);
    }

    #[tokio::test]
    async fn test_handle_dns_query_formerr_on_no_question() {
        let server = test_server();
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Query);
        let bytes = msg.to_bytes().unwrap();
        let response = handle_dns_query(&bytes, &server, None).await.unwrap();
        let parsed = Message::from_bytes(&response).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::FormErr);
    }

    // Edge cases

    #[test]
    fn test_blocked_response_no_queries() {
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Query);
        let resp = blocked_response(&msg);
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
        assert_eq!(resp.queries().len(), 0);
    }

    #[test]
    fn test_should_block_empty_rules() {
        let rules = Arc::new(RuleEngine::new(
            Arc::new(ExceptionMatcher::new()),
            Vec::new(),
        ));
        let req = create_query("example.com");
        assert!(!should_block(&req, &rules));
    }
}
