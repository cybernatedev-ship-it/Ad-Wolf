use std::sync::Arc;
use tokio::net::UdpSocket;
use trust_dns_proto::op::{Message, ResponseCode};
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

use crate::rules::engine::RuleEngine;

pub async fn run_server(addr: &str, rules: Arc<RuleEngine>) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    tracing::info!("DNS server listening on {}", addr);

    loop {
        let mut buf = vec![0; 512];
        let (n, peer_addr) = socket.recv_from(&mut buf).await?;

        let rules = Arc::clone(&rules);
        let socket = Arc::clone(&socket);

        tokio::spawn(async move {
            if let Err(e) = handle_query(&buf[..n], &*rules, &*socket, peer_addr).await {
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
) -> anyhow::Result<()> {
    let req = Message::from_bytes(buf)?;
    let mut resp = Message::new();
    resp.set_id(req.id());
    resp.set_recursion_available(true);

    if let Some(query) = req.queries().first() {
        let domain = query.name().to_utf8();
        tracing::debug!("Query: {}", domain);

        if rules.is_blocked(&domain) {
            tracing::info!("BLOCKED: {}", domain);
            resp.set_response_code(ResponseCode::NXDOMAIN);
        } else {
            tracing::debug!("ALLOWED: {}", domain);
            resp.set_response_code(ResponseCode::NoError);
        }

        resp.add_query(query.clone());
    }

    let response_bytes = resp.to_bytes()?;
    socket.send_to(&response_bytes, peer_addr).await?;

    Ok(())
}
