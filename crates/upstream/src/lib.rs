//! Upstream resolver handling

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// An upstream DNS resolver
#[derive(Clone, Debug)]
pub struct Upstream {
    server: SocketAddr,
}

impl Upstream {
    /// Create a new upstream resolver
    pub fn new(server: SocketAddr) -> Self {
        Self { server }
    }

    /// Forward a DNS query to the upstream resolver
    pub async fn forward(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(query, self.server).await?;

        let mut buf = vec![0; 4096];
        let (len, _) = timeout(UPSTREAM_TIMEOUT, socket.recv_from(&mut buf)).await??;
        buf.truncate(len);
        Ok(buf)
    }
}
