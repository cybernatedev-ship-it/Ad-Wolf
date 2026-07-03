use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct Upstream {
    server: SocketAddr,
}

impl Upstream {
    pub fn new(server: SocketAddr) -> Self {
        Self { server }
    }

    pub async fn forward(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(query, self.server).await?;

        let mut buf = vec![0; 4096];
        let (len, _) = timeout(UPSTREAM_TIMEOUT, socket.recv_from(&mut buf)).await??;
        buf.truncate(len);
        Ok(buf)
    }
}
