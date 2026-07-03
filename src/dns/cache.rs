use std::time::{Duration, Instant};

use dashmap::DashMap;
use trust_dns_proto::op::Message;
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

#[derive(Debug)]
struct CacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
}

#[derive(Debug)]
pub struct ResponseCache {
    entries: DashMap<Vec<u8>, CacheEntry>,
    ttl: Duration,
}

impl ResponseCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            ttl,
        }
    }

    pub fn get(&self, request: &Message) -> anyhow::Result<Option<Vec<u8>>> {
        let key = cache_key(request);
        let Some(entry) = self.entries.get(&key) else {
            return Ok(None);
        };

        if Instant::now() >= entry.expires_at {
            drop(entry);
            self.entries.remove(&key);
            return Ok(None);
        }

        let mut response = Message::from_bytes(&entry.response)?;
        response.set_id(request.id());
        Ok(Some(response.to_bytes()?))
    }

    pub fn insert(&self, request: &Message, response: Vec<u8>) {
        self.entries.insert(
            cache_key(request),
            CacheEntry {
                response,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }
}

fn cache_key(request: &Message) -> Vec<u8> {
    let mut key = Vec::new();
    for query in request.queries() {
        key.extend_from_slice(query.name().to_utf8().to_ascii_lowercase().as_bytes());
        key.push(0);
        key.extend_from_slice(
            format!("{:?}:{:?}", query.query_type(), query.query_class()).as_bytes(),
        );
        key.push(0);
    }
    key
}
