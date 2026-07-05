//! DNS response caching layer

use std::time::{Duration, Instant};

use dashmap::DashMap;
use trust_dns_proto::op::Message;
use trust_dns_proto::serialize::binary::{BinDecodable, BinEncodable};

/// A cached DNS response with TTL
#[derive(Debug)]
struct CacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
}

/// DNS response cache with TTL-based eviction
#[derive(Debug)]
pub struct ResponseCache {
    entries: DashMap<Vec<u8>, CacheEntry>,
    ttl: Duration,
}

impl ResponseCache {
    /// Create a new response cache with the given TTL
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            ttl,
        }
    }

    /// Try to get a cached response for a DNS request
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

    /// Insert a response into the cache
    pub fn insert(&self, request: &Message, response: Vec<u8>) {
        self.entries.insert(
            cache_key(request),
            CacheEntry {
                response,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    /// Get the number of cached entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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

#[cfg(test)]
mod tests {
    use super::*;
    use trust_dns_proto::op::{Message, MessageType, Query, ResponseCode};
    use trust_dns_proto::rr::record_type::RecordType;
    use trust_dns_proto::rr::Name;
    use trust_dns_proto::serialize::binary::BinEncodable;

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

    fn create_response(req: &Message) -> Message {
        let mut resp = Message::new();
        resp.set_id(req.id());
        resp.set_message_type(MessageType::Response);
        resp.set_response_code(ResponseCode::NXDomain);
        for query in req.queries() {
            resp.add_query(query.clone());
        }
        resp
    }

    #[test]
    fn test_cache_empty() {
        let cache = ResponseCache::new(Duration::from_secs(300));
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_insert_and_get() {
        let cache = ResponseCache::new(Duration::from_secs(300));
        let req = create_query("example.com");
        let resp = create_response(&req);
        let resp_bytes = resp.to_bytes().unwrap();

        cache.insert(&req, resp_bytes);
        assert_eq!(cache.len(), 1);

        let cached = cache.get(&req).unwrap();
        assert!(cached.is_some());
        let parsed = Message::from_bytes(&cached.unwrap()).unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::NXDomain);
    }

    #[test]
    fn test_cache_miss() {
        let cache = ResponseCache::new(Duration::from_secs(300));
        let req = create_query("example.com");
        assert!(cache.get(&req).unwrap().is_none());
    }

    #[test]
    fn test_cache_id_masking() {
        let cache = ResponseCache::new(Duration::from_secs(300));
        let req = create_query("example.com");
        let resp = create_response(&req);
        cache.insert(&req, resp.to_bytes().unwrap());

        let mut req2 = create_query("example.com");
        req2.set_id(999);
        let cached = cache.get(&req2).unwrap();
        assert!(cached.is_some());
        let parsed = Message::from_bytes(&cached.unwrap()).unwrap();
        assert_eq!(parsed.id(), 999);
    }

    #[test]
    fn test_cache_multiple_queries() {
        let cache = ResponseCache::new(Duration::from_secs(300));
        let req1 = create_query("example.com");
        let req2 = create_query("other.com");
        let resp1 = create_response(&req1);
        let resp2 = create_response(&req2);

        cache.insert(&req1, resp1.to_bytes().unwrap());
        cache.insert(&req2, resp2.to_bytes().unwrap());
        assert_eq!(cache.len(), 2);

        assert!(cache.get(&req1).unwrap().is_some());
        assert!(cache.get(&req2).unwrap().is_some());
    }

    #[test]
    fn test_cache_overwrite() {
        let cache = ResponseCache::new(Duration::from_secs(300));
        let req = create_query("example.com");
        let resp = create_response(&req);

        cache.insert(&req, resp.to_bytes().unwrap());
        cache.insert(&req, resp.to_bytes().unwrap());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_expiry() {
        let cache = ResponseCache::new(Duration::from_secs(0));
        let req = create_query("example.com");
        let resp = create_response(&req);
        cache.insert(&req, resp.to_bytes().unwrap());
        assert!(cache.get(&req).unwrap().is_none());
        assert_eq!(cache.len(), 0);
    }
}
