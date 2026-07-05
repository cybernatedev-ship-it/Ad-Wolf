use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::Router;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

#[derive(Debug, Clone, Hash, PartialEq, Eq, prometheus_client::encoding::EncodeLabelSet)]
pub struct QueryLabels {
    pub action: String,
}

/// Shared Prometheus metrics collection
pub struct Metrics {
    registry: Registry,
    pub queries_total: Family<QueryLabels, Counter>,
    pub query_duration_ms: Histogram,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::default();
        let queries_total = Family::<QueryLabels, Counter>::default();
        registry.register(
            "dns_queries_total",
            "Total DNS queries by action",
            queries_total.clone(),
        );
        let query_duration_ms = Histogram::new(
            prometheus_client::metrics::histogram::exponential_buckets(1.0, 2.0, 10),
        );
        registry.register(
            "dns_query_duration_ms",
            "DNS query duration in milliseconds",
            query_duration_ms.clone(),
        );
        let cache_hits = Counter::default();
        registry.register(
            "dns_cache_hits_total",
            "Total cache hits",
            cache_hits.clone(),
        );
        let cache_misses = Counter::default();
        registry.register(
            "dns_cache_misses_total",
            "Total cache misses",
            cache_misses.clone(),
        );
        Self {
            registry,
            queries_total,
            query_duration_ms,
            cache_hits,
            cache_misses,
        }
    }
}

/// Serve the Prometheus metrics endpoint on `addr`
pub async fn serve_metrics(addr: SocketAddr, metrics: Arc<Metrics>) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(metrics);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Metrics HTTP endpoint listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn metrics_handler(State(metrics): State<Arc<Metrics>>) -> String {
    let mut buf = String::new();
    encode(&mut buf, &metrics.registry).unwrap();
    buf
}
