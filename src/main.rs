use std::sync::Arc;

use rust_dns_ad_filter::config::AppConfig;
use rust_dns_ad_filter::dns::server::{run_server_with_options, ServerOptions};
use rust_dns_ad_filter::filter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = AppConfig::load_or_default("config.toml").await?;

    // Load rules from lists/
    let rules = Arc::new(filter::loader::load_rules(&config.list_dir).await?);
    tracing::info!("Loaded rules with {} domains", rules.count());

    // Start DNS server
    run_server_with_options(
        ServerOptions {
            listen_addr: config.listen_addr()?,
            upstream_addr: config.first_udp_upstream_addr()?,
            cache_enabled: config.cache,
            log_queries: config.log_queries,
            cache_ttl: config.cache_ttl(),
        },
        rules,
    )
    .await?;

    Ok(())
}
