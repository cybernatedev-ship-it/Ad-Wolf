#![doc = include_str!("../README.md")]

use std::sync::Arc;

use dns_filter_config::Config;
use dns_filter_dns::run_server;
use dns_filter_filter::loader;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Load configuration
    let config = Config::default();
    tracing::info!("DNS Filter starting with config: {:?}", config);

    // Load rules from lists/
    let rules = Arc::new(loader::load_rules("lists")?);
    tracing::info!("Loaded {} matchers from rules", rules.matcher_count());

    // Start DNS server
    run_server(&config.listen, rules).await?;

    Ok(())
}
