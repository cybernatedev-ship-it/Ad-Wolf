#![doc = include_str!("../README.md")]

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use dns_filter_cache::ResponseCache;
use dns_filter_config::Config;
use dns_filter_dns::DnsServer;
use dns_filter_filter::loader;
use dns_filter_upstream::Upstream;

/// Local DNS filtering daemon
#[derive(Parser, Debug)]
#[command(name = "dns-filter", about, version)]
struct Args {
    /// Path to configuration file
    #[arg(short = 'c', long = "config")]
    config: Option<String>,

    /// Listening address (overrides config file)
    #[arg(short = 'l', long = "listen")]
    listen: Option<String>,

    /// Rules directory (overrides config file)
    #[arg(short = 'r', long = "rules-dir")]
    rules_dir: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let config = Config::load(args.config.as_deref());

    // Apply CLI overrides
    let listen = args.listen.unwrap_or(config.listen);
    let rules_dir = args.rules_dir.unwrap_or(config.lists_dir);

    tracing::info!(
        "DNS Filter starting — listen: {}, rules: {}",
        listen,
        rules_dir
    );

    // Build upstream resolver from config
    let upstream_addr = config
        .upstream
        .first()
        .map(|u| u.address.parse::<SocketAddr>())
        .unwrap_or_else(|| Ok("1.1.1.1:53".parse().unwrap()))?;
    let upstream = Arc::new(Upstream::new(upstream_addr));

    // Build cache
    let cache_ttl = if config.cache {
        std::time::Duration::from_secs(config.cache_ttl)
    } else {
        std::time::Duration::from_secs(0)
    };
    let cache = Arc::new(ResponseCache::new(cache_ttl));

    // Stats
    let stats = Arc::new(dns_filter_core::QueryLogger::new());

    // Load rules
    let rules = Arc::new(loader::load_rules(&rules_dir)?);
    tracing::info!(
        "Loaded {} rules across {} matchers",
        rules.total_rule_count(),
        rules.matcher_count()
    );

    // Build and run server
    let server = DnsServer {
        listen,
        rules,
        cache,
        upstream,
        stats,
    };

    dns_filter_dns::run_server(server).await?;

    Ok(())
}
