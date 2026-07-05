#![doc = include_str!("../README.md")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use clap::Parser;
use dns_filter_cache::ResponseCache;
use dns_filter_config::Config;
use dns_filter_dns::DnsServer;
use dns_filter_filter::loader;
use dns_filter_filter::RuleEngine;
use dns_filter_storage::QueryStore;
use dns_filter_upstream::{UpstreamConfig, UpstreamManager};
use notify::{Event, EventKind, RecursiveMode, Watcher};
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

const LIST_UPDATE_INTERVAL: Duration = Duration::from_secs(6 * 3600);

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

    /// Path to query log database
    #[arg(short = 'd', long = "db")]
    storage_path: Option<String>,

    /// Prometheus metrics listen address (overrides config)
    #[arg(short = 'm', long = "metrics-addr")]
    metrics_addr: Option<String>,
}

/// Download a single rule list from a URL to a destination path
async fn download_list(
    client: &reqwest::Client,
    url: &str,
    dest: &std::path::Path,
) -> anyhow::Result<()> {
    let resp = client
        .get(url)
        .timeout(Duration::from_secs(30))
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("HTTP {}", resp.status());
    }
    let content = resp.text().await?;
    tokio::fs::write(dest, &content).await?;
    tracing::info!("Downloaded list from {} ({} bytes)", url, content.len());
    Ok(())
}

/// Download all enabled URL-based rule lists to the rules directory
async fn update_lists(config: &Config, dest_dir: &std::path::Path) {
    tokio::fs::create_dir_all(dest_dir).await.ok();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .use_rustls_tls()
        .build()
        .unwrap();

    for list in &config.lists {
        if !list.enabled {
            continue;
        }
        if list.path.starts_with("http://") || list.path.starts_with("https://") {
            let dest = dest_dir.join(format!("{}.txt", list.name));
            tracing::info!("Downloading list '{}' from {}", list.name, list.path);
            if let Err(e) = download_list(&client, &list.path, &dest).await {
                tracing::warn!("Failed to download list '{}': {}", list.name, e);
            }
        }
    }
}

/// Periodically update all rule lists
async fn periodic_updates(config: Config, dest_dir: PathBuf) {
    loop {
        tokio::time::sleep(LIST_UPDATE_INTERVAL).await;
        tracing::info!("Periodic list update starting...");
        update_lists(&config, &dest_dir).await;
    }
}

/// Reload rules from disk and atomically swap them
fn reload_rules(rules: &ArcSwap<RuleEngine>, dir: &std::path::Path) {
    match loader::load_rules(dir) {
        Ok(new_engine) => {
            let count = new_engine.total_rule_count();
            let matchers = new_engine.matcher_count();
            rules.store(Arc::new(new_engine));
            tracing::info!("Reloaded {} rules across {} matchers", count, matchers);
        }
        Err(e) => {
            tracing::error!("Failed to reload rules: {}", e);
        }
    }
}

/// Run the file watcher for hot reload
async fn watch_rules(rules: Arc<ArcSwap<RuleEngine>>, dir: PathBuf) -> anyhow::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            if matches!(
                event.kind,
                EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
            ) {
                let _ = tx.blocking_send(());
            }
        }
    })?;

    watcher.watch(&dir, RecursiveMode::NonRecursive)?;
    tracing::info!("Watching rules directory: {}", dir.display());

    while rx.recv().await.is_some() {
        tracing::info!("Rules directory changed, reloading...");
        reload_rules(&rules, &dir);
    }

    Ok(())
}

/// Run the SIGHUP signal handler for hot reload (Unix only)
#[cfg(unix)]
async fn watch_sighup(rules: Arc<ArcSwap<RuleEngine>>, dir: PathBuf) -> anyhow::Result<()> {
    let mut sig = signal(SignalKind::hangup())?;
    loop {
        sig.recv().await;
        tracing::info!("Received SIGHUP, reloading rules...");
        reload_rules(&rules, &dir);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let config = Config::load(args.config.as_deref());

    // Apply CLI overrides
    let listen = args.listen.unwrap_or(config.listen.clone());
    let rules_dir: PathBuf = args.rules_dir.unwrap_or(config.lists_dir.clone()).into();

    tracing::info!(
        "DNS Filter starting — listen: {}, rules: {}",
        listen,
        rules_dir.display()
    );

    // Build upstream resolver from config
    let upstream = {
        let configs: Vec<UpstreamConfig> = if config.upstream.is_empty() {
            vec![UpstreamConfig::new(
                dns_filter_upstream::Protocol::Udp,
                "1.1.1.1:53",
            )]
        } else {
            config
                .upstream
                .iter()
                .filter_map(|u| {
                    let protocol = dns_filter_upstream::Protocol::parse(&u.protocol)?;
                    Some(UpstreamConfig::new(protocol, u.address.clone()))
                })
                .collect()
        };
        if configs.is_empty() {
            anyhow::bail!("no valid upstream resolvers configured");
        }
        Arc::new(UpstreamManager::new(configs))
    };

    // Build cache
    let cache_ttl = if config.cache {
        std::time::Duration::from_secs(config.cache_ttl)
    } else {
        std::time::Duration::from_secs(0)
    };
    let cache = Arc::new(ResponseCache::new(cache_ttl));

    // Stats
    let stats = Arc::new(dns_filter_core::QueryLogger::new());

    // Open query log store
    let store_path = args.storage_path.or_else(|| config.storage_path.clone());
    let store = match &store_path {
        Some(path) => {
            tracing::info!("Opening query log database: {}", path);
            let db = QueryStore::open(path)?;
            if config.prune_days > 0 {
                let cutoff = std::time::Duration::from_secs(config.prune_days * 86400);
                match db.prune(cutoff) {
                    Ok(deleted) => tracing::info!("Pruned {} old query log entries", deleted),
                    Err(e) => tracing::warn!("Failed to prune query log: {}", e),
                }
            }
            Arc::new(db)
        }
        None => {
            tracing::info!("Using in-memory query log (no --db path given)");
            Arc::new(QueryStore::in_memory()?)
        }
    };

    // Start Prometheus metrics endpoint
    let metrics_addr = args
        .metrics_addr
        .clone()
        .unwrap_or_else(|| config.metrics_addr.clone());
    let metrics: Option<Arc<dns_filter_metrics::Metrics>> = if !metrics_addr.is_empty() {
        let m = Arc::new(dns_filter_metrics::Metrics::default());
        let metrics_clone = Arc::clone(&m);
        let addr = metrics_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = dns_filter_metrics::serve_metrics(
                addr.parse().expect("invalid metrics address"),
                metrics_clone,
            )
            .await
            {
                tracing::error!("Metrics server error: {}", e);
            }
        });
        tracing::info!(
            "Prometheus metrics enabled on http://{}/metrics",
            metrics_addr
        );
        Some(m)
    } else {
        None
    };

    // Download remote rule lists
    if !config.lists.is_empty() {
        update_lists(&config, &rules_dir).await;
    }

    // Load rules into hot-swappable ArcSwap
    let rules = Arc::new(ArcSwap::new(Arc::new(loader::load_rules(&rules_dir)?)));
    {
        let r = rules.load();
        tracing::info!(
            "Loaded {} rules across {} matchers",
            r.total_rule_count(),
            r.matcher_count()
        );
    }

    // Spawn periodic list updater
    if !config.lists.is_empty() {
        let update_config = config.clone();
        let update_dir = rules_dir.clone();
        tokio::spawn(async move {
            periodic_updates(update_config, update_dir).await;
        });
    }

    // Spawn hot-reload tasks
    let watch_dir = rules_dir.clone();
    let rules_watcher = Arc::clone(&rules);
    tokio::spawn(async move {
        if let Err(e) = watch_rules(rules_watcher, watch_dir).await {
            tracing::error!("File watcher error: {}", e);
        }
    });

    #[cfg(unix)]
    {
        let sighup_dir = rules_dir.clone();
        let rules_sighup = Arc::clone(&rules);
        tokio::spawn(async move {
            if let Err(e) = watch_sighup(rules_sighup, sighup_dir).await {
                tracing::error!("SIGHUP handler error: {}", e);
            }
        });
    }

    // Build and run server
    let server = DnsServer {
        listen,
        rules,
        cache,
        upstream,
        stats,
        store,
        metrics,
        log_queries: config.log_queries,
    };

    let mut server_handle = tokio::spawn(dns_filter_dns::run_server(server));

    // Wait for shutdown signal
    let ctrl_c = tokio::signal::ctrl_c();
    let term = shutdown_signal();
    tokio::pin!(term);

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl+C, shutting down..."),
        _ = &mut term => tracing::info!("Received SIGTERM, shutting down..."),
        result = &mut server_handle => result??,
    }

    tracing::info!("Shutdown complete.");
    Ok(())
}

/// Return a future that resolves on SIGTERM (Unix), or never resolves on other platforms
fn shutdown_signal() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    #[cfg(unix)]
    {
        let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        Box::pin(async move {
            sig.recv().await;
        })
    }
    #[cfg(not(unix))]
    {
        Box::pin(std::future::pending())
    }
}
