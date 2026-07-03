mod dns;
mod rules;

use std::sync::Arc;
use tracing_subscriber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Load rules from lists/
    let rules = Arc::new(rules::loader::load_rules("lists").await?);
    tracing::info!("Loaded rules with {} domains", rules.count());

    // Start DNS server
    dns::server::run_server("127.0.0.1:5353", rules).await?;

    Ok(())
}
