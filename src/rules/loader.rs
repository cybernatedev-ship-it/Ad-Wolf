use std::path::Path;
use tokio::fs;

use super::engine::RuleEngine;
use super::parser::parse_line;

pub async fn load_rules(list_dir: &str) -> anyhow::Result<RuleEngine> {
    let path = Path::new(list_dir);
    let mut domains = Vec::new();

    // Try to read directory, but don't fail if it doesn't exist yet
    let mut entries = match fs::read_dir(path).await {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!("Rules directory {} not found, starting with empty rules", list_dir);
            return Ok(RuleEngine::new(vec![]));
        }
        Err(e) => return Err(e.into()),
    };

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("txt") {
            tracing::debug!("Loading rules from {}", path.display());
            load_file(&path, &mut domains).await?;
        }
    }

    tracing::info!("Loaded {} rules", domains.len());
    Ok(RuleEngine::new(domains))
}

async fn load_file(path: &Path, domains: &mut Vec<String>) -> anyhow::Result<()> {
    let content = fs::read_to_string(path).await?;
    for line in content.lines() {
        if let Some(domain) = parse_line(line) {
            domains.push(domain);
        }
    }
    Ok(())
}
