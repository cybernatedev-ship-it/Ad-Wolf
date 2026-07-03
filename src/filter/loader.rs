use std::{fs, path::Path};

use anyhow::Result;

use crate::rules::{
    engine::RuleEngine,
    parser::parse_rule,
};

pub async fn load_rules<P: AsRef<Path>>(dir: P) -> Result<RuleEngine> {
    let mut domains = Vec::new();

<<<<<<< HEAD:src/filter/loader.rs
    // Try to read directory, but don't fail if it doesn't exist yet
    let mut entries = match fs::read_dir(path).await {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                "Rules directory {} not found, starting with empty rules",
                list_dir
            );
            return Ok(RuleEngine::new(vec![]));
        }
        Err(e) => return Err(e.into()),
    };

    while let Some(entry) = entries.next_entry().await? {
=======
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
>>>>>>> e9cac0d (Fix ResponseCode::NXDOMAIN to NXDomain):src/rules/loader.rs
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) != Some("txt") {
            continue;
        }

        let contents = fs::read_to_string(path)?;

        for line in contents.lines() {
            if let Some(rule) = parse_rule(line) {
                domains.push(rule.to_ascii_lowercase());
            }
        }
    }

    Ok(RuleEngine::new(domains))
}
