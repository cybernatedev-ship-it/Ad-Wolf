use std::{fs, path::Path};

use anyhow::Result;

use crate::filter::{engine::RuleEngine, parser::parse_line};

pub async fn load_rules<P: AsRef<Path>>(dir: P) -> Result<RuleEngine> {
    let mut domains = Vec::new();

    // Try to read directory, but don't fail if it doesn't exist yet
    let entries = match fs::read_dir(dir.as_ref()) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                "Rules directory {} not found, starting with empty rules",
                dir.as_ref().display()
            );
            return Ok(RuleEngine::new(vec![]));
        }
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) != Some("txt") {
            continue;
        }

        let contents = fs::read_to_string(path)?;

        for line in contents.lines() {
            if let Some(rule) = parse_line(line) {
                domains.push(rule.to_ascii_lowercase());
            }
        }
    }

    Ok(RuleEngine::new(domains))
}
