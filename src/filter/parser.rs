/// Parse a single line from a rules file.
///
/// Supports:
/// - Plain domains: `ads.example.com`
/// - uBlock-style rules: `||ads.example.com^`
/// - Comments: `! comment`
/// - Empty lines
pub fn parse_line(line: &str) -> Option<String> {
    let line = line.trim();

    // Skip empty lines and comments
    if line.is_empty() || line.starts_with('!') {
        return None;
    }

    // Parse uBlock-style rules: ||domain.com^
    let domain = if line.starts_with("||") && line.ends_with('^') {
        &line[2..line.len() - 1]
    } else if line.starts_with("||") {
        &line[2..]
    } else {
        line
    };

    // Return lowercase domain
    if !domain.is_empty() {
        Some(domain.to_lowercase())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_domain() {
        assert_eq!(
            parse_line("ads.example.com"),
            Some("ads.example.com".to_string())
        );
    }

    #[test]
    fn test_ublock_rule() {
        assert_eq!(
            parse_line("||ads.example.com^"),
            Some("ads.example.com".to_string())
        );
    }

    #[test]
    fn test_comment() {
        assert_eq!(parse_line("! this is a comment"), None);
    }

    #[test]
    fn test_empty_line() {
        assert_eq!(parse_line(""), None);
        assert_eq!(parse_line("   "), None);
    }
}
