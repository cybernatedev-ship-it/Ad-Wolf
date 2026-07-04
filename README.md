# rust-dns-ad-filter

A fully local DNS filtering daemon written in Rust, inspired by Pi-hole and uBlock Origin.

## Features

- **100% local** — No external APIs or cloud dependency
- **DNS server** — UDP and TCP, IPv4 + IPv6
- **Upstream forwarding** — Configurable resolvers with failover
- **Response cache** — Reuses recent upstream DNS responses
- **Filter engine** — Modular matchers with priority-based matching
- **Multiple formats** — Plain domains, hosts files, uBlock/AdGuard rules
- **Hot reload** — Update rules without restart
- **Statistics** — Query counts, block rates, top blocked domains

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run --bin dns-filter-cli
```

The server listens on the address configured in `config.toml` and loads rules from the `lists/` directory.

## Rule Formats

Add rules to files in the `lists/` directory (e.g., `lists/custom.txt`):

### Plain domains
```
ads.example.com
tracker.google.com
```

### Hosts file format
```
0.0.0.0 ads.example.com
```

### uBlock-style rules
```
||doubleclick.net^
@@||allowed.example.com^
```

### Comments and empty lines
```
! This is a comment
```

## Project Structure

```
crates/
  core/        — Business logic, matcher traits, statistics
  filter/      — Rule engine, parser, loader
  dns/         — DNS server (UDP + TCP), query handling
  cache/       — DNS response caching
  upstream/    — Upstream resolver forwarding
  config/      — TOML configuration management
  cli/         — CLI entry point
lists/
  custom.txt   — Example filter list
```

## Testing

```bash
cargo test
```

## License

GPL-3.0
