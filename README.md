# Ad-Wolf

A fully local DNS filtering daemon written in Rust, inspired by Pi-hole and uBlock Origin.

## Features

- **100% local** — No external APIs or cloud dependency
- **DNS server** — UDP and TCP, IPv4 + IPv6
- **Upstream forwarding** — UDP, TCP, TLS (DoT), HTTPS (DoH) with failover
- **Response cache** — Reuses recent upstream DNS responses
- **Filter engine** — Modular matchers with priority-based matching
- **Multiple formats** — Plain domains, hosts files, uBlock/AdGuard rules
- **Hot reload** — Update rules via file watcher or SIGHUP without restart
- **Remote list management** — Download and periodically update rule lists from URLs
- **Query logging** — Optional SQLite-backed persistent query log
- **Statistics** — Query counts, block rates, top blocked domains
- **Prometheus metrics** — HTTP endpoint at `:9120/metrics`
- **Terminal dashboard** — Real-time TUI with stats, top blocked, recent queries
- **Tauri GUI** — Cross-platform desktop frontend (in development)

## Building

```bash
# Build the CLI daemon
cargo build --release --bin dns-filter

# Build everything
cargo build --release
```

## Running

```bash
# With auto-detected config
dns-filter

# With explicit config
dns-filter -c /etc/dns-filter/config.toml

# With CLI overrides
dns-filter -l 0.0.0.0:53 -r ./lists --db ./queries.db --metrics-addr 127.0.0.1:9120
```

See `config.example.toml` for all configuration options.

### Terminal dashboard

```bash
# Standalone TUI (requires a query log database)
cargo run -p dns-filter-tui -- queries.db
```

## Installation

### Linux (systemd)

```bash
sudo cp dns-filter.service /etc/systemd/system/
sudo systemctl enable --now dns-filter
```

### Docker

```bash
docker build -t ad-wolf .
docker run -p 53:53/udp -p 53:53/tcp -v ./config.toml:/etc/dns-filter/config.toml ad-wolf
```

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
  upstream/    — Upstream resolver forwarding (UDP, TCP, TLS, HTTPS)
  config/      — TOML configuration management
  cli/         — CLI entry point (bin: dns-filter)
  storage/     — SQLite query log persistence
  metrics/     — Prometheus HTTP endpoint
  tui/         — Terminal dashboard with ratatui
gui/           — Tauri v2 desktop GUI (React + TypeScript)
lists/         — Example filter lists
```

## Testing

```bash
cargo test
```

## License

GPL-3.0
