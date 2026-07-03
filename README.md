# rust-dns-ad-filter

A fully local DNS filtering daemon written in Rust, inspired by Pi-hole and uBlock Origin.

## Features

- **100% local** — No external APIs or cloud dependency
- **DNS server** — Listens on `127.0.0.1:5353` (UDP)
- **Rule engine** — Blocks domains from local filter lists
- **Multiple formats** — Plain domains and uBlock-style rules
- **Fast matching** — Uses `DashSet` for concurrent lookups

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run
```

The server will listen on `127.0.0.1:5353` and load rules from `lists/*.txt`.

## Rule Formats

Add rules to files in the `lists/` directory (e.g., `lists/custom.txt`):

### Plain domains
```
ads.example.com
tracker.google.com
```

### uBlock-style rules
```
||doubleclick.net^
||facebook.com^
```

### Comments and empty lines
```
! This is a comment
```

## Testing

Query the local DNS server:
```bash
nslookup ads.example.com 127.0.0.1 -port=5353
```

Should return `NXDOMAIN` for blocked domains, and normal responses for allowed domains.

## Project Structure

```
src/
  main.rs          — Entry point
  dns/
    server.rs      — UDP DNS server
  rules/
    engine.rs      — Rule matching engine
    parser.rs      — Rule file parser
    loader.rs      — Rule file loader
lists/
  custom.txt       — Example filter list
```

## License

GPL-3.0
