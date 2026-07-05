# dns-filter

Command-line DNS filtering daemon.

```bash
# With auto-detected config
dns-filter

# With explicit config
dns-filter -c /etc/dns-filter/config.toml

# With all overrides
dns-filter -l 0.0.0.0:53 -r ./lists --db ./queries.db --metrics-addr :9120
```
