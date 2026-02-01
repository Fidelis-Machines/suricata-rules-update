# suricata-rules-update

A Rust implementation of a Suricata rule update tool. Downloads, merges, and manages Suricata rule files from various sources.

## Building

### Prerequisites

- Rust 1.70 or later
- OpenSSL development libraries (for TLS support)

On Debian/Ubuntu:
```bash
apt install build-essential pkg-config libssl-dev
```

On Fedora/RHEL:
```bash
dnf install gcc pkg-config openssl-devel
```

### Build from source

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release
```

The binary will be located at:
- Debug: `target/debug/suricata-rules-update`
- Release: `target/release/suricata-rules-update`

### Install

```bash
cargo install --path .
```

Or copy the binary to a system location:
```bash
sudo cp target/release/suricata-rules-update /usr/local/bin/
```

## Usage

### Update rules (default action)

```bash
# Update rules using defaults
suricata-rules-update

# Update with custom paths
suricata-rules-update -c /etc/suricata/suricata.yaml -o /var/lib/suricata/rules

# Force update (ignore cache)
suricata-rules-update --force

# Update and reload Suricata
suricata-rules-update --reload

# Verbose output
suricata-rules-update -v
```

### Manage rule sources

```bash
# List available sources
suricata-rules-update list-sources

# Enable a source
suricata-rules-update enable-source et/open

# Disable a source
suricata-rules-update disable-source oisf/trafficid

# Update source index from OISF
suricata-rules-update update-sources

# Add a custom source (URL or local file)
suricata-rules-update add-source https://example.com/custom.rules
suricata-rules-update add-source /path/to/local.rules
```

### Check for updates

```bash
suricata-rules-update check-version
```

## Command-line options

| Option | Description | Default |
|--------|-------------|---------|
| `-c, --config` | Path to suricata.yaml | `/etc/suricata/suricata.yaml` |
| `-o, --output` | Output directory for rules | `/var/lib/suricata/rules` |
| `--data-dir` | Data directory for cache and state | `/var/lib/suricata` |
| `-v, --verbose` | Enable verbose output | false |
| `-f, --force` | Force update even if rules are current | false |
| `--reload` | Reload Suricata after update | false |

## Configuration

The tool stores its configuration in `<data-dir>/update/config.yaml`. You can manually edit this file to:

### Disable specific rules by SID

```yaml
disable_sid:
  - 2100498
  - 2100499
```

### Enable specific rules by SID (overrides disable)

```yaml
enable_sid:
  - 2100500
```

### Modify rule actions

```yaml
modify_sid:
  - sid: 2100501
    action: drop
  - sid: 2100502
    action: reject
```

### Local rules

Place custom rules in `<data-dir>/rules/local.rules`. These will be merged with downloaded rules.

## Built-in sources

| Name | Description | Default |
|------|-------------|---------|
| `et/open` | Emerging Threats Open Ruleset | Enabled |
| `oisf/trafficid` | Traffic ID rules for protocol detection | Disabled |
| `ptresearch/attackdetection` | PT Attack Detection Team ruleset | Disabled |
| `sslbl/ssl-fp-blacklist` | SSL Fingerprint Blacklist | Disabled |

## Examples

### Basic setup

```bash
# Enable Emerging Threats Open rules (enabled by default)
suricata-rules-update enable-source et/open

# Download and install rules
sudo suricata-rules-update

# Verify rules were installed
ls -la /var/lib/suricata/rules/
```

### Using with systemd timer

Create `/etc/systemd/system/suricata-rules-update.service`:
```ini
[Unit]
Description=Update Suricata rules

[Service]
Type=oneshot
ExecStart=/usr/local/bin/suricata-rules-update --reload
```

Create `/etc/systemd/system/suricata-rules-update.timer`:
```ini
[Unit]
Description=Daily Suricata rule update

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the timer:
```bash
sudo systemctl enable --now suricata-rules-update.timer
```

## License

GPL-2.0-only
