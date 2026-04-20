# Zeek MCP Server

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green?logo=node.js)](https://nodejs.org/)
[![MCP](https://img.shields.io/badge/MCP-1.x-purple)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An MCP (Model Context Protocol) server for [Zeek](https://zeek.org/) and [Suricata](https://suricata.io/), providing intelligent log parsing, querying, and analysis over network security monitoring data. Enables LLMs to query connection logs, DNS activity, HTTP requests, SSL certificates, file extractions, security notices, IDS alerts, and cross-reference findings between both sensors.

## Features

- **25 tools** for querying and analyzing Zeek + Suricata logs
- **2 resources** for log type metadata and sensor stats
- **4 prompts** for guided investigation workflows
- **Dual format support** - JSON and TSV (Zeek's native tab-separated format)
- **Suricata integration** - Query eve.json alerts, cross-correlate with Zeek, engine stats
- **CIDR matching** - Filter by IP ranges (10.0.0.0/8, 192.168.1.0/24)
- **IPv6 support** - Full IPv6 CIDR matching
- **Wildcard matching** - Search domains and URIs with patterns (*.evil.com)
- **Beaconing detection** - Statistical C2 beacon analysis with jitter scoring
- **Anomaly detection** - Port scan, data exfiltration, and unusual port detection
- **DNS tunneling detection** - Shannon entropy analysis with encoding detection
- **DHCP asset mapping** - MAC-to-IP/hostname device inventory
- **Compressed log support** - Reads .gz archived logs
- **Date-based rotation** - Navigates Zeek's archived log directories by date

## Prerequisites

- Node.js 20+
- Zeek sensor generating logs (JSON or TSV format)
- Suricata (optional, for IDS alert correlation)

## Installation

```bash
git clone https://github.com/solomonneas/zeek-mcp.git
cd zeek-mcp
npm install
npm run build
```

## Configuration

### Zeek

| Variable | Default | Description |
|----------|---------|-------------|
| `ZEEK_LOG_DIR` | `/opt/zeek/logs/current` | Path to current Zeek logs |
| `ZEEK_LOG_ARCHIVE` | `/opt/zeek/logs` | Path to archived/rotated logs |
| `ZEEK_LOG_FORMAT` | `json` | Log format: `json` or `tsv` |
| `ZEEK_MAX_RESULTS` | `1000` | Maximum results per query |

### Suricata

| Variable | Default | Description |
|----------|---------|-------------|
| `SURICATA_EVE_LOG` | `/opt/nids/suricata/logs/eve.json` | Path to Suricata eve.json |
| `SURICATA_FAST_LOG` | `/opt/nids/suricata/logs/fast.log` | Path to Suricata fast.log |
| `SURICATA_RULES_DIR` | `/opt/nids/suricata/rules` | Path to Suricata rules directory |

## Usage

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "zeek": {
      "command": "zeek-mcp",
      "env": {
        "ZEEK_LOG_DIR": "/opt/nids/zeek/logs",
        "ZEEK_LOG_FORMAT": "tsv",
        "SURICATA_EVE_LOG": "/opt/nids/suricata/logs/eve.json"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add zeek \
  --env ZEEK_LOG_DIR=/opt/nids/zeek/logs \
  --env ZEEK_LOG_FORMAT=tsv \
  --env SURICATA_EVE_LOG=/opt/nids/suricata/logs/eve.json \
  -- zeek-mcp
```

Add `--scope user` to make it available from any directory instead of only the current project.

### OpenClaw

If you're running from a source checkout instead of the npm-installed binary, point `command`/`args` at the built `dist/index.js`:

```bash
openclaw mcp set zeek '{
  "command": "node",
  "args": ["/absolute/path/to/zeek-mcp/dist/index.js"],
  "env": {
    "ZEEK_LOG_DIR": "/opt/nids/zeek/logs",
    "ZEEK_LOG_FORMAT": "tsv",
    "SURICATA_EVE_LOG": "/opt/nids/suricata/logs/eve.json"
  }
}'
```

Or, with the global npm install:

```bash
openclaw mcp set zeek '{
  "command": "zeek-mcp",
  "env": {
    "ZEEK_LOG_DIR": "/opt/nids/zeek/logs",
    "ZEEK_LOG_FORMAT": "tsv",
    "SURICATA_EVE_LOG": "/opt/nids/suricata/logs/eve.json"
  }
}'
```

Then restart the OpenClaw gateway so the new server is picked up:

```bash
systemctl --user restart openclaw-gateway
openclaw mcp list   # confirm "zeek" is registered
```

### Hermes Agent

[Hermes Agent](https://github.com/NousResearch/hermes-agent) reads MCP config from `~/.hermes/config.yaml` under the `mcp_servers` key. Add an entry:

```yaml
mcp_servers:
  zeek:
    command: "zeek-mcp"
    env:
      ZEEK_LOG_DIR: "/opt/nids/zeek/logs"
      ZEEK_LOG_FORMAT: "tsv"
      SURICATA_EVE_LOG: "/opt/nids/suricata/logs/eve.json"
```

Or, when running from a source checkout instead of the global npm install:

```yaml
mcp_servers:
  zeek:
    command: "node"
    args: ["/absolute/path/to/zeek-mcp/dist/index.js"]
    env:
      ZEEK_LOG_DIR: "/opt/nids/zeek/logs"
      ZEEK_LOG_FORMAT: "tsv"
      SURICATA_EVE_LOG: "/opt/nids/suricata/logs/eve.json"
```

Then reload MCP from inside a Hermes session:

```
/reload-mcp
```

### Codex CLI

[Codex CLI](https://github.com/openai/codex) registers MCP servers via `codex mcp add`:

```bash
codex mcp add zeek \
  --env ZEEK_LOG_DIR=/opt/nids/zeek/logs \
  --env ZEEK_LOG_FORMAT=tsv \
  --env SURICATA_EVE_LOG=/opt/nids/suricata/logs/eve.json \
  -- zeek-mcp
```

Or, when running from a source checkout:

```bash
codex mcp add zeek \
  --env ZEEK_LOG_DIR=/opt/nids/zeek/logs \
  --env ZEEK_LOG_FORMAT=tsv \
  --env SURICATA_EVE_LOG=/opt/nids/suricata/logs/eve.json \
  -- node /absolute/path/to/zeek-mcp/dist/index.js
```

Codex writes the entry to `~/.codex/config.toml` under `[mcp_servers.zeek]`. Verify with:

```bash
codex mcp list
```

### Standalone

```bash
ZEEK_LOG_DIR=/opt/nids/zeek/logs ZEEK_LOG_FORMAT=tsv node dist/index.js
```

### Development

```bash
ZEEK_LOG_DIR=./test-data npm run dev
```

## Tools

### Connection Analysis

| Tool | Description |
|------|-------------|
| `zeek_query_connections` | Search connection logs with flexible filters (CIDR, protocol, duration, bytes) |
| `zeek_connection_summary` | Statistical summary: top talkers, services, bytes, connection counts |
| `zeek_long_connections` | Find long-lived connections (potential C2 beacons, tunnels) |

### DNS Analysis

| Tool | Description |
|------|-------------|
| `zeek_query_dns` | Search DNS queries with domain wildcards and response code filtering |
| `zeek_dns_summary` | Top domains, NXDOMAIN counts (DGA detection), query type distribution |
| `zeek_dns_tunneling_check` | Detect DNS tunneling via entropy analysis and encoding detection |

### HTTP Analysis

| Tool | Description |
|------|-------------|
| `zeek_query_http` | Search HTTP requests by host, URI, method, user agent, status code |
| `zeek_suspicious_http` | Find suspicious HTTP: POSTs to IPs, unusual agents, large bodies, base64 in URLs |

### SSL/TLS Analysis

| Tool | Description |
|------|-------------|
| `zeek_query_ssl` | Search SSL/TLS by SNI, version, validation status, certificate fields |
| `zeek_expired_certs` | Find expired, self-signed, or invalid certificates |

### File Analysis

| Tool | Description |
|------|-------------|
| `zeek_query_files` | Search file extractions by MIME type, hash, filename, size |
| `zeek_executable_downloads` | Find executable transfers (PE, ELF, scripts) on the wire |

### Security Notices

| Tool | Description |
|------|-------------|
| `zeek_query_notices` | Search Zeek security notices (port scans, invalid certs, custom alerts) |

### SSH Analysis

| Tool | Description |
|------|-------------|
| `zeek_query_ssh` | Search SSH connections by auth status, direction, client/server |
| `zeek_ssh_bruteforce` | Detect SSH brute force attempts exceeding a failure threshold |

### DHCP & Asset Discovery

| Tool | Description |
|------|-------------|
| `zeek_query_dhcp` | Search DHCP logs for lease assignments and device discovery |
| `zeek_dhcp_asset_map` | Build MAC-to-IP/hostname asset map for network inventory |

### Cross-Log Investigation

| Tool | Description |
|------|-------------|
| `zeek_investigate_host` | Full host investigation across all log types |
| `zeek_investigate_uid` | Follow a connection UID across all log types |

### Software Discovery

| Tool | Description |
|------|-------------|
| `zeek_software_inventory` | List detected software and versions on the network |

### Analytics

| Tool | Description |
|------|-------------|
| `zeek_detect_beaconing` | Detect C2 beaconing by analyzing connection interval regularity and jitter |
| `zeek_detect_anomalies` | Statistical anomaly detection: port scans, data exfiltration, unusual ports |

### Suricata IDS

| Tool | Description |
|------|-------------|
| `suricata_query_alerts` | Search Suricata alerts by signature, severity, IP, protocol, time |
| `suricata_alert_summary` | High-level alert summary: top signatures, categories, IPs, severity distribution |
| `suricata_correlate_zeek` | Cross-reference Suricata alerts with Zeek logs for full context |
| `suricata_eve_stats` | Suricata engine statistics: packets, flows, detection performance |

### Sensor Management

| Tool | Description |
|------|-------------|
| `nids_sensor_status` | Live sensor status: log inventory, sizes, freshness, health checks |

## Resources

| Resource | URI | Description |
|----------|-----|-------------|
| Log Types | `zeek://log-types` | All Zeek log types with field descriptions |
| Stats | `zeek://stats` | Sensor statistics and available log types |

## Prompts

| Prompt | Description |
|--------|-------------|
| `triage-alert` | Triage a Suricata alert by cross-referencing with Zeek logs |
| `investigate-host` | Guided host investigation workflow across all logs |
| `hunt-for-c2` | Threat hunting for C2 communication patterns |
| `network-baseline` | Generate a network activity baseline |

## Supported Log Types

conn, dns, http, ssl, files, notice, weird, x509, smtp, ssh, dpd, software, dhcp, ntp, ocsp, websocket

## Testing

```bash
npm test
```

110 tests covering parsers (JSON + TSV), query engine, CIDR/wildcard filters, analytics (entropy, beaconing, anomaly detection), Suricata eve.json parsing, DHCP log parsing, and sensor status.

### Generate Test Data

```bash
npm run generate-logs
npx tsx scripts/generate-zeek-logs.ts --output=/tmp/zeek-logs --format=json
```

## Project Structure

```
zeek-mcp/
  src/
    index.ts                 # MCP server entry point
    config.ts                # Environment config + validation
    types.ts                 # Zeek log type definitions (16 log types)
    resources.ts             # MCP resources
    prompts.ts               # MCP prompts (4 workflows)
    parser/
      index.ts               # Format-agnostic parser + log resolution
      json.ts                # JSON log parser
      tsv.ts                 # TSV log parser with header detection
    query/
      engine.ts              # Query engine with filtering/sorting
      filters.ts             # CIDR match (v4+v6), wildcard, range operators
      aggregation.ts         # Statistical aggregation functions
    tools/
      connections.ts         # Connection analysis tools
      dns.ts                 # DNS analysis tools
      http.ts                # HTTP analysis tools
      ssl.ts                 # SSL/TLS analysis tools
      files.ts               # File analysis tools
      notices.ts             # Security notice tools
      ssh.ts                 # SSH analysis tools
      investigation.ts       # Cross-log investigation tools
      software.ts            # Software/asset discovery
      dhcp.ts                # DHCP log tools + asset mapping
      beaconing.ts           # Beaconing detection tool
      anomaly.ts             # Anomaly detection tool
      suricata.ts            # Suricata eve.json tools
      sensor.ts              # Sensor status + health checks
    analytics/
      entropy.ts             # Shannon entropy calculation
      beaconing.ts           # Beacon detection algorithms
      anomaly.ts             # Statistical anomaly detection
  tests/
    parser.test.ts           # Parser unit tests (JSON + TSV)
    query.test.ts            # Query engine + filter tests
    analytics.test.ts        # Entropy, beaconing, anomaly tests
    tools.test.ts            # Integration tests with sample data
    suricata.test.ts         # Suricata eve.json parsing tests
    dhcp.test.ts             # DHCP log parsing + asset map tests
    beaconing-tools.test.ts  # Beaconing + anomaly detection tests
    sensor.test.ts           # Sensor status tests
  test-data/                 # Sample Zeek + Suricata logs
  scripts/
    generate-zeek-logs.ts    # Mock data generator
```

## License

MIT
