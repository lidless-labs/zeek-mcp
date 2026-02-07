# Zeek MCP Server

An MCP (Model Context Protocol) server for [Zeek](https://zeek.org/) (formerly Bro), the powerful network analysis framework. This server provides intelligent log parsing, querying, and analysis capabilities over Zeek's rich log ecosystem, enabling LLMs to query connection logs, DNS activity, HTTP requests, SSL certificates, file extractions, and security notices.

## Features

- **18 tools** for querying and analyzing Zeek logs
- **2 resources** for log type metadata and sensor stats
- **3 prompts** for guided investigation workflows
- **Dual format support** - JSON and TSV (Zeek's native tab-separated format)
- **CIDR matching** - filter by IP ranges (10.0.0.0/8, 192.168.1.0/24)
- **Wildcard matching** - search domains and URIs with patterns (*.evil.com)
- **Analytics** - Shannon entropy for DNS tunneling detection, beaconing analysis, anomaly detection
- **Compressed log support** - reads .gz archived logs
- **Date-based rotation** - navigates Zeek's archived log directories by date

## Prerequisites

- Node.js 20+
- Zeek sensor generating logs (JSON or TSV format)

## Installation

```bash
git clone <repo-url>
cd zeek-mcp
npm install
npm run build
```

## Configuration

Set environment variables before running:

| Variable | Default | Description |
|----------|---------|-------------|
| `ZEEK_LOG_DIR` | `/opt/zeek/logs/current` | Path to current Zeek logs |
| `ZEEK_LOG_ARCHIVE` | `/opt/zeek/logs` | Path to archived/rotated logs |
| `ZEEK_LOG_FORMAT` | `json` | Log format: `json` or `tsv` |
| `ZEEK_MAX_RESULTS` | `1000` | Maximum results per query |

## Usage

### Claude Desktop

Add to your Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "zeek": {
      "command": "node",
      "args": ["/path/to/zeek-mcp/dist/index.js"],
      "env": {
        "ZEEK_LOG_DIR": "/opt/zeek/logs/current",
        "ZEEK_LOG_FORMAT": "json"
      }
    }
  }
}
```

### Standalone

```bash
ZEEK_LOG_DIR=/opt/zeek/logs/current node dist/index.js
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
| `zeek_connection_summary` | Statistical summary - top talkers, services, bytes, connection counts |
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

### Cross-Log Investigation

| Tool | Description |
|------|-------------|
| `zeek_investigate_host` | Full host investigation across all log types |
| `zeek_investigate_uid` | Follow a connection UID across all log types |

### Software Discovery

| Tool | Description |
|------|-------------|
| `zeek_software_inventory` | List detected software and versions on the network |

## Resources

| Resource | URI | Description |
|----------|-----|-------------|
| Log Types | `zeek://log-types` | All Zeek log types with field descriptions |
| Stats | `zeek://stats` | Sensor statistics and available log types |

## Prompts

| Prompt | Description |
|--------|-------------|
| `investigate-host` | Guided host investigation workflow across all logs |
| `hunt-for-c2` | Threat hunting for C2 communication patterns |
| `network-baseline` | Generate a network activity baseline |

## Supported Log Types

conn, dns, http, ssl, files, notice, weird, x509, smtp, ssh, dpd, software

## Testing

```bash
npm test
```

Tests use sample Zeek log files in `test-data/` covering both JSON and TSV formats.

### Generate Test Data

Generate realistic Zeek logs with injected suspicious patterns:

```bash
npm run generate-logs

# Options
npx tsx scripts/generate-zeek-logs.ts --output=/tmp/zeek-logs --format=json
```

## Project Structure

```
zeek-mcp/
  src/
    index.ts                 # MCP server entry point
    config.ts                # Environment config + validation
    types.ts                 # Zeek log type definitions
    resources.ts             # MCP resources
    prompts.ts               # MCP prompts
    parser/
      index.ts               # Format-agnostic parser + log resolution
      json.ts                # JSON log parser
      tsv.ts                 # TSV log parser with header detection
    query/
      engine.ts              # Query engine with filtering/sorting
      filters.ts             # CIDR match, wildcard, range operators
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
    analytics/
      entropy.ts             # Shannon entropy calculation
      beaconing.ts           # Beacon detection algorithms
      anomaly.ts             # Statistical anomaly detection
  tests/
    parser.test.ts           # Parser unit tests (JSON + TSV)
    query.test.ts            # Query engine + filter tests
    analytics.test.ts        # Entropy, beaconing, anomaly tests
    tools.test.ts            # Integration tests with sample data
  test-data/                 # Sample Zeek logs
  scripts/
    generate-zeek-logs.ts    # Mock data generator
```

## License

MIT
