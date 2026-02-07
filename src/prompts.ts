import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export function registerPrompts(server: McpServer): void {
  server.prompt(
    "investigate-host",
    "Full host investigation workflow - cross-log analysis, anomaly identification, and connection profiling for a specific IP address.",
    {
      ip: z.string().describe("IP address to investigate"),
      timeWindow: z
        .string()
        .optional()
        .describe("Time window to investigate (e.g. 'last 24h', '2024-01-15 to 2024-01-16')"),
    },
    ({ ip, timeWindow }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `Investigate the following host across all Zeek logs: ${ip}${timeWindow ? ` (Time window: ${timeWindow})` : ""}

Follow this investigation workflow:

1. **Run zeek_investigate_host** for the target IP to get a cross-log overview
2. **Analyze connections**: Look at top destinations, unusual ports, high byte counts, and connection states
3. **Check DNS activity**: Look for DGA patterns, tunneling indicators, or suspicious domain queries
4. **Review HTTP requests**: Check for suspicious user agents, POSTs to raw IPs, or unusual URIs
5. **Inspect SSL/TLS**: Look for self-signed certs, expired certs, or connections to suspicious SNI hostnames
6. **Check security notices**: Review any Zeek-generated alerts for this host
7. **Review SSH activity**: Check for brute force attempts or unusual SSH patterns
8. **Software inventory**: Identify what software was detected on this host
9. **Run zeek_dns_tunneling_check** if DNS activity looks anomalous
10. **Summarize findings**: Provide a risk assessment with specific indicators of concern

Rate the host's risk level: LOW / MEDIUM / HIGH / CRITICAL with supporting evidence.`,
          },
        },
      ],
    }),
  );

  server.prompt(
    "hunt-for-c2",
    "Threat hunting workflow for command-and-control communication patterns using long connections, DNS anomalies, suspicious HTTP, and beaconing analysis.",
    {
      timeWindow: z
        .string()
        .optional()
        .describe("Time window to hunt in (e.g. 'last 24h')"),
    },
    ({ timeWindow }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `Hunt for potential C2 (command and control) communication in Zeek logs${timeWindow ? ` (Time window: ${timeWindow})` : ""}.

Follow this threat hunting workflow:

1. **Long-lived connections**: Run zeek_long_connections with minDuration of 3600 (1 hour)
   - C2 channels often maintain persistent connections
   - Look for connections to external IPs on unusual ports

2. **DNS anomalies**: Run zeek_dns_tunneling_check
   - DNS tunneling uses high-entropy subdomains to exfiltrate data
   - Look for excessive TXT/NULL queries to single domains
   - Check for high NXDOMAIN rates (potential DGA)

3. **DNS summary**: Run zeek_dns_summary
   - Identify domains with abnormally high query counts
   - Look for newly-seen domains or unusual TLDs

4. **Suspicious HTTP**: Run zeek_suspicious_http
   - C2 over HTTP often uses POSTs to raw IPs
   - Look for unusual user agents or regular-interval callbacks
   - Check for base64 in URLs or large POST bodies

5. **SSL/TLS anomalies**: Run zeek_expired_certs
   - C2 infrastructure often uses self-signed or expired certificates
   - Look for connections to IPs (not domains) over HTTPS

6. **Beaconing analysis**: Look for regular-interval connections in connection logs
   - Filter connections by low jitter in callback intervals
   - Group by source-destination pairs

7. **Cross-reference findings**: For any suspicious IPs found, run zeek_investigate_host
   - Correlate across all log types
   - Build a complete picture of the suspect activity

8. **Summary**: List all C2 indicators found, ordered by confidence level:
   - CONFIRMED: Clear C2 indicators
   - HIGH: Strong suspicious patterns
   - MEDIUM: Worth investigating further
   - LOW: Possible false positives`,
          },
        },
      ],
    }),
  );

  server.prompt(
    "network-baseline",
    "Generate a network activity baseline showing normal traffic patterns, top talkers, common services, and DNS behavior.",
    {
      timeWindow: z
        .string()
        .optional()
        .describe("Time window for baseline (e.g. 'last 7d')"),
    },
    ({ timeWindow }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `Generate a network activity baseline from Zeek logs${timeWindow ? ` (Time window: ${timeWindow})` : ""}.

Build a baseline profile:

1. **Connection overview**: Run zeek_connection_summary
   - Total connections, unique IPs, total bytes
   - Top talkers (source and destination)
   - Service distribution
   - Protocol distribution
   - Connection state distribution (look for high S0/REJ rates)

2. **DNS profile**: Run zeek_dns_summary
   - Top queried domains (normal business domains)
   - Query type distribution
   - DNS client distribution
   - NXDOMAIN rate (baseline for DGA detection)

3. **HTTP profile**: Run zeek_query_http with a high limit
   - Top visited hosts
   - Common user agents
   - Method distribution

4. **SSL/TLS profile**: Run zeek_query_ssl with a high limit
   - Top SNI hostnames
   - TLS version distribution
   - Certificate validation status overview

5. **Software inventory**: Run zeek_software_inventory
   - What browsers, servers, and applications are on the network
   - Version distribution

6. **Security notices**: Run zeek_query_notices
   - Baseline notice types and frequencies

7. **Produce a baseline report**:
   - Normal traffic patterns and thresholds
   - Expected top talkers and services
   - Known software and versions
   - Recommended alerting thresholds based on observed patterns
   - Any immediate concerns found during baselining`,
          },
        },
      ],
    }),
  );
}
