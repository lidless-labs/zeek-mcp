import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export function registerPrompts(server: McpServer): void {
  server.prompt(
    "triage-alert",
    "Triage a Suricata alert by cross-referencing with Zeek logs for full context. Determines if the alert is a true positive, false positive, or needs escalation.",
    {
      signatureId: z
        .string()
        .optional()
        .describe("Suricata signature ID (SID) to triage"),
      srcIp: z
        .string()
        .optional()
        .describe("Source IP from the alert"),
    },
    ({ signatureId, srcIp }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: `Triage the following Suricata alert${signatureId ? ` (SID: ${signatureId})` : ""}${srcIp ? ` from source IP ${srcIp}` : ""}:

Follow this triage workflow:

1. **Get alert details**: Run suricata_query_alerts${signatureId ? ` with signatureId=${signatureId}` : ""}${srcIp ? ` with srcIp=${srcIp}` : ""} to get the full alert context
2. **Cross-reference with Zeek**: Run suricata_correlate_zeek to get correlation suggestions, then execute the suggested Zeek queries
3. **Investigate the source host**: Run zeek_investigate_host for the source IP
4. **Check for patterns**: Look for repeated alerts, related activity, or coordinated behavior
5. **DNS context**: Run zeek_query_dns for the source IP to check domain queries
6. **DHCP/Asset context**: Run zeek_dhcp_asset_map to identify what device triggered the alert
7. **Determine verdict**:
   - TRUE POSITIVE: Alert matches real malicious activity confirmed by Zeek context
   - FALSE POSITIVE: Alert triggered on legitimate traffic (explain why)
   - NEEDS ESCALATION: Insufficient data to determine, or activity is suspicious but not conclusive
8. **Recommend actions**: Block IP, add exception, investigate further, or dismiss`,
          },
        },
      ],
    }),
  );


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
