import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "node:fs";
import * as readline from "node:readline";

export interface SuricataConfig {
  eveLogPath: string;
  fastLogPath: string;
  rulesDir: string;
}

export function getSuricataConfig(): SuricataConfig {
  return {
    eveLogPath: process.env.SURICATA_EVE_LOG ?? "/opt/nids/suricata/logs/eve.json",
    fastLogPath: process.env.SURICATA_FAST_LOG ?? "/opt/nids/suricata/logs/fast.log",
    rulesDir: process.env.SURICATA_RULES_DIR ?? "/opt/nids/suricata/rules",
  };
}

interface EveAlert {
  timestamp: string;
  event_type: string;
  src_ip: string;
  src_port?: number;
  dest_ip: string;
  dest_port?: number;
  proto: string;
  alert?: {
    action: string;
    gid: number;
    signature_id: number;
    rev: number;
    signature: string;
    category: string;
    severity: number;
    metadata?: Record<string, unknown>;
  };
  flow?: {
    pkts_toserver: number;
    pkts_toclient: number;
    bytes_toserver: number;
    bytes_toclient: number;
    start: string;
  };
  http?: {
    hostname: string;
    url: string;
    http_user_agent: string;
    http_method: string;
    protocol: string;
    status: number;
    length: number;
  };
  dns?: {
    query: Array<{ rrname: string; rrtype: string }>;
    answer?: Array<{ rrname: string; rrtype: string; rdata: string }>;
  };
  tls?: {
    subject: string;
    issuerdn: string;
    serial: string;
    fingerprint: string;
    sni: string;
    version: string;
    ja3?: { hash: string };
    ja3s?: { hash: string };
  };
  app_proto?: string;
  flow_id?: number;
  community_id?: string;
}

async function readEveLog(
  filePath: string,
  maxLines: number,
  filter?: (event: EveAlert) => boolean,
): Promise<EveAlert[]> {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const stream = fs.createReadStream(filePath);
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

  const events: EveAlert[] = [];
  for await (const line of rl) {
    if (!line.trim()) continue;
    try {
      const event = JSON.parse(line) as EveAlert;
      if (!filter || filter(event)) {
        events.push(event);
        if (events.length >= maxLines) break;
      }
    } catch {
      // skip malformed lines
    }
  }

  return events;
}

async function tailEveLog(
  filePath: string,
  maxLines: number,
  filter?: (event: EveAlert) => boolean,
): Promise<EveAlert[]> {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  // Read file backwards for tail behavior
  const stat = fs.statSync(filePath);
  const bufferSize = Math.min(stat.size, 10 * 1024 * 1024); // 10MB max
  const buffer = Buffer.alloc(bufferSize);
  const fd = fs.openSync(filePath, "r");
  fs.readSync(fd, buffer, 0, bufferSize, stat.size - bufferSize);
  fs.closeSync(fd);

  const content = buffer.toString("utf-8");
  const lines = content.split("\n").filter((l) => l.trim());

  const events: EveAlert[] = [];
  for (let i = lines.length - 1; i >= 0 && events.length < maxLines; i--) {
    try {
      const event = JSON.parse(lines[i]) as EveAlert;
      if (!filter || filter(event)) {
        events.push(event);
      }
    } catch {
      // skip
    }
  }

  return events;
}

export function registerSuricataTools(server: McpServer): void {
  const config = getSuricataConfig();

  server.tool(
    "suricata_query_alerts",
    "Search Suricata IDS/IPS alerts from eve.json. Filter by signature, severity, source/destination IP, protocol, and time range. Returns the most recent alerts matching the criteria.",
    {
      signature: z.string().optional().describe("Alert signature text (partial match)"),
      signatureId: z.number().int().optional().describe("Suricata signature ID (SID)"),
      category: z.string().optional().describe("Alert category (partial match)"),
      srcIp: z.string().optional().describe("Source IP address"),
      dstIp: z.string().optional().describe("Destination IP address"),
      minSeverity: z.number().int().min(1).max(4).optional().describe("Minimum severity (1=highest, 4=lowest)"),
      proto: z.string().optional().describe("Protocol (TCP, UDP, ICMP)"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().int().min(1).max(5000).default(100).describe("Max results"),
    },
    async (params) => {
      try {
        const fromTs = params.timeFrom ? new Date(params.timeFrom).getTime() : undefined;
        const toTs = params.timeTo ? new Date(params.timeTo).getTime() : undefined;

        const events = await tailEveLog(config.eveLogPath, params.limit * 5, (event) => {
          if (event.event_type !== "alert") return false;
          if (!event.alert) return false;

          if (params.signature && !event.alert.signature.toLowerCase().includes(params.signature.toLowerCase())) return false;
          if (params.signatureId !== undefined && event.alert.signature_id !== params.signatureId) return false;
          if (params.category && !event.alert.category.toLowerCase().includes(params.category.toLowerCase())) return false;
          if (params.srcIp && event.src_ip !== params.srcIp) return false;
          if (params.dstIp && event.dest_ip !== params.dstIp) return false;
          if (params.minSeverity !== undefined && event.alert.severity > params.minSeverity) return false;
          if (params.proto && event.proto.toUpperCase() !== params.proto.toUpperCase()) return false;

          if (fromTs || toTs) {
            const eventTs = new Date(event.timestamp).getTime();
            if (fromTs && eventTs < fromTs) return false;
            if (toTs && eventTs > toTs) return false;
          }

          return true;
        });

        const alerts = events.slice(0, params.limit).map((e) => ({
          timestamp: e.timestamp,
          signature: e.alert!.signature,
          signatureId: e.alert!.signature_id,
          category: e.alert!.category,
          severity: e.alert!.severity,
          action: e.alert!.action,
          src: `${e.src_ip}:${e.src_port ?? ""}`,
          dst: `${e.dest_ip}:${e.dest_port ?? ""}`,
          proto: e.proto,
          appProto: e.app_proto,
          communityId: e.community_id,
          flowId: e.flow_id,
          http: e.http ? {
            method: e.http.http_method,
            host: e.http.hostname,
            url: e.http.url,
            userAgent: e.http.http_user_agent,
            status: e.http.status,
          } : undefined,
          tls: e.tls ? {
            sni: e.tls.sni,
            subject: e.tls.subject,
            ja3: e.tls.ja3?.hash,
          } : undefined,
        }));

        // Build severity distribution
        const bySeverity: Record<number, number> = {};
        const byCategory: Record<string, number> = {};
        const bySrc: Record<string, number> = {};
        for (const a of alerts) {
          bySeverity[a.severity] = (bySeverity[a.severity] ?? 0) + 1;
          byCategory[a.category] = (byCategory[a.category] ?? 0) + 1;
          bySrc[a.src] = (bySrc[a.src] ?? 0) + 1;
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              count: alerts.length,
              bySeverity,
              topCategories: Object.entries(byCategory)
                .sort(([, a], [, b]) => b - a)
                .slice(0, 10)
                .map(([cat, count]) => ({ category: cat, count })),
              alerts,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error querying Suricata alerts: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_alert_summary",
    "Get a high-level summary of Suricata alerts: top signatures, categories, severity distribution, top source/destination IPs, and alert timeline.",
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().int().min(100).max(50000).default(5000).describe("Max events to analyze"),
    },
    async (params) => {
      try {
        const fromTs = params.timeFrom ? new Date(params.timeFrom).getTime() : undefined;
        const toTs = params.timeTo ? new Date(params.timeTo).getTime() : undefined;

        const events = await tailEveLog(config.eveLogPath, params.limit, (event) => {
          if (event.event_type !== "alert") return false;
          if (fromTs || toTs) {
            const eventTs = new Date(event.timestamp).getTime();
            if (fromTs && eventTs < fromTs) return false;
            if (toTs && eventTs > toTs) return false;
          }
          return true;
        });

        const sigCounts = new Map<string, { count: number; severity: number; sid: number }>();
        const catCounts = new Map<string, number>();
        const srcCounts = new Map<string, number>();
        const dstCounts = new Map<string, number>();
        const severityCounts: Record<number, number> = {};
        const actionCounts: Record<string, number> = {};

        for (const e of events) {
          if (!e.alert) continue;

          const sig = e.alert.signature;
          const existing = sigCounts.get(sig);
          if (existing) {
            existing.count++;
          } else {
            sigCounts.set(sig, { count: 1, severity: e.alert.severity, sid: e.alert.signature_id });
          }

          catCounts.set(e.alert.category, (catCounts.get(e.alert.category) ?? 0) + 1);
          srcCounts.set(e.src_ip, (srcCounts.get(e.src_ip) ?? 0) + 1);
          dstCounts.set(e.dest_ip, (dstCounts.get(e.dest_ip) ?? 0) + 1);
          severityCounts[e.alert.severity] = (severityCounts[e.alert.severity] ?? 0) + 1;
          actionCounts[e.alert.action] = (actionCounts[e.alert.action] ?? 0) + 1;
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalAlerts: events.length,
              severityDistribution: severityCounts,
              actionDistribution: actionCounts,
              topSignatures: [...sigCounts.entries()]
                .sort((a, b) => b[1].count - a[1].count)
                .slice(0, 20)
                .map(([sig, data]) => ({ signature: sig, ...data })),
              topCategories: [...catCounts.entries()]
                .sort((a, b) => b[1] - a[1])
                .slice(0, 15)
                .map(([cat, count]) => ({ category: cat, count })),
              topSourceIps: [...srcCounts.entries()]
                .sort((a, b) => b[1] - a[1])
                .slice(0, 15)
                .map(([ip, count]) => ({ ip, alertCount: count })),
              topDestinationIps: [...dstCounts.entries()]
                .sort((a, b) => b[1] - a[1])
                .slice(0, 15)
                .map(([ip, count]) => ({ ip, alertCount: count })),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error generating alert summary: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_correlate_zeek",
    "Cross-reference a Suricata alert with Zeek logs using community_id or IP/port/time matching. Returns the Suricata alert details alongside instructions to investigate the same flow in Zeek.",
    {
      signatureId: z.number().int().optional().describe("Suricata SID to look up"),
      srcIp: z.string().optional().describe("Source IP from alert"),
      dstIp: z.string().optional().describe("Destination IP from alert"),
      communityId: z.string().optional().describe("Community ID for cross-tool correlation"),
      limit: z.number().int().min(1).max(100).default(10).describe("Max alerts to correlate"),
    },
    async (params) => {
      try {
        const events = await tailEveLog(config.eveLogPath, params.limit * 10, (event) => {
          if (event.event_type !== "alert") return false;
          if (params.signatureId !== undefined && event.alert?.signature_id !== params.signatureId) return false;
          if (params.srcIp && event.src_ip !== params.srcIp) return false;
          if (params.dstIp && event.dest_ip !== params.dstIp) return false;
          if (params.communityId && event.community_id !== params.communityId) return false;
          return true;
        });

        const correlations = events.slice(0, params.limit).map((e) => ({
          suricataAlert: {
            timestamp: e.timestamp,
            signature: e.alert?.signature,
            signatureId: e.alert?.signature_id,
            category: e.alert?.category,
            severity: e.alert?.severity,
            src: `${e.src_ip}:${e.src_port ?? ""}`,
            dst: `${e.dest_ip}:${e.dest_port ?? ""}`,
            proto: e.proto,
            communityId: e.community_id,
            flowId: e.flow_id,
            flow: e.flow,
            http: e.http,
            tls: e.tls,
            dns: e.dns,
          },
          zeekCorrelation: {
            note: "Use the following Zeek MCP tools to investigate this alert further",
            suggestedTools: [
              {
                tool: "zeek_investigate_host",
                params: { ip: e.src_ip },
                reason: "Full cross-log investigation of the alert source",
              },
              {
                tool: "zeek_query_connections",
                params: {
                  srcIp: e.src_ip,
                  dstIp: e.dest_ip,
                  dstPort: e.dest_port,
                  timeFrom: new Date(new Date(e.timestamp).getTime() - 300000).toISOString(),
                  timeTo: new Date(new Date(e.timestamp).getTime() + 300000).toISOString(),
                },
                reason: "Find the exact Zeek connection record for this alert (5-min window)",
              },
              ...(e.http ? [{
                tool: "zeek_query_http" as const,
                params: { srcIp: e.src_ip, host: e.http.hostname },
                reason: "Check HTTP activity from the alert source",
              }] : []),
              ...(e.tls ? [{
                tool: "zeek_query_ssl" as const,
                params: { srcIp: e.src_ip, serverName: e.tls.sni },
                reason: "Check TLS connections from the alert source",
              }] : []),
              ...(e.dns ? [{
                tool: "zeek_query_dns" as const,
                params: { srcIp: e.src_ip },
                reason: "Check DNS queries from the alert source",
              }] : []),
            ],
          },
        }));

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              count: correlations.length,
              correlations,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error correlating alerts: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "suricata_eve_stats",
    "Get Suricata engine statistics from eve.json stats events: packet counts, decoder stats, flow metrics, and detection engine performance.",
    {},
    async () => {
      try {
        // Stats events are typically at the end of the log
        const events = await tailEveLog(config.eveLogPath, 100, (event) => {
          return event.event_type === "stats";
        });

        if (events.length === 0) {
          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify({ message: "No stats events found in eve.json" }),
            }],
          };
        }

        // Get the most recent stats event
        const latest = events[0] as unknown as Record<string, unknown>;

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              timestamp: latest.timestamp,
              stats: latest.stats,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error reading Suricata stats: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}
