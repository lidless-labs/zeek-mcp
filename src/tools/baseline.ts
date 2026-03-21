import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import { executeQuery } from "../query/engine.js";
import { topN, groupBy, sumField, countUnique, avgField } from "../query/aggregation.js";

export function registerBaselineTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_network_baseline",
    "Generate a statistical baseline of normal network activity. Calculates averages, standard deviations, and distributions for connections, bytes, services, and protocols. Use as a reference point to identify deviations that may indicate compromise.",
    {
      timeFrom: z.string().optional().describe("Baseline period start (ISO 8601)"),
      timeTo: z.string().optional().describe("Baseline period end (ISO 8601)"),
    },
    async (params) => {
      try {
        const records = await executeQuery(config, {
          logType: "conn",
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: config.maxResults,
        });

        if (records.length === 0) {
          return {
            content: [{ type: "text" as const, text: JSON.stringify({ message: "No connection records found for baseline period" }) }],
          };
        }

        // Calculate byte statistics
        const origBytes = records.map((r) => (r.orig_bytes as number) ?? 0).filter((b) => b > 0);
        const respBytes = records.map((r) => (r.resp_bytes as number) ?? 0).filter((b) => b > 0);
        const durations = records.map((r) => (r.duration as number) ?? 0).filter((d) => d > 0);

        const origByteStats = calculateStats(origBytes);
        const respByteStats = calculateStats(respBytes);
        const durationStats = calculateStats(durations);

        // Time span
        const timestamps = records.map((r) => r.ts).sort((a, b) => a - b);
        const timeSpanSeconds = timestamps.length >= 2
          ? timestamps[timestamps.length - 1] - timestamps[0]
          : 0;
        const connectionsPerMinute = timeSpanSeconds > 0
          ? records.length / (timeSpanSeconds / 60)
          : 0;

        // Hourly distribution
        const hourCounts: number[] = new Array(24).fill(0);
        for (const r of records) {
          const hour = new Date(r.ts * 1000).getUTCHours();
          hourCounts[hour]++;
        }

        // Internal vs external
        const internalPrefixes = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "fe80:"];
        const isInternal = (ip: string) => internalPrefixes.some((p) => ip.startsWith(p));

        let internalToInternal = 0;
        let internalToExternal = 0;
        let externalToInternal = 0;
        let externalToExternal = 0;

        for (const r of records) {
          const srcInt = isInternal(String(r["id.orig_h"] ?? ""));
          const dstInt = isInternal(String(r["id.resp_h"] ?? ""));
          if (srcInt && dstInt) internalToInternal++;
          else if (srcInt && !dstInt) internalToExternal++;
          else if (!srcInt && dstInt) externalToInternal++;
          else externalToExternal++;
        }

        const baseline = {
          period: {
            from: new Date(timestamps[0] * 1000).toISOString(),
            to: new Date(timestamps[timestamps.length - 1] * 1000).toISOString(),
            durationHours: Math.round(timeSpanSeconds / 3600 * 10) / 10,
          },
          volume: {
            totalConnections: records.length,
            connectionsPerMinute: Math.round(connectionsPerMinute * 100) / 100,
            uniqueSourceIps: countUnique(records, "id.orig_h"),
            uniqueDestIps: countUnique(records, "id.resp_h"),
            totalBytesSent: sumField(records, "orig_bytes"),
            totalBytesReceived: sumField(records, "resp_bytes"),
          },
          byteStatistics: {
            origBytes: origByteStats,
            respBytes: respByteStats,
          },
          durationStatistics: durationStats,
          trafficFlow: {
            internalToInternal,
            internalToExternal,
            externalToInternal,
            externalToExternal,
          },
          protocolDistribution: groupBy(records, "proto"),
          serviceDistribution: groupBy(records, "service"),
          connStateDistribution: groupBy(records, "conn_state"),
          topSourceIps: topN(records, "id.orig_h", 15),
          topDestIps: topN(records, "id.resp_h", 15),
          topPorts: topN(records, "id.resp_p", 15),
          hourlyDistribution: hourCounts.map((count, hour) => ({
            hour,
            connections: count,
            percentage: Math.round((count / records.length) * 10000) / 100,
          })),
          thresholds: {
            note: "Suggested alerting thresholds based on observed patterns",
            highBytesThreshold: origByteStats.mean + 3 * origByteStats.stdDev,
            longConnectionThreshold: durationStats.mean + 3 * durationStats.stdDev,
            highConnectionRatePerMinute: connectionsPerMinute * 3,
          },
        };

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify(baseline, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error generating baseline: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "zeek_detect_outliers",
    "Compare current network activity against a baseline and identify statistical outliers. Flags hosts with unusual byte volumes, connection counts, port diversity, or timing patterns that deviate significantly from the norm.",
    {
      timeFrom: z.string().optional().describe("Current period start (ISO 8601)"),
      timeTo: z.string().optional().describe("Current period end (ISO 8601)"),
      stdDevThreshold: z.number().min(1).max(10).default(3).describe("Standard deviations from mean to flag (default 3)"),
    },
    async (params) => {
      try {
        const records = await executeQuery(config, {
          logType: "conn",
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: config.maxResults,
        });

        if (records.length < 10) {
          return {
            content: [{ type: "text" as const, text: JSON.stringify({ message: "Insufficient data for outlier detection (need 10+ records)" }) }],
          };
        }

        const outliers: Array<{
          type: string;
          host: string;
          metric: string;
          value: number;
          mean: number;
          stdDev: number;
          deviations: number;
          severity: string;
          context: Record<string, unknown>;
        }> = [];

        // --- Outlier 1: Bytes sent per source host ---
        const srcBytes = new Map<string, number>();
        const srcConnCounts = new Map<string, number>();
        const srcPortDiversity = new Map<string, Set<number>>();

        for (const r of records) {
          const src = String(r["id.orig_h"] ?? "");
          const bytes = (r.orig_bytes as number) ?? 0;
          const dstPort = r["id.resp_p"] as number;

          srcBytes.set(src, (srcBytes.get(src) ?? 0) + bytes);
          srcConnCounts.set(src, (srcConnCounts.get(src) ?? 0) + 1);

          if (!srcPortDiversity.has(src)) srcPortDiversity.set(src, new Set());
          if (dstPort) srcPortDiversity.get(src)!.add(dstPort);
        }

        // Byte volume outliers
        const byteValues = [...srcBytes.values()];
        const byteStats = calculateStats(byteValues);

        for (const [host, bytes] of srcBytes) {
          if (byteStats.stdDev === 0) continue;
          const devs = (bytes - byteStats.mean) / byteStats.stdDev;
          if (devs >= params.stdDevThreshold) {
            outliers.push({
              type: "high_bytes",
              host,
              metric: "bytes_sent",
              value: bytes,
              mean: byteStats.mean,
              stdDev: byteStats.stdDev,
              deviations: Math.round(devs * 100) / 100,
              severity: devs >= 5 ? "critical" : devs >= 4 ? "high" : "medium",
              context: {
                bytesHuman: formatBytes(bytes),
                meanHuman: formatBytes(byteStats.mean),
                connections: srcConnCounts.get(host),
              },
            });
          }
        }

        // Connection count outliers
        const connValues = [...srcConnCounts.values()];
        const connStats = calculateStats(connValues);

        for (const [host, count] of srcConnCounts) {
          if (connStats.stdDev === 0) continue;
          const devs = (count - connStats.mean) / connStats.stdDev;
          if (devs >= params.stdDevThreshold) {
            outliers.push({
              type: "high_connections",
              host,
              metric: "connection_count",
              value: count,
              mean: connStats.mean,
              stdDev: connStats.stdDev,
              deviations: Math.round(devs * 100) / 100,
              severity: devs >= 5 ? "critical" : devs >= 4 ? "high" : "medium",
              context: {
                portDiversity: srcPortDiversity.get(host)?.size ?? 0,
                bytesTotal: srcBytes.get(host),
              },
            });
          }
        }

        // Port diversity outliers (potential scanning)
        const portDivValues = [...srcPortDiversity.entries()].map(([, ports]) => ports.size);
        const portDivStats = calculateStats(portDivValues);

        for (const [host, ports] of srcPortDiversity) {
          if (portDivStats.stdDev === 0) continue;
          const devs = (ports.size - portDivStats.mean) / portDivStats.stdDev;
          if (devs >= params.stdDevThreshold && ports.size > 20) {
            outliers.push({
              type: "port_diversity",
              host,
              metric: "unique_dest_ports",
              value: ports.size,
              mean: portDivStats.mean,
              stdDev: portDivStats.stdDev,
              deviations: Math.round(devs * 100) / 100,
              severity: ports.size > 100 ? "high" : "medium",
              context: {
                connections: srcConnCounts.get(host),
                samplePorts: [...ports].slice(0, 20),
              },
            });
          }
        }

        // Sort by deviation
        outliers.sort((a, b) => b.deviations - a.deviations);

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalConnectionsAnalyzed: records.length,
              uniqueHosts: srcBytes.size,
              stdDevThreshold: params.stdDevThreshold,
              outliersFound: outliers.length,
              bySeverity: {
                critical: outliers.filter((o) => o.severity === "critical").length,
                high: outliers.filter((o) => o.severity === "high").length,
                medium: outliers.filter((o) => o.severity === "medium").length,
              },
              byType: {
                high_bytes: outliers.filter((o) => o.type === "high_bytes").length,
                high_connections: outliers.filter((o) => o.type === "high_connections").length,
                port_diversity: outliers.filter((o) => o.type === "port_diversity").length,
              },
              outliers,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error detecting outliers: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

interface Stats {
  count: number;
  mean: number;
  median: number;
  stdDev: number;
  min: number;
  max: number;
  p95: number;
  p99: number;
}

function calculateStats(values: number[]): Stats {
  if (values.length === 0) {
    return { count: 0, mean: 0, median: 0, stdDev: 0, min: 0, max: 0, p95: 0, p99: 0 };
  }

  const sorted = [...values].sort((a, b) => a - b);
  const count = sorted.length;
  const mean = sorted.reduce((a, b) => a + b, 0) / count;
  const variance = sorted.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / count;
  const stdDev = Math.sqrt(variance);

  return {
    count,
    mean: Math.round(mean * 100) / 100,
    median: sorted[Math.floor(count / 2)],
    stdDev: Math.round(stdDev * 100) / 100,
    min: sorted[0],
    max: sorted[count - 1],
    p95: sorted[Math.floor(count * 0.95)],
    p99: sorted[Math.floor(count * 0.99)],
  };
}

function formatBytes(bytes: number): string {
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}
