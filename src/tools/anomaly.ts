import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import { executeQuery } from "../query/engine.js";
import { detectConnectionAnomalies } from "../analytics/anomaly.js";

export function registerAnomalyTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_detect_anomalies",
    "Run statistical anomaly detection across connection logs. Detects port scanning, data exfiltration (statistical outliers in bytes sent), and high-volume connections to unusual ports without identified services.",
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      minSeverity: z.enum(["low", "medium", "high", "critical"]).default("low").describe("Minimum severity to include (default: low)"),
    },
    async (params) => {
      try {
        const records = await executeQuery(config, {
          logType: "conn",
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: config.maxResults,
        });

        const anomalies = detectConnectionAnomalies(records);

        const severityOrder = { low: 0, medium: 1, high: 2, critical: 3 };
        const minLevel = severityOrder[params.minSeverity];
        const filtered = anomalies.filter(
          (a) => severityOrder[a.severity] >= minLevel,
        );

        const bySeverity = {
          critical: filtered.filter((a) => a.severity === "critical").length,
          high: filtered.filter((a) => a.severity === "high").length,
          medium: filtered.filter((a) => a.severity === "medium").length,
          low: filtered.filter((a) => a.severity === "low").length,
        };

        const byType: Record<string, number> = {};
        for (const a of filtered) {
          byType[a.type] = (byType[a.type] ?? 0) + 1;
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalConnectionsAnalyzed: records.length,
              anomaliesFound: filtered.length,
              bySeverity,
              byType,
              anomalies: filtered,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error detecting anomalies: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}
