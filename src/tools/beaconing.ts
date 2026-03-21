import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import { executeQuery } from "../query/engine.js";
import { detectBeaconing } from "../analytics/beaconing.js";

export function registerBeaconingTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_detect_beaconing",
    "Detect potential C2 beaconing by analyzing connection interval regularity. Finds source-destination pairs with suspiciously consistent callback intervals (low jitter). Higher scores indicate more regular beaconing patterns.",
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      srcIp: z.string().optional().describe("Filter by source IP"),
      dstIp: z.string().optional().describe("Filter by destination IP"),
      minConnections: z.number().int().min(3).default(10).describe("Minimum connections to consider a pair (default 10)"),
      maxJitterPercent: z.number().min(0).max(100).default(30).describe("Maximum jitter percentage to flag as beaconing (default 30)"),
      minScore: z.number().min(0).max(100).default(50).describe("Minimum beacon score to include in results (default 50)"),
    },
    async (params) => {
      try {
        const filters = [];
        if (params.srcIp) {
          filters.push({
            field: "id.orig_h",
            op: params.srcIp.includes("/") ? "cidr" as const : "eq" as const,
            value: params.srcIp,
          });
        }
        if (params.dstIp) {
          filters.push({
            field: "id.resp_h",
            op: params.dstIp.includes("/") ? "cidr" as const : "eq" as const,
            value: params.dstIp,
          });
        }

        const records = await executeQuery(config, {
          logType: "conn",
          filters,
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: config.maxResults,
        });

        const candidates = detectBeaconing(
          records,
          params.minConnections,
          params.maxJitterPercent,
        );

        const filtered = candidates.filter((c) => c.score >= params.minScore);

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalConnectionsAnalyzed: records.length,
              beaconCandidates: filtered.length,
              minConnectionsThreshold: params.minConnections,
              maxJitterThreshold: params.maxJitterPercent,
              minScoreThreshold: params.minScore,
              candidates: filtered.map((c) => ({
                ...c,
                avgIntervalHuman: formatInterval(c.avgInterval),
                riskLevel: c.score >= 90 ? "CRITICAL" :
                  c.score >= 75 ? "HIGH" :
                  c.score >= 60 ? "MEDIUM" : "LOW",
              })),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error detecting beaconing: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

function formatInterval(seconds: number): string {
  if (seconds >= 3600) return `${(seconds / 3600).toFixed(1)}h`;
  if (seconds >= 60) return `${(seconds / 60).toFixed(1)}m`;
  return `${seconds.toFixed(1)}s`;
}
