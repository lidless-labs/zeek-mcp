import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import { executeQuery, type FilterDef } from "../query/engine.js";
import { topN } from "../query/aggregation.js";

export function registerSshTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_query_ssh",
    "Search Zeek SSH connection logs. Filter by source/destination IP, authentication status, and connection direction.",
    {
      srcIp: z.string().optional().describe("Source IP address"),
      dstIp: z.string().optional().describe("Destination IP address"),
      authSuccess: z.boolean().optional().describe("Filter by authentication success/failure"),
      direction: z.string().optional().describe("Connection direction"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().int().min(1).max(10000).default(100).describe("Max results"),
    },
    async (params) => {
      try {
        const filters: FilterDef[] = [];

        if (params.srcIp) {
          filters.push({ field: "id.orig_h", op: params.srcIp.includes("/") ? "cidr" : "eq", value: params.srcIp });
        }
        if (params.dstIp) {
          filters.push({ field: "id.resp_h", op: params.dstIp.includes("/") ? "cidr" : "eq", value: params.dstIp });
        }
        if (params.authSuccess !== undefined) {
          filters.push({ field: "auth_success", op: "eq", value: params.authSuccess });
        }
        if (params.direction) {
          filters.push({ field: "direction", op: "eq", value: params.direction });
        }

        const records = await executeQuery(config, {
          logType: "ssh",
          filters,
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: params.limit,
        });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              count: records.length,
              connections: records.map(formatSsh),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error querying SSH: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "zeek_ssh_bruteforce",
    "Detect SSH brute force attempts by identifying sources with multiple failed authentication attempts exceeding a threshold.",
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      threshold: z.number().int().min(1).default(5).describe("Minimum failed attempts to flag (default 5)"),
    },
    async (params) => {
      try {
        const records = await executeQuery(config, {
          logType: "ssh",
          filters: [
            { field: "auth_success", op: "eq", value: false },
          ],
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: config.maxResults,
        });

        const srcCounts = new Map<string, {
          count: number;
          targets: Set<string>;
          firstSeen: number;
          lastSeen: number;
        }>();

        for (const record of records) {
          const src = String(record["id.orig_h"] ?? "");
          const dst = String(record["id.resp_h"] ?? "");
          const ts = record.ts as number;

          if (!srcCounts.has(src)) {
            srcCounts.set(src, {
              count: 0,
              targets: new Set(),
              firstSeen: ts,
              lastSeen: ts,
            });
          }

          const entry = srcCounts.get(src)!;
          entry.count++;
          entry.targets.add(dst);
          entry.firstSeen = Math.min(entry.firstSeen, ts);
          entry.lastSeen = Math.max(entry.lastSeen, ts);
        }

        const bruteForce = [...srcCounts.entries()]
          .filter(([, data]) => data.count >= params.threshold)
          .sort((a, b) => b[1].count - a[1].count)
          .map(([src, data]) => ({
            sourceIp: src,
            failedAttempts: data.count,
            uniqueTargets: data.targets.size,
            targets: [...data.targets].slice(0, 20),
            firstSeen: new Date(data.firstSeen * 1000).toISOString(),
            lastSeen: new Date(data.lastSeen * 1000).toISOString(),
          }));

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalFailedAuth: records.length,
              bruteForceSourceCount: bruteForce.length,
              threshold: params.threshold,
              sources: bruteForce,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error detecting SSH brute force: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

function formatSsh(record: Record<string, unknown>): Record<string, unknown> {
  return {
    timestamp: record.ts ? new Date((record.ts as number) * 1000).toISOString() : undefined,
    uid: record.uid,
    src: `${record["id.orig_h"]}:${record["id.orig_p"]}`,
    dst: `${record["id.resp_h"]}:${record["id.resp_p"]}`,
    authSuccess: record.auth_success,
    authAttempts: record.auth_attempts,
    direction: record.direction,
    client: record.client,
    server: record.server,
  };
}
