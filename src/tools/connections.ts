import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import { executeQuery, type FilterDef } from "../query/engine.js";
import { groupBy, sumField, countUnique, topN } from "../query/aggregation.js";

export function registerConnectionTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_query_connections",
    "Search Zeek connection logs with flexible filters. Supports CIDR notation for IPs, connection state filtering, duration/byte thresholds, and time ranges.",
    {
      srcIp: z.string().optional().describe("Source IP address (supports CIDR notation like 10.0.0.0/8)"),
      dstIp: z.string().optional().describe("Destination IP address (supports CIDR notation)"),
      srcPort: z.number().int().optional().describe("Source port number"),
      dstPort: z.number().int().optional().describe("Destination port number"),
      proto: z.enum(["tcp", "udp", "icmp"]).optional().describe("Transport protocol"),
      service: z.string().optional().describe("Detected service (http, ssl, dns, ssh, smtp, etc.)"),
      connState: z.string().optional().describe("Connection state (S0, S1, SF, REJ, RSTO, etc.)"),
      minDuration: z.number().optional().describe("Minimum connection duration in seconds"),
      maxDuration: z.number().optional().describe("Maximum connection duration in seconds"),
      minBytes: z.number().optional().describe("Minimum total bytes transferred"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().int().min(1).max(10000).default(100).describe("Max results (default 100)"),
      sortBy: z.string().optional().describe("Sort field (default: ts descending)"),
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
        if (params.srcPort !== undefined) {
          filters.push({ field: "id.orig_p", op: "eq", value: params.srcPort });
        }
        if (params.dstPort !== undefined) {
          filters.push({ field: "id.resp_p", op: "eq", value: params.dstPort });
        }
        if (params.proto) {
          filters.push({ field: "proto", op: "eq", value: params.proto });
        }
        if (params.service) {
          filters.push({ field: "service", op: "eq", value: params.service });
        }
        if (params.connState) {
          filters.push({ field: "conn_state", op: "eq", value: params.connState });
        }
        if (params.minDuration !== undefined) {
          filters.push({ field: "duration", op: "gte", value: params.minDuration });
        }
        if (params.maxDuration !== undefined) {
          filters.push({ field: "duration", op: "lte", value: params.maxDuration });
        }
        if (params.minBytes !== undefined) {
          filters.push({ field: "orig_bytes", op: "gte", value: params.minBytes });
        }

        const records = await executeQuery(config, {
          logType: "conn",
          filters,
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          sortBy: params.sortBy,
          limit: params.limit,
        });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              count: records.length,
              connections: records.map(formatConnection),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error querying connections: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "zeek_connection_summary",
    "Get statistical summary of connections over a time period - top talkers, services, bytes, and connection counts.",
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      groupBy: z.enum(["src", "dst", "service", "port", "proto"]).optional().describe("Primary grouping dimension"),
    },
    async (params) => {
      try {
        const records = await executeQuery(config, {
          logType: "conn",
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: config.maxResults,
        });

        const groupField = {
          src: "id.orig_h",
          dst: "id.resp_h",
          service: "service",
          port: "id.resp_p",
          proto: "proto",
        }[params.groupBy ?? "src"];

        const summary = {
          totalConnections: records.length,
          totalBytes: sumField(records, "orig_bytes") + sumField(records, "resp_bytes"),
          uniqueSrcIps: countUnique(records, "id.orig_h"),
          uniqueDstIps: countUnique(records, "id.resp_h"),
          topSources: topN(records, "id.orig_h", 10),
          topDestinations: topN(records, "id.resp_h", 10),
          topServices: topN(records, "service", 10),
          topPorts: topN(records, "id.resp_p", 10),
          protocolDistribution: groupBy(records, "proto"),
          connStateDistribution: groupBy(records, "conn_state"),
          primaryGrouping: groupField ? groupBy(records, groupField) : undefined,
        };

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify(summary, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error generating connection summary: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "zeek_long_connections",
    "Find unusually long-lived connections that may indicate C2 beacons, tunnels, or persistent backdoors.",
    {
      minDuration: z.number().describe("Minimum connection duration in seconds"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().int().min(1).max(10000).default(100).describe("Max results"),
    },
    async (params) => {
      try {
        const records = await executeQuery(config, {
          logType: "conn",
          filters: [
            { field: "duration", op: "gte", value: params.minDuration },
          ],
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          sortBy: "duration",
          sortOrder: "desc",
          limit: params.limit,
        });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              count: records.length,
              minDurationFilter: params.minDuration,
              connections: records.map(formatConnection),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error querying long connections: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

function formatConnection(record: Record<string, unknown>): Record<string, unknown> {
  return {
    timestamp: record.ts ? new Date((record.ts as number) * 1000).toISOString() : undefined,
    uid: record.uid,
    src: `${record["id.orig_h"]}:${record["id.orig_p"]}`,
    dst: `${record["id.resp_h"]}:${record["id.resp_p"]}`,
    proto: record.proto,
    service: record.service,
    duration: record.duration,
    origBytes: record.orig_bytes,
    respBytes: record.resp_bytes,
    connState: record.conn_state,
    history: record.history,
  };
}
