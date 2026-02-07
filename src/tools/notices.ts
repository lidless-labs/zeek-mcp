import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import { executeQuery, type FilterDef } from "../query/engine.js";

export function registerNoticeTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_query_notices",
    "Search Zeek security notices (built-in and custom detections). Notices include port scans, invalid certificates, protocol violations, and custom alerts.",
    {
      note: z.string().optional().describe("Notice type (e.g. Scan::Port_Scan, SSL::Invalid_Server_Cert)"),
      srcIp: z.string().optional().describe("Source IP address"),
      dstIp: z.string().optional().describe("Destination IP address"),
      msg: z.string().optional().describe("Message content search (partial match)"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().int().min(1).max(10000).default(100).describe("Max results"),
    },
    async (params) => {
      try {
        const filters: FilterDef[] = [];

        if (params.note) {
          filters.push({
            field: "note",
            op: params.note.includes("*") ? "wildcard" : "contains",
            value: params.note,
          });
        }
        if (params.srcIp) {
          filters.push({ field: "src", op: params.srcIp.includes("/") ? "cidr" : "eq", value: params.srcIp });
        }
        if (params.dstIp) {
          filters.push({ field: "dst", op: params.dstIp.includes("/") ? "cidr" : "eq", value: params.dstIp });
        }
        if (params.msg) {
          filters.push({ field: "msg", op: "contains", value: params.msg });
        }

        const records = await executeQuery(config, {
          logType: "notice",
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
              notices: records.map(formatNotice),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error querying notices: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

function formatNotice(record: Record<string, unknown>): Record<string, unknown> {
  return {
    timestamp: record.ts ? new Date((record.ts as number) * 1000).toISOString() : undefined,
    uid: record.uid,
    note: record.note,
    msg: record.msg,
    sub: record.sub,
    src: record.src,
    dst: record.dst,
    port: record.p,
    actions: record.actions,
  };
}
