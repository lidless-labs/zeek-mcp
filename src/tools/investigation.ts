import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import type { LogType } from "../types.js";
import { executeQuery, type FilterDef } from "../query/engine.js";
import { topN, sumField, countUnique } from "../query/aggregation.js";

export function registerInvestigationTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_investigate_host",
    "Comprehensive investigation of all activity for a specific host across all Zeek log types - connections, DNS, HTTP, SSL, files, notices, SSH, and software.",
    {
      ip: z.string().describe("IP address to investigate"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
    },
    async (params) => {
      try {
        const timeRange = {
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
        };

        const ipFilters = (field: string): FilterDef[] => [
          { field, op: "eq", value: params.ip },
        ];

        const [
          connSrc,
          connDst,
          dnsRecords,
          httpRecords,
          sslRecords,
          sshRecords,
          noticeRecords,
          softwareRecords,
        ] = await Promise.all([
          executeQuery(config, {
            logType: "conn",
            filters: ipFilters("id.orig_h"),
            ...timeRange,
            limit: config.maxResults,
          }),
          executeQuery(config, {
            logType: "conn",
            filters: ipFilters("id.resp_h"),
            ...timeRange,
            limit: config.maxResults,
          }),
          safeQuery(config, "dns", [
            { field: "id.orig_h", op: "eq" as const, value: params.ip },
          ], timeRange),
          safeQuery(config, "http", ipFilters("id.orig_h"), timeRange),
          safeQuery(config, "ssl", ipFilters("id.orig_h"), timeRange),
          safeQuery(config, "ssh", ipFilters("id.orig_h"), timeRange),
          safeQuery(config, "notice", [
            { field: "src", op: "eq" as const, value: params.ip },
          ], timeRange),
          safeQuery(config, "software", [
            { field: "host", op: "eq" as const, value: params.ip },
          ], timeRange),
        ]);

        const allConn = [...connSrc, ...connDst];
        const totalOrigBytes = sumField(connSrc, "orig_bytes");
        const totalRespBytes = sumField(connSrc, "resp_bytes");

        const investigation = {
          host: params.ip,
          connectionSummary: {
            asSource: connSrc.length,
            asDestination: connDst.length,
            totalBytes: totalOrigBytes + totalRespBytes,
            bytesSent: totalOrigBytes,
            bytesReceived: totalRespBytes,
            topDestinations: topN(connSrc, "id.resp_h", 10),
            topSources: topN(connDst, "id.orig_h", 10),
            topServices: topN(allConn, "service", 10),
            topPorts: topN(connSrc, "id.resp_p", 10),
            uniqueDestinations: countUnique(connSrc, "id.resp_h"),
          },
          dns: {
            queryCount: dnsRecords.length,
            topDomains: topN(dnsRecords, "query", 20),
            uniqueDomains: countUnique(dnsRecords, "query"),
          },
          http: {
            requestCount: httpRecords.length,
            topHosts: topN(httpRecords, "host", 10),
            topUris: topN(httpRecords, "uri", 10),
            topUserAgents: topN(httpRecords, "user_agent", 5),
          },
          ssl: {
            connectionCount: sslRecords.length,
            topServerNames: topN(sslRecords, "server_name", 10),
          },
          ssh: {
            connectionCount: sshRecords.length,
            connections: sshRecords.slice(0, 20).map((r) => ({
              dst: `${r["id.resp_h"]}:${r["id.resp_p"]}`,
              authSuccess: r.auth_success,
              client: r.client,
            })),
          },
          notices: {
            count: noticeRecords.length,
            notices: noticeRecords.slice(0, 20).map((r) => ({
              note: r.note,
              msg: r.msg,
              timestamp: r.ts ? new Date((r.ts as number) * 1000).toISOString() : undefined,
            })),
          },
          software: softwareRecords.map((r) => ({
            type: r.software_type,
            name: r.name,
            version: [r["version.major"], r["version.minor"], r["version.minor2"]]
              .filter((v) => v !== undefined)
              .join("."),
          })),
        };

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify(investigation, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error investigating host: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "zeek_investigate_uid",
    "Follow a specific connection UID across all Zeek log types to reconstruct the complete session lifecycle.",
    {
      uid: z.string().describe("Zeek connection UID to investigate"),
    },
    async (params) => {
      try {
        const uidFilter: FilterDef[] = [
          { field: "uid", op: "eq", value: params.uid },
        ];

        const logTypes: LogType[] = ["conn", "dns", "http", "ssl", "files", "notice", "weird", "ssh", "smtp"];

        const results = await Promise.all(
          logTypes.map(async (logType) => {
            try {
              const records = await executeQuery(config, {
                logType,
                filters: logType === "files"
                  ? [{ field: "conn_uids", op: "contains", value: params.uid }]
                  : uidFilter,
                limit: 100,
              });
              return { logType, records };
            } catch {
              return { logType, records: [] };
            }
          }),
        );

        const session: Record<string, unknown> = {
          uid: params.uid,
        };

        for (const { logType, records } of results) {
          if (records.length > 0) {
            session[logType] = records.map((r) => {
              const formatted: Record<string, unknown> = { ...r };
              if (formatted.ts) {
                formatted.timestamp = new Date((formatted.ts as number) * 1000).toISOString();
              }
              return formatted;
            });
          }
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify(session, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error investigating UID: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

async function safeQuery(
  config: ZeekConfig,
  logType: LogType,
  filters: FilterDef[],
  timeRange: { timeFrom?: string; timeTo?: string },
) {
  try {
    return await executeQuery(config, {
      logType,
      filters,
      ...timeRange,
      limit: config.maxResults,
    });
  } catch {
    return [];
  }
}
