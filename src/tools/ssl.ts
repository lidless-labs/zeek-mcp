import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import { executeQuery, type FilterDef } from "../query/engine.js";

export function registerSslTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_query_ssl",
    "Search Zeek SSL/TLS connection logs. Filter by SNI hostname, TLS version, certificate validation status, subject, and issuer.",
    {
      serverName: z.string().optional().describe("SNI hostname (supports wildcards)"),
      srcIp: z.string().optional().describe("Source IP address"),
      dstIp: z.string().optional().describe("Destination IP address"),
      version: z.string().optional().describe("TLS version (TLSv10, TLSv11, TLSv12, TLSv13, SSLv3)"),
      validationStatus: z.string().optional().describe("Certificate validation status (ok, self signed certificate, etc.)"),
      subject: z.string().optional().describe("Certificate subject (partial match)"),
      issuer: z.string().optional().describe("Certificate issuer (partial match)"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().int().min(1).max(10000).default(100).describe("Max results"),
    },
    async (params) => {
      try {
        const filters: FilterDef[] = [];

        if (params.serverName) {
          filters.push({
            field: "server_name",
            op: params.serverName.includes("*") ? "wildcard" : "contains",
            value: params.serverName,
          });
        }
        if (params.srcIp) {
          filters.push({ field: "id.orig_h", op: params.srcIp.includes("/") ? "cidr" : "eq", value: params.srcIp });
        }
        if (params.dstIp) {
          filters.push({ field: "id.resp_h", op: params.dstIp.includes("/") ? "cidr" : "eq", value: params.dstIp });
        }
        if (params.version) {
          filters.push({ field: "version", op: "eq", value: params.version });
        }
        if (params.validationStatus) {
          filters.push({ field: "validation_status", op: "contains", value: params.validationStatus });
        }
        if (params.subject) {
          filters.push({ field: "subject", op: "contains", value: params.subject });
        }
        if (params.issuer) {
          filters.push({ field: "issuer", op: "contains", value: params.issuer });
        }

        const records = await executeQuery(config, {
          logType: "ssl",
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
              connections: records.map(formatSsl),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error querying SSL: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "zeek_expired_certs",
    "Find connections using expired or self-signed certificates - potential indicators of man-in-the-middle or malicious infrastructure.",
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
    },
    async (params) => {
      try {
        const records = await executeQuery(config, {
          logType: "ssl",
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: config.maxResults,
        });

        const flagged: Array<{
          record: Record<string, unknown>;
          issues: string[];
        }> = [];

        for (const record of records) {
          const issues: string[] = [];
          const validationStatus = String(record.validation_status ?? "");

          if (validationStatus && validationStatus !== "ok" && validationStatus !== "-") {
            if (validationStatus.includes("self signed")) {
              issues.push("Self-signed certificate");
            }
            if (validationStatus.includes("expired")) {
              issues.push("Expired certificate");
            }
            if (validationStatus.includes("unable to get local issuer")) {
              issues.push("Unknown certificate authority");
            }
            if (issues.length === 0) {
              issues.push(`Validation failure: ${validationStatus}`);
            }
          }

          const version = String(record.version ?? "");
          if (version === "SSLv3" || version === "TLSv10") {
            issues.push(`Deprecated protocol version: ${version}`);
          }

          if (issues.length > 0) {
            flagged.push({
              record: formatSsl(record),
              issues,
            });
          }
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalAnalyzed: records.length,
              flaggedCount: flagged.length,
              flagged: flagged.slice(0, 200),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error checking expired certs: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

function formatSsl(record: Record<string, unknown>): Record<string, unknown> {
  return {
    timestamp: record.ts ? new Date((record.ts as number) * 1000).toISOString() : undefined,
    uid: record.uid,
    src: `${record["id.orig_h"]}:${record["id.orig_p"]}`,
    dst: `${record["id.resp_h"]}:${record["id.resp_p"]}`,
    version: record.version,
    cipher: record.cipher,
    serverName: record.server_name,
    subject: record.subject,
    issuer: record.issuer,
    validationStatus: record.validation_status,
  };
}
