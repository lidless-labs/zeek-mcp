import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import { executeQuery, type FilterDef } from "../query/engine.js";

export function registerHttpTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_query_http",
    "Search Zeek HTTP request logs. Supports wildcard matching on host and URI, user agent filtering, and status code filtering.",
    {
      srcIp: z.string().optional().describe("Source IP address"),
      host: z.string().optional().describe("HTTP Host header (supports wildcards)"),
      uri: z.string().optional().describe("URI path (supports wildcards)"),
      method: z.string().optional().describe("HTTP method (GET, POST, PUT, DELETE, etc.)"),
      statusCode: z.number().int().optional().describe("HTTP response status code"),
      userAgent: z.string().optional().describe("User-Agent string (partial match)"),
      mimeType: z.string().optional().describe("Response MIME type"),
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
        if (params.host) {
          filters.push({
            field: "host",
            op: params.host.includes("*") ? "wildcard" : "contains",
            value: params.host,
          });
        }
        if (params.uri) {
          filters.push({
            field: "uri",
            op: params.uri.includes("*") ? "wildcard" : "contains",
            value: params.uri,
          });
        }
        if (params.method) {
          filters.push({ field: "method", op: "eq", value: params.method.toUpperCase() });
        }
        if (params.statusCode !== undefined) {
          filters.push({ field: "status_code", op: "eq", value: params.statusCode });
        }
        if (params.userAgent) {
          filters.push({ field: "user_agent", op: "contains", value: params.userAgent });
        }
        if (params.mimeType) {
          filters.push({ field: "resp_mime_types", op: "contains", value: params.mimeType });
        }

        const records = await executeQuery(config, {
          logType: "http",
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
              requests: records.map(formatHttp),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error querying HTTP: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "zeek_suspicious_http",
    "Find suspicious HTTP activity including POSTs to raw IPs, unusual user agents, large POST bodies, requests to high ports, and base64 in URLs.",
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
    },
    async (params) => {
      try {
        const records = await executeQuery(config, {
          logType: "http",
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: config.maxResults,
        });

        const suspicious: Array<{
          record: Record<string, unknown>;
          reasons: string[];
        }> = [];

        const suspiciousAgents = [
          "curl", "wget", "python-requests", "python-urllib",
          "go-http-client", "powershell", "certutil",
        ];

        for (const record of records) {
          const reasons: string[] = [];
          const host = String(record.host ?? "");
          const uri = String(record.uri ?? "");
          const method = String(record.method ?? "");
          const userAgent = String(record.user_agent ?? "").toLowerCase();
          const respPort = record["id.resp_p"] as number;
          const requestBodyLen = record.request_body_len as number;

          if (host && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) && method === "POST") {
            reasons.push("POST to raw IP address (no domain)");
          }

          for (const agent of suspiciousAgents) {
            if (userAgent.includes(agent)) {
              reasons.push(`Suspicious user agent: ${agent}`);
              break;
            }
          }

          if (requestBodyLen && requestBodyLen > 1048576) {
            reasons.push(`Large POST body (${(requestBodyLen / 1048576).toFixed(1)} MB) - potential data exfiltration`);
          }

          if (respPort && respPort > 8080 && respPort !== 8443 && respPort !== 8888) {
            reasons.push(`Request to high port: ${respPort}`);
          }

          if (/[A-Za-z0-9+/]{20,}={0,2}/.test(uri)) {
            reasons.push("Possible base64 content in URL");
          }

          if (/\.(exe|dll|bat|ps1|vbs|scr|cmd)(\?|$)/i.test(uri)) {
            reasons.push("Request for executable file");
          }

          if (reasons.length > 0) {
            suspicious.push({
              record: formatHttp(record),
              reasons,
            });
          }
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalAnalyzed: records.length,
              suspiciousCount: suspicious.length,
              suspicious: suspicious.slice(0, 100),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error checking suspicious HTTP: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

function formatHttp(record: Record<string, unknown>): Record<string, unknown> {
  return {
    timestamp: record.ts ? new Date((record.ts as number) * 1000).toISOString() : undefined,
    uid: record.uid,
    srcIp: record["id.orig_h"],
    method: record.method,
    host: record.host,
    uri: record.uri,
    statusCode: record.status_code,
    userAgent: record.user_agent,
    requestBodyLen: record.request_body_len,
    responseBodyLen: record.response_body_len,
    mimeTypes: record.resp_mime_types,
  };
}
