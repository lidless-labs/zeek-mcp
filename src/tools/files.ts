import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import { executeQuery, type FilterDef } from "../query/engine.js";

const EXECUTABLE_MIME_TYPES = [
  "application/x-dosexec",
  "application/x-executable",
  "application/x-mach-binary",
  "application/x-elf",
  "application/x-sharedlib",
  "application/x-object",
  "application/x-pie-executable",
  "application/vnd.microsoft.portable-executable",
  "application/x-msdos-program",
  "application/x-msdownload",
  "application/x-shellscript",
  "application/x-bat",
  "application/x-powershell",
  "text/x-python",
  "text/x-perl",
  "text/x-shellscript",
  "application/java-archive",
  "application/x-java-applet",
];

export function registerFileTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_query_files",
    "Search Zeek file extraction logs. Filter by MIME type, filename, hash values, source IP, and file size.",
    {
      mimeType: z.string().optional().describe("MIME type (application/x-dosexec, application/pdf, etc.)"),
      filename: z.string().optional().describe("Filename (supports wildcards)"),
      md5: z.string().optional().describe("MD5 hash"),
      sha256: z.string().optional().describe("SHA256 hash"),
      srcIp: z.string().optional().describe("Source IP (from tx_hosts)"),
      minSize: z.number().optional().describe("Minimum file size in bytes"),
      maxSize: z.number().optional().describe("Maximum file size in bytes"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
      limit: z.number().int().min(1).max(10000).default(100).describe("Max results"),
    },
    async (params) => {
      try {
        const filters: FilterDef[] = [];

        if (params.mimeType) {
          filters.push({ field: "mime_type", op: "contains", value: params.mimeType });
        }
        if (params.filename) {
          filters.push({
            field: "filename",
            op: params.filename.includes("*") ? "wildcard" : "contains",
            value: params.filename,
          });
        }
        if (params.md5) {
          filters.push({ field: "md5", op: "eq", value: params.md5 });
        }
        if (params.sha256) {
          filters.push({ field: "sha256", op: "eq", value: params.sha256 });
        }
        if (params.srcIp) {
          filters.push({ field: "tx_hosts", op: "contains", value: params.srcIp });
        }
        if (params.minSize !== undefined) {
          filters.push({ field: "total_bytes", op: "gte", value: params.minSize });
        }
        if (params.maxSize !== undefined) {
          filters.push({ field: "total_bytes", op: "lte", value: params.maxSize });
        }

        const records = await executeQuery(config, {
          logType: "files",
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
              files: records.map(formatFile),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error querying files: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "zeek_executable_downloads",
    "Find executable file transfers on the network - PE, ELF, Mach-O binaries and scripts that may indicate malware delivery.",
    {
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
    },
    async (params) => {
      try {
        const records = await executeQuery(config, {
          logType: "files",
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: config.maxResults,
        });

        const executables = records.filter((record) => {
          const mimeType = String(record.mime_type ?? "");
          return EXECUTABLE_MIME_TYPES.some((t) => mimeType.includes(t));
        });

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalFiles: records.length,
              executableCount: executables.length,
              executables: executables.map(formatFile),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error checking executables: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

function formatFile(record: Record<string, unknown>): Record<string, unknown> {
  return {
    timestamp: record.ts ? new Date((record.ts as number) * 1000).toISOString() : undefined,
    fuid: record.fuid,
    source: record.source,
    mimeType: record.mime_type,
    filename: record.filename,
    totalBytes: record.total_bytes,
    seenBytes: record.seen_bytes,
    md5: record.md5,
    sha1: record.sha1,
    sha256: record.sha256,
    txHosts: record.tx_hosts,
    rxHosts: record.rx_hosts,
    connUids: record.conn_uids,
  };
}
