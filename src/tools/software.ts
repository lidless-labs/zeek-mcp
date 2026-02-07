import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { ZeekConfig } from "../config.js";
import { executeQuery, type FilterDef } from "../query/engine.js";

export function registerSoftwareTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "zeek_software_inventory",
    "List detected software and versions on the network from Zeek's protocol analysis. Useful for asset discovery and vulnerability assessment.",
    {
      host: z.string().optional().describe("Filter by host IP"),
      softwareType: z.string().optional().describe("Filter by software type (e.g. HTTP::BROWSER, HTTP::SERVER)"),
      timeFrom: z.string().optional().describe("Start time (ISO 8601)"),
      timeTo: z.string().optional().describe("End time (ISO 8601)"),
    },
    async (params) => {
      try {
        const filters: FilterDef[] = [];

        if (params.host) {
          filters.push({ field: "host", op: "eq", value: params.host });
        }
        if (params.softwareType) {
          filters.push({ field: "software_type", op: "contains", value: params.softwareType });
        }

        const records = await executeQuery(config, {
          logType: "software",
          filters,
          timeFrom: params.timeFrom,
          timeTo: params.timeTo,
          limit: config.maxResults,
        });

        const inventory = records.map((record) => {
          const versionParts = [
            record["version.major"],
            record["version.minor"],
            record["version.minor2"],
            record["version.minor3"],
          ].filter((v) => v !== undefined && v !== null);

          const version = versionParts.length > 0
            ? versionParts.join(".")
            : record.unparsed_version ?? "unknown";

          return {
            timestamp: record.ts ? new Date((record.ts as number) * 1000).toISOString() : undefined,
            host: record.host,
            softwareType: record.software_type,
            name: record.name,
            version,
            unparsedVersion: record.unparsed_version,
          };
        });

        const byHost = new Map<string, Set<string>>();
        for (const item of inventory) {
          const key = String(item.host);
          if (!byHost.has(key)) byHost.set(key, new Set());
          byHost.get(key)!.add(`${item.name} ${item.version}`);
        }

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              totalEntries: inventory.length,
              uniqueHosts: byHost.size,
              inventory,
              hostSummary: [...byHost.entries()]
                .sort((a, b) => b[1].size - a[1].size)
                .slice(0, 50)
                .map(([host, software]) => ({
                  host,
                  softwareCount: software.size,
                  software: [...software],
                })),
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error querying software: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}
