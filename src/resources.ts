import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { LOG_FIELD_DEFINITIONS, type LogType } from "./types.js";

export function registerResources(server: McpServer): void {
  server.resource(
    "log-types",
    "zeek://log-types",
    {
      description: "List of all Zeek log types with their field descriptions",
      mimeType: "application/json",
    },
    async () => {
      const logTypes = Object.entries(LOG_FIELD_DEFINITIONS).map(
        ([logType, fields]) => ({
          logType,
          filename: `${logType}.log`,
          fields: fields.map((f) => ({
            name: f.name,
            type: f.type,
            description: f.description,
          })),
        }),
      );

      return {
        contents: [
          {
            uri: "zeek://log-types",
            mimeType: "application/json",
            text: JSON.stringify(logTypes, null, 2),
          },
        ],
      };
    },
  );

  server.resource(
    "stats",
    "zeek://stats",
    {
      description: "Current Zeek log directory statistics and available log files",
      mimeType: "application/json",
    },
    async () => {
      const stats = {
        availableLogTypes: Object.keys(LOG_FIELD_DEFINITIONS) as LogType[],
        note: "Actual file availability depends on the Zeek sensor configuration and log directory contents",
      };

      return {
        contents: [
          {
            uri: "zeek://stats",
            mimeType: "application/json",
            text: JSON.stringify(stats, null, 2),
          },
        ],
      };
    },
  );
}
