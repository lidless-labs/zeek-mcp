import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as fs from "node:fs";
import * as path from "node:path";
import type { ZeekConfig } from "../config.js";
import { getSuricataConfig } from "./suricata.js";

export function registerSensorTools(
  server: McpServer,
  config: ZeekConfig,
): void {
  server.tool(
    "nids_sensor_status",
    "Get the current status of the NIDS sensor: available Zeek log files with sizes, record counts, and freshness. Also checks Suricata eve.json status. Use this to understand what data is available before running queries.",
    {},
    async () => {
      try {
        const zeekLogs = getLogInventory(config.logDir);
        const suricataConfig = getSuricataConfig();
        const suricataStatus = getFileStatus(suricataConfig.eveLogPath);
        const fastLogStatus = getFileStatus(suricataConfig.fastLogPath);

        const totalSize = zeekLogs.reduce((sum, l) => sum + l.sizeBytes, 0);

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              zeek: {
                logDirectory: config.logDir,
                logFormat: config.logFormat,
                maxResults: config.maxResults,
                archiveDirectory: config.logArchive,
                logs: zeekLogs,
                totalSizeHuman: formatBytes(totalSize),
                totalFiles: zeekLogs.length,
              },
              suricata: {
                eveLog: suricataStatus,
                fastLog: fastLogStatus,
              },
              health: {
                zeekActive: zeekLogs.some((l) => l.ageMinutes < 10),
                suricataActive: suricataStatus.exists && suricataStatus.ageMinutes !== undefined && suricataStatus.ageMinutes < 10,
                staleLogThresholdMinutes: 10,
              },
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error checking sensor status: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

interface LogFileInfo {
  name: string;
  logType: string;
  sizeBytes: number;
  sizeHuman: string;
  lastModified: string;
  ageMinutes: number;
  estimatedRecords: number;
}

function getLogInventory(logDir: string): LogFileInfo[] {
  if (!fs.existsSync(logDir)) {
    return [];
  }

  const files = fs.readdirSync(logDir);
  const now = Date.now();
  const logs: LogFileInfo[] = [];

  for (const file of files) {
    if (!file.endsWith(".log") && !file.endsWith(".log.gz")) continue;

    const filePath = path.join(logDir, file);
    try {
      const stat = fs.statSync(filePath);
      const logType = file.replace(/\.log(\.gz)?$/, "");
      const ageMs = now - stat.mtimeMs;

      // Estimate records: average ~200 bytes per TSV record, ~300 for JSON
      const avgRecordSize = file.endsWith(".gz") ? 600 : 250;
      const estimatedRecords = Math.round(stat.size / avgRecordSize);

      logs.push({
        name: file,
        logType,
        sizeBytes: stat.size,
        sizeHuman: formatBytes(stat.size),
        lastModified: new Date(stat.mtimeMs).toISOString(),
        ageMinutes: Math.round(ageMs / 60000),
        estimatedRecords,
      });
    } catch {
      // skip unreadable files
    }
  }

  return logs.sort((a, b) => b.sizeBytes - a.sizeBytes);
}

interface FileStatus {
  exists: boolean;
  path: string;
  sizeHuman?: string;
  sizeBytes?: number;
  lastModified?: string;
  ageMinutes?: number;
}

function getFileStatus(filePath: string): FileStatus {
  if (!fs.existsSync(filePath)) {
    return { exists: false, path: filePath };
  }

  try {
    const stat = fs.statSync(filePath);
    return {
      exists: true,
      path: filePath,
      sizeBytes: stat.size,
      sizeHuman: formatBytes(stat.size),
      lastModified: new Date(stat.mtimeMs).toISOString(),
      ageMinutes: Math.round((Date.now() - stat.mtimeMs) / 60000),
    };
  } catch {
    return { exists: false, path: filePath };
  }
}

function formatBytes(bytes: number): string {
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}
