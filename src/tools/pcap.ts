import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "node:fs";
import * as path from "node:path";
import * as child_process from "node:child_process";

export interface PcapConfig {
  pcapDir: string;
  zeekBinary: string;
  zeekContainer: string | null;
  outputDir: string;
}

export function getPcapConfig(): PcapConfig {
  return {
    pcapDir: process.env.PCAP_DIR ?? "/opt/nids/pcaps",
    zeekBinary: process.env.ZEEK_BINARY ?? "/usr/local/zeek/bin/zeek",
    zeekContainer: process.env.ZEEK_CONTAINER ?? "zeek",
    outputDir: process.env.PCAP_OUTPUT_DIR ?? "/tmp/zeek-pcap-analysis",
  };
}

function execCommand(cmd: string, timeoutMs = 60000): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    child_process.exec(cmd, { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      resolve({
        stdout: stdout?.toString() ?? "",
        stderr: stderr?.toString() ?? (error ? error.message : ""),
        code: typeof error?.code === "number" ? error.code : (error ? 1 : 0),
      });
    });
  });
}

// Validate script names to prevent command injection
function validateScriptName(script: string): boolean {
  return /^[a-zA-Z0-9_.\-\/]+$/.test(script);
}

export function registerPcapTools(server: McpServer): void {
  const config = getPcapConfig();

  server.tool(
    "pcap_list",
    "List available PCAP files in the capture directory with file sizes and timestamps.",
    {},
    async () => {
      try {
        if (!fs.existsSync(config.pcapDir)) {
          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify({
                error: `PCAP directory not found: ${config.pcapDir}`,
                hint: "Set PCAP_DIR environment variable",
              }),
            }],
            isError: true,
          };
        }

        const files = fs.readdirSync(config.pcapDir);
        const pcaps = files
          .filter((f) => /\.(pcap|pcapng|cap)$/i.test(f))
          .map((f) => {
            const filePath = path.join(config.pcapDir, f);
            const stat = fs.statSync(filePath);
            return {
              name: f,
              path: filePath,
              sizeBytes: stat.size,
              sizeHuman: formatBytes(stat.size),
              lastModified: new Date(stat.mtimeMs).toISOString(),
            };
          })
          .sort((a, b) => b.sizeBytes - a.sizeBytes);

        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({
              directory: config.pcapDir,
              count: pcaps.length,
              files: pcaps,
            }, null, 2),
          }],
        };
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error listing PCAPs: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "pcap_analyze",
    "Replay a PCAP file through Zeek and return the generated log summary. Creates connection, DNS, HTTP, SSL, and other logs from the packet capture. Useful for forensic analysis of captured traffic.",
    {
      filename: z.string().describe("PCAP filename (from pcap_list) or full path"),
      scripts: z.array(z.string()).optional().describe("Additional Zeek scripts to load (e.g. 'protocols/ssl/log-hostcerts-only')"),
      timeoutSeconds: z.number().int().min(10).max(600).default(120).describe("Analysis timeout in seconds"),
    },
    async (params) => {
      try {
        // Validate scripts to prevent command injection
        if (params.scripts) {
          for (const script of params.scripts) {
            if (!validateScriptName(script)) {
              return {
                content: [{ type: "text" as const, text: `Invalid script name: "${script}". Only alphanumeric, underscore, dash, dot, and slash allowed.` }],
                isError: true,
              };
            }
          }
        }

        const pcapPath = params.filename.startsWith("/")
          ? params.filename
          : path.join(config.pcapDir, params.filename);

        // Prevent path traversal
        const resolvedPcap = path.resolve(pcapPath);
        const resolvedDir = path.resolve(config.pcapDir);
        if (!params.filename.startsWith("/") && !resolvedPcap.startsWith(resolvedDir + path.sep) && resolvedPcap !== resolvedDir) {
          return {
            content: [{ type: "text" as const, text: `Path traversal blocked: "${params.filename}"` }],
            isError: true,
          };
        }

        if (!fs.existsSync(pcapPath)) {
          return {
            content: [{ type: "text" as const, text: `PCAP file not found: ${pcapPath}` }],
            isError: true,
          };
        }

        // Create output directory for this analysis
        const analysisId = `pcap-${Date.now()}`;
        const outputDir = path.join(config.outputDir, analysisId);

        let cmd: string;
        if (config.zeekContainer) {
          // Run inside Docker container
          const containerPcapPath = `/pcaps/${path.basename(pcapPath)}`;
          const scriptArgs = params.scripts ? params.scripts.join(" ") : "";
          cmd = `docker exec ${config.zeekContainer} /bin/sh -c "mkdir -p /tmp/${analysisId} && cd /tmp/${analysisId} && ${config.zeekBinary} -r ${containerPcapPath} ${scriptArgs} 2>&1 && echo '---ZEEK_DONE---' && ls -la /tmp/${analysisId}/ && echo '---FILES---'"`;

          // After zeek runs, copy logs out
          const result = await execCommand(cmd, params.timeoutSeconds * 1000);

          // Read the generated logs from inside the container
          const logListCmd = `docker exec ${config.zeekContainer} ls /tmp/${analysisId}/`;
          const logList = await execCommand(logListCmd, 5000);
          const logFiles = logList.stdout.trim().split("\n").filter((f) => f.endsWith(".log"));

          const logs: Record<string, { recordCount: number; sample: string[] }> = {};
          for (const logFile of logFiles) {
            const catCmd = `docker exec ${config.zeekContainer} cat /tmp/${analysisId}/${logFile}`;
            const logContent = await execCommand(catCmd, 10000);
            const lines = logContent.stdout.split("\n").filter((l) => l.trim() && !l.startsWith("#"));
            const headerLines = logContent.stdout.split("\n").filter((l) => l.startsWith("#fields") || l.startsWith("#types"));
            logs[logFile.replace(".log", "")] = {
              recordCount: lines.length,
              sample: [...headerLines, ...lines.slice(0, 5)],
            };
          }

          // Cleanup
          await execCommand(`docker exec ${config.zeekContainer} rm -rf /tmp/${analysisId}`, 5000);

          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify({
                pcapFile: path.basename(pcapPath),
                pcapSize: formatBytes(fs.statSync(pcapPath).size),
                analysisId,
                logTypesGenerated: Object.keys(logs),
                totalRecords: Object.values(logs).reduce((sum, l) => sum + l.recordCount, 0),
                logs,
                zeekOutput: result.stderr || result.stdout.split("---ZEEK_DONE---")[0],
              }, null, 2),
            }],
          };
        } else {
          // Run Zeek directly on host
          fs.mkdirSync(outputDir, { recursive: true });
          const scriptArgs = params.scripts ? params.scripts.join(" ") : "";
          cmd = `cd ${outputDir} && ${config.zeekBinary} -r ${pcapPath} ${scriptArgs} 2>&1`;

          const result = await execCommand(cmd, params.timeoutSeconds * 1000);

          const logFiles = fs.existsSync(outputDir)
            ? fs.readdirSync(outputDir).filter((f) => f.endsWith(".log"))
            : [];

          const logs: Record<string, { recordCount: number; sample: string[] }> = {};
          for (const logFile of logFiles) {
            const content = fs.readFileSync(path.join(outputDir, logFile), "utf-8");
            const lines = content.split("\n").filter((l) => l.trim() && !l.startsWith("#"));
            const headerLines = content.split("\n").filter((l) => l.startsWith("#fields") || l.startsWith("#types"));
            logs[logFile.replace(".log", "")] = {
              recordCount: lines.length,
              sample: [...headerLines, ...lines.slice(0, 5)],
            };
          }

          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify({
                pcapFile: path.basename(pcapPath),
                pcapSize: formatBytes(fs.statSync(pcapPath).size),
                analysisId,
                outputDirectory: outputDir,
                logTypesGenerated: Object.keys(logs),
                totalRecords: Object.values(logs).reduce((sum, l) => sum + l.recordCount, 0),
                logs,
                zeekOutput: result.stdout,
              }, null, 2),
            }],
          };
        }
      } catch (error) {
        return {
          content: [{ type: "text" as const, text: `Error analyzing PCAP: ${error instanceof Error ? error.message : String(error)}` }],
          isError: true,
        };
      }
    },
  );
}

function formatBytes(bytes: number): string {
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}
