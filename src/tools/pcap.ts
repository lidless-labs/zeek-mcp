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

// Run a command with an argv ARRAY (no shell). User-controlled values are passed
// as discrete arguments, so they can never be interpreted as shell syntax.
function execFileCommand(
  file: string,
  args: string[],
  timeoutMs = 60000,
  cwd?: string,
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    child_process.execFile(file, args, { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024, cwd }, (error, stdout, stderr) => {
      resolve({
        stdout: stdout?.toString() ?? "",
        stderr: stderr?.toString() ?? (error ? error.message : ""),
        code: typeof (error as { code?: unknown } | null)?.code === "number" ? (error as { code: number }).code : (error ? 1 : 0),
      });
    });
  });
}

// Validate script names to prevent command/path injection.
// Strict allowlist: alphanumerics plus . _ - and / for namespaced script paths.
// Reject "/" prefixes and any ".." traversal segment so a script arg can never
// escape Zeek's script search path or smuggle shell metacharacters.
function validateScriptName(script: string): boolean {
  if (!/^[A-Za-z0-9._\-/]+$/.test(script)) return false;
  if (script.startsWith("/")) return false;
  if (script.split("/").some((seg) => seg === "..")) return false;
  return true;
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

        // Confine ALL filenames (relative or absolute) to the configured pcapDir.
        // Absolute paths are resolved as-is; relative paths are joined onto pcapDir.
        // After resolution the path MUST live inside pcapDir or we reject it, so a
        // caller can never read or feed Zeek an arbitrary file on the host.
        const resolvedDir = path.resolve(config.pcapDir);
        const pcapPath = path.isAbsolute(params.filename)
          ? path.resolve(params.filename)
          : path.resolve(resolvedDir, params.filename);

        if (pcapPath !== resolvedDir && !pcapPath.startsWith(resolvedDir + path.sep)) {
          return {
            content: [{ type: "text" as const, text: `Path traversal blocked: "${params.filename}" is outside the allowed PCAP directory.` }],
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

        if (config.zeekContainer) {
          // Run inside Docker container. Every value is passed as a discrete argv
          // element to `docker` (no inner `sh -c`, no shell string), so a hostile
          // filename or script name can never be interpreted as shell syntax.
          const containerWorkDir = `/tmp/${analysisId}`;
          const containerPcapPath = `/pcaps/${path.basename(pcapPath)}`;
          const scripts = params.scripts ?? [];

          // Create the per-analysis working directory.
          await execFileCommand("docker", ["exec", config.zeekContainer, "mkdir", "-p", containerWorkDir], 5000);

          // Run Zeek with its working directory set via `-w` (no `cd`).
          const result = await execFileCommand(
            "docker",
            ["exec", "-w", containerWorkDir, config.zeekContainer, config.zeekBinary, "-r", containerPcapPath, ...scripts],
            params.timeoutSeconds * 1000,
          );

          // Read the generated logs from inside the container
          const logList = await execFileCommand("docker", ["exec", config.zeekContainer, "ls", containerWorkDir], 5000);
          const logFiles = logList.stdout.trim().split("\n").filter((f) => f.endsWith(".log"));

          const logs: Record<string, { recordCount: number; sample: string[] }> = {};
          for (const logFile of logFiles) {
            const logContent = await execFileCommand("docker", ["exec", config.zeekContainer, "cat", `${containerWorkDir}/${logFile}`], 10000);
            const lines = logContent.stdout.split("\n").filter((l) => l.trim() && !l.startsWith("#"));
            const headerLines = logContent.stdout.split("\n").filter((l) => l.startsWith("#fields") || l.startsWith("#types"));
            logs[logFile.replace(".log", "")] = {
              recordCount: lines.length,
              sample: [...headerLines, ...lines.slice(0, 5)],
            };
          }

          // Cleanup
          await execFileCommand("docker", ["exec", config.zeekContainer, "rm", "-rf", containerWorkDir], 5000);

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
                zeekOutput: result.stderr || result.stdout,
              }, null, 2),
            }],
          };
        } else {
          // Run Zeek directly on host. Binary, flags, pcap path, and each script
          // are passed as discrete argv elements (no shell), and Zeek runs with its
          // cwd set to the per-analysis output directory instead of a `cd &&` prefix.
          fs.mkdirSync(outputDir, { recursive: true });
          const scripts = params.scripts ?? [];

          const result = await execFileCommand(
            config.zeekBinary,
            ["-r", pcapPath, ...scripts],
            params.timeoutSeconds * 1000,
            outputDir,
          );

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
