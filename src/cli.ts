import * as fs from "node:fs";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { getConfig, type ZeekConfig } from "./config.js";
import { detectBeaconing, type BeaconCandidate } from "./analytics/beaconing.js";
import { executeQuery, type FilterDef } from "./query/engine.js";
import type { ZeekRecord } from "./types.js";
import { serveMcp } from "./mcp-server.js";

export interface CliIo {
  env?: NodeJS.ProcessEnv;
  stdout?: Pick<typeof process.stdout, "write">;
  stderr?: Pick<typeof process.stderr, "write">;
}

interface ParsedArgs {
  positional: string[];
  flags: Map<string, string | boolean>;
  json: boolean;
}

const VERSION = "3.1.0";

const HELP = `zeekctrl ${VERSION}

Usage:
  zeekctrl status [--json]
  zeekctrl conn query [filters] [--json]
  zeekctrl dns query [filters] [--json]
  zeekctrl beaconing detect [filters] [--json]
  zeekctrl mcp

Aliases:
  zeekctl      compatibility CLI alias
  zeek-mcp     MCP stdio adapter

Connection filters:
  --src-ip IP|CIDR       --dst-ip IP|CIDR
  --src-port PORT        --dst-port PORT
  --proto tcp|udp|icmp   --service NAME
  --conn-state STATE     --min-duration SECONDS
  --max-duration SECONDS --min-orig-bytes BYTES
  --time-from ISO        --time-to ISO
  --sort-by FIELD        --limit N

DNS filters:
  --query TEXT|*.domain  --src-ip IP|CIDR
  --qtype A|AAAA|1       --rcode NOERROR|NXDOMAIN|0
  --answers TEXT         --time-from ISO
  --time-to ISO          --limit N

Beaconing filters:
  --src-ip IP|CIDR       --dst-ip IP|CIDR
  --min-connections N    --max-jitter-percent N
  --min-score N          --time-from ISO
  --time-to ISO          --limit N
`;

export async function runCli(args: string[], io: CliIo = {}): Promise<number> {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const env = io.env ?? process.env;

  try {
    const parsed = parseArgs(args);
    const [group, command] = parsed.positional;

    if (!group || group === "help" || group === "--help" || group === "-h") {
      write(stdout, HELP);
      return 0;
    }

    if (group === "version" || group === "--version" || group === "-v") {
      write(stdout, `${VERSION}\n`);
      return 0;
    }

    if (group === "mcp") {
      await serveMcp(getConfig(env));
      return 0;
    }

    if (group === "status") {
      const config = getConfig(env);
      const status = getStatus(config);
      writeOutput(stdout, status, parsed.json, renderStatus(status));
      return 0;
    }

    if (group === "conn" && command === "query") {
      const config = getConfig(env);
      const records = await queryConnections(config, parsed);
      writeOutput(stdout, records, parsed.json, renderConnections(records));
      return 0;
    }

    if (group === "dns" && command === "query") {
      const config = getConfig(env);
      const records = await queryDns(config, parsed);
      writeOutput(stdout, records, parsed.json, renderDns(records));
      return 0;
    }

    if (group === "beaconing" && command === "detect") {
      const config = getConfig(env);
      const candidates = await detectBeacons(config, parsed);
      writeOutput(stdout, candidates, parsed.json, renderBeaconing(candidates));
      return 0;
    }

    write(stderr, `Unknown command: ${parsed.positional.join(" ")}\n\n${HELP}`);
    return 2;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    write(stderr, `zeekctrl: ${message}\n`);
    return 1;
  }
}

function parseArgs(args: string[]): ParsedArgs {
  const positional: string[] = [];
  const flags = new Map<string, string | boolean>();

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }

    const equalIndex = arg.indexOf("=");
    if (equalIndex > -1) {
      flags.set(arg.slice(2, equalIndex), arg.slice(equalIndex + 1));
      continue;
    }

    const name = arg.slice(2);
    const next = args[i + 1];
    if (next && !next.startsWith("--")) {
      flags.set(name, next);
      i++;
    } else {
      flags.set(name, true);
    }
  }

  return {
    positional,
    flags,
    json: flags.has("json"),
  };
}

function getStatus(config: ZeekConfig) {
  const connPath = findLog(config.logDir, "conn.log");
  const dnsPath = findLog(config.logDir, "dns.log");
  const logDir = checkPath(config.logDir);
  const logArchive = checkPath(config.logArchive);

  return {
    ok: logDir.exists && logDir.readable,
    config,
    paths: {
      logDir,
      logArchive,
      currentConnLog: connPath ? checkPath(connPath) : missingPath(path.join(config.logDir, "conn.log")),
      currentDnsLog: dnsPath ? checkPath(dnsPath) : missingPath(path.join(config.logDir, "dns.log")),
    },
  };
}

function findLog(dir: string, filename: string): string | null {
  const plain = path.join(dir, filename);
  if (fs.existsSync(plain)) return plain;
  const gz = `${plain}.gz`;
  if (fs.existsSync(gz)) return gz;
  return null;
}

function checkPath(target: string) {
  const status = {
    path: target,
    exists: fs.existsSync(target),
    readable: false,
  };
  if (!status.exists) return status;
  try {
    fs.accessSync(target, fs.constants.R_OK);
    status.readable = true;
  } catch {
    status.readable = false;
  }
  return status;
}

function missingPath(target: string) {
  return { path: target, exists: false, readable: false };
}

async function queryConnections(config: ZeekConfig, parsed: ParsedArgs): Promise<ZeekRecord[]> {
  const filters: FilterDef[] = [];
  addIpFilter(filters, "id.orig_h", getString(parsed, "src-ip"));
  addIpFilter(filters, "id.resp_h", getString(parsed, "dst-ip"));
  addNumberFilter(filters, "id.orig_p", "eq", getNumber(parsed, "src-port"));
  addNumberFilter(filters, "id.resp_p", "eq", getNumber(parsed, "dst-port"));
  addStringFilter(filters, "proto", "eq", getString(parsed, "proto"));
  addStringFilter(filters, "service", "eq", getString(parsed, "service"));
  addStringFilter(filters, "conn_state", "eq", getString(parsed, "conn-state"));
  addNumberFilter(filters, "duration", "gte", getNumber(parsed, "min-duration"));
  addNumberFilter(filters, "duration", "lte", getNumber(parsed, "max-duration"));
  addNumberFilter(filters, "orig_bytes", "gte", getNumber(parsed, "min-orig-bytes"));

  return executeQuery(config, {
    logType: "conn",
    filters,
    timeFrom: getString(parsed, "time-from"),
    timeTo: getString(parsed, "time-to"),
    sortBy: getString(parsed, "sort-by") ?? "ts",
    limit: getLimit(parsed, config),
  });
}

async function queryDns(config: ZeekConfig, parsed: ParsedArgs): Promise<ZeekRecord[]> {
  const filters: FilterDef[] = [];
  const query = getString(parsed, "query");
  if (query) {
    filters.push({ field: "query", op: query.includes("*") ? "wildcard" : "contains", value: query });
  }
  addIpFilter(filters, "id.orig_h", getString(parsed, "src-ip"));

  const qtype = getString(parsed, "qtype");
  if (qtype) {
    const qtypeNumber = Number(qtype);
    filters.push(Number.isFinite(qtypeNumber)
      ? { field: "qtype", op: "eq", value: qtypeNumber }
      : { field: "qtype_name", op: "eq", value: qtype.toUpperCase() });
  }

  const rcode = getString(parsed, "rcode");
  if (rcode) {
    const rcodeNumber = Number(rcode);
    filters.push(Number.isFinite(rcodeNumber)
      ? { field: "rcode", op: "eq", value: rcodeNumber }
      : { field: "rcode_name", op: "eq", value: rcode.toUpperCase() });
  }

  addStringFilter(filters, "answers", "contains", getString(parsed, "answers"));

  return executeQuery(config, {
    logType: "dns",
    filters,
    timeFrom: getString(parsed, "time-from"),
    timeTo: getString(parsed, "time-to"),
    sortBy: getString(parsed, "sort-by") ?? "ts",
    limit: getLimit(parsed, config),
  });
}

async function detectBeacons(config: ZeekConfig, parsed: ParsedArgs): Promise<BeaconCandidate[]> {
  const filters: FilterDef[] = [];
  addIpFilter(filters, "id.orig_h", getString(parsed, "src-ip"));
  addIpFilter(filters, "id.resp_h", getString(parsed, "dst-ip"));

  const records = await executeQuery(config, {
    logType: "conn",
    filters,
    timeFrom: getString(parsed, "time-from"),
    timeTo: getString(parsed, "time-to"),
    limit: getLimit(parsed, config),
  });

  const minConnections = getNumber(parsed, "min-connections") ?? 10;
  const maxJitterPercent = getNumber(parsed, "max-jitter-percent") ?? 30;
  const minScore = getNumber(parsed, "min-score") ?? 0;

  return detectBeaconing(records, minConnections, maxJitterPercent)
    .filter((candidate) => candidate.score >= minScore);
}

function addIpFilter(filters: FilterDef[], field: string, value: string | undefined): void {
  if (!value) return;
  filters.push({ field, op: value.includes("/") ? "cidr" : "eq", value });
}

function addStringFilter(
  filters: FilterDef[],
  field: string,
  op: Extract<FilterDef["op"], "eq" | "contains" | "wildcard">,
  value: string | undefined,
): void {
  if (value === undefined) return;
  filters.push({ field, op, value });
}

function addNumberFilter(
  filters: FilterDef[],
  field: string,
  op: Extract<FilterDef["op"], "eq" | "gte" | "lte">,
  value: number | undefined,
): void {
  if (value === undefined) return;
  filters.push({ field, op, value });
}

function getString(parsed: ParsedArgs, name: string): string | undefined {
  const value = parsed.flags.get(name);
  if (typeof value !== "string" || value.length === 0) return undefined;
  return value;
}

function getNumber(parsed: ParsedArgs, name: string): number | undefined {
  const raw = getString(parsed, name);
  if (raw === undefined) return undefined;
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    throw new Error(`--${name} must be a number`);
  }
  return value;
}

function getLimit(parsed: ParsedArgs, config: ZeekConfig): number {
  const value = getNumber(parsed, "limit") ?? 25;
  if (!Number.isInteger(value) || value < 1) {
    throw new Error("--limit must be a positive integer");
  }
  return Math.min(value, config.maxResults);
}

function renderStatus(status: ReturnType<typeof getStatus>): string {
  const lines = [
    `status: ${status.ok ? "ok" : "needs-attention"}`,
    `logDir: ${status.config.logDir} (${pathStatus(status.paths.logDir)})`,
    `archive: ${status.config.logArchive} (${pathStatus(status.paths.logArchive)})`,
    `format: ${status.config.logFormat}`,
    `maxResults: ${status.config.maxResults}`,
    `conn.log: ${pathStatus(status.paths.currentConnLog)}`,
    `dns.log: ${pathStatus(status.paths.currentDnsLog)}`,
  ];
  return `${lines.join("\n")}\n`;
}

function pathStatus(status: { exists: boolean; readable: boolean }): string {
  if (!status.exists) return "missing";
  return status.readable ? "readable" : "not-readable";
}

function renderConnections(records: ZeekRecord[]): string {
  if (records.length === 0) return "No connection records matched.\n";
  const rows = records.map((record) => [
    formatTime(record.ts),
    String(record["id.orig_h"] ?? ""),
    `${record["id.resp_h"] ?? ""}:${record["id.resp_p"] ?? ""}`,
    String(record.proto ?? ""),
    String(record.service ?? "-"),
    String(record.conn_state ?? "-"),
    formatNumber(record.duration),
  ]);
  return renderTable(["time", "src", "dst", "proto", "service", "state", "duration"], rows);
}

function renderDns(records: ZeekRecord[]): string {
  if (records.length === 0) return "No DNS records matched.\n";
  const rows = records.map((record) => [
    formatTime(record.ts),
    String(record["id.orig_h"] ?? ""),
    String(record.query ?? ""),
    String(record.qtype_name ?? record.qtype ?? "-"),
    String(record.rcode_name ?? record.rcode ?? "-"),
    Array.isArray(record.answers) ? record.answers.join(",") : String(record.answers ?? "-"),
  ]);
  return renderTable(["time", "src", "query", "qtype", "rcode", "answers"], rows);
}

function renderBeaconing(candidates: BeaconCandidate[]): string {
  if (candidates.length === 0) return "No beaconing candidates matched.\n";
  const rows = candidates.map((candidate) => [
    candidate.srcIp,
    `${candidate.dstIp}:${candidate.dstPort}`,
    String(candidate.connectionCount),
    `${candidate.avgInterval}s`,
    `${candidate.jitter}%`,
    String(candidate.score),
    String(candidate.avgBytes),
  ]);
  return renderTable(["src", "dst", "count", "interval", "jitter", "score", "avgBytes"], rows);
}

function renderTable(headers: string[], rows: string[][]): string {
  const widths = headers.map((header, index) =>
    Math.max(header.length, ...rows.map((row) => row[index]?.length ?? 0)),
  );
  const formatRow = (row: string[]) =>
    row.map((value, index) => value.padEnd(widths[index])).join("  ").trimEnd();
  return `${formatRow(headers)}\n${widths.map((width) => "-".repeat(width)).join("  ")}\n${rows.map(formatRow).join("\n")}\n`;
}

function formatTime(ts: unknown): string {
  if (typeof ts !== "number" || !Number.isFinite(ts)) return "";
  return new Date(ts * 1000).toISOString();
}

function formatNumber(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "-";
  return Number.isInteger(value) ? String(value) : value.toFixed(3);
}

function writeOutput(
  stdout: Pick<typeof process.stdout, "write">,
  value: unknown,
  json: boolean,
  text: string,
): void {
  write(stdout, json ? `${JSON.stringify(value, null, 2)}\n` : text);
}

function write(stream: Pick<typeof process.stdout, "write">, value: string): void {
  stream.write(value);
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (import.meta.url === invokedPath) {
  const code = await runCli(process.argv.slice(2));
  process.exitCode = code;
}
