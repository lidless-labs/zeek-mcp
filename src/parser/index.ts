import * as fs from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline";
import * as zlib from "node:zlib";
import type { ZeekRecord, LogType } from "../types.js";
import type { ZeekConfig } from "../config.js";
import { parseJsonLine } from "./json.js";
import { parseTsvHeader, parseTsvRecord, type TsvHeader } from "./tsv.js";

export { parseJsonLines } from "./json.js";
export { parseTsvContent, parseTsvHeader, parseTsvRecord } from "./tsv.js";

// The iterator owns both streams so an early return also stops decompression.
async function* streamLogFile(logPath: string, format: "json" | "tsv", onLine?: () => boolean): AsyncGenerator<ZeekRecord> {
  const source = fs.createReadStream(logPath);
  const input = logPath.endsWith(".gz") ? source.pipe(zlib.createGunzip()) : source;
  const forwardError = (error: Error) => input.destroy(error);
  if (input !== source) source.on("error", forwardError);
  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  const directives = new Map<string, string>();
  let header: TsvHeader | null = null;
  try {
    for await (const line of rl) {
      if (onLine && !onLine()) return;
      if (format === "tsv" && line.startsWith("#")) {
        const directive = /^#(separator|set_separator|empty_field|unset_field|path|open|fields|types)\b/.exec(line)?.[1];
        if (directive) {
          directives.set(directive, line);
          header = parseTsvHeader([...directives.values()]);
        }
        continue;
      }
      const record = format === "json" ? parseJsonLine(line) : header ? parseTsvRecord(line, header) : null;
      if (record) yield record;
    }
  } finally {
    rl.close();
    input.destroy();
    source.destroy();
    source.off("error", forwardError);
  }
}

export async function readLogFile(
  logPath: string,
  format: "json" | "tsv",
  predicate: (record: ZeekRecord) => boolean = () => true,
  cap = Infinity,
): Promise<ZeekRecord[]> {
  const records: ZeekRecord[] = [];
  if (cap <= 0) return records;
  for await (const record of streamLogFile(logPath, format)) {
    if (predicate(record)) {
      records.push(record);
      if (records.length >= cap) break;
    }
  }
  return records;
}

export function resolveLogPath(
  config: ZeekConfig,
  logType: LogType,
  date?: string,
): string[] {
  const filename = `${logType}.log`;
  const paths: string[] = [];

  if (!date) {
    const currentPath = path.join(config.logDir, filename);
    if (fs.existsSync(currentPath)) {
      paths.push(currentPath);
    }
    const gzPath = currentPath + ".gz";
    if (fs.existsSync(gzPath)) {
      paths.push(gzPath);
    }
    return paths;
  }

  const archivePath = path.join(config.logArchive, date, filename);
  if (fs.existsSync(archivePath)) {
    paths.push(archivePath);
  }

  const gzArchivePath = archivePath + ".gz";
  if (fs.existsSync(gzArchivePath)) {
    paths.push(gzArchivePath);
  }

  const rotatedGlob = path.join(config.logArchive, date);
  if (fs.existsSync(rotatedGlob)) {
    try {
      const files = fs.readdirSync(rotatedGlob);
      for (const f of files) {
        if (
          f.startsWith(`${logType}.`) &&
          f !== filename &&
          f !== filename + ".gz"
        ) {
          paths.push(path.join(rotatedGlob, f));
        }
      }
    } catch {
      // directory may not be readable
    }
  }

  return paths;
}

export type LogRecords = ZeekRecord[] & { truncated?: true };

// A callback lets query consumers retain only the records their result needs.
export async function scanLogs(
  config: ZeekConfig,
  logType: LogType,
  timeFrom: string | undefined,
  timeTo: string | undefined,
  visit: (record: ZeekRecord) => void,
): Promise<{ truncated: boolean }> {
  const dates = getDateRange(timeFrom, timeTo, config.maxDateRangeDays ?? 31);
  const fromTs = timeFrom ? new Date(timeFrom).getTime() / 1000 : -Infinity;
  const toTs = timeTo ? new Date(timeTo).getTime() / 1000 : Infinity;
  const maxScan = config.maxScan ?? 1000000;
  let scanned = 0;
  const selections: Array<string | undefined> = [...dates, undefined];
  for (const date of selections) {
    const paths = resolveLogPath(config, logType, date);
    for (const file of paths) {
      if (date && !archiveOverlaps(file, date, fromTs, toTs)) continue;
      // Keep IO failures separate from exceptions raised by query consumers.
      const readable = async function* () {
        try {
          yield* streamLogFile(file, config.logFormat, () => {
            if (scanned >= maxScan) return false;
            scanned++;
            return true;
          });
        } catch {
          // Preserve the existing policy of skipping unreadable logs.
        }
      };
      for await (const record of readable()) {
        if ((!timeFrom || record.ts >= fromTs) && (!timeTo || record.ts <= toTs)) visit(record);
        if (scanned >= maxScan) return { truncated: true };
      }
      if (scanned >= maxScan) return { truncated: true };
    }
  }
  return { truncated: false };
}

export async function queryLog(
  config: ZeekConfig,
  logType: LogType,
  timeFrom?: string,
  timeTo?: string,
): Promise<LogRecords> {
  const records: LogRecords = [];
  const result = await scanLogs(config, logType, timeFrom, timeTo, (record) => records.push(record));
  if (result.truncated) records.truncated = true;
  return records;
}

function archiveOverlaps(file: string, date: string, fromTs: number, toTs: number): boolean {
  const range = /\.(\d{2}:\d{2}:\d{2})-(\d{2}:\d{2}:\d{2})\.log(?:\.gz)?$/.exec(file);
  if (!range) return true;
  // Zeek's archive dates and rotation clocks use the sensor's local timezone.
  const midnight = new Date(`${date}T00:00:00`);
  const evening = new Date(`${date}T23:59:59`);
  // Repeated or missing clock hours make filename-only pruning ambiguous.
  if (midnight.getTimezoneOffset() !== evening.getTimezoneOffset()) return true;
  const start = new Date(`${date}T${range[1]}`);
  const end = new Date(`${date}T${range[2]}`);
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime())) return true;
  if (end <= start) end.setDate(end.getDate() + 1);
  return start.getTime() / 1000 <= toTs && end.getTime() / 1000 >= fromTs;
}

function getDateRange(timeFrom?: string, timeTo?: string, maxDays = 31): string[] {
  if (!timeFrom && !timeTo) return [];
  const start = new Date(timeFrom ?? timeTo!);
  const end = timeTo ? new Date(timeTo) : new Date();
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime())) {
    throw new Error("Invalid time range: use ISO 8601 timestamps.");
  }
  if (start > end) throw new Error("Invalid time range: start must not be after end.");
  const calendarDay = (date: Date) => Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()) / 86400000;
  const days = calendarDay(end) - calendarDay(start) + 1;
  if (days > maxDays) throw new Error(`Time range exceeds the limit of ${maxDays} days (ZEEK_MAX_DATE_RANGE_DAYS).`);
  start.setHours(0, 0, 0, 0);
  const dates: string[] = [];
  for (let i = 0; i < days; i++) {
    dates.push(`${start.getFullYear()}-${String(start.getMonth() + 1).padStart(2, "0")}-${String(start.getDate()).padStart(2, "0")}`);
    start.setDate(start.getDate() + 1);
  }
  return dates;
}
