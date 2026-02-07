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

export async function readLogFile(
  logPath: string,
  format: "json" | "tsv",
): Promise<ZeekRecord[]> {
  const isGzipped = logPath.endsWith(".gz");

  let inputStream: NodeJS.ReadableStream;
  if (isGzipped) {
    inputStream = fs.createReadStream(logPath).pipe(zlib.createGunzip());
  } else {
    inputStream = fs.createReadStream(logPath);
  }

  const rl = readline.createInterface({
    input: inputStream,
    crlfDelay: Infinity,
  });

  const records: ZeekRecord[] = [];

  if (format === "json") {
    for await (const line of rl) {
      const record = parseJsonLine(line);
      if (record) {
        records.push(record);
      }
    }
  } else {
    const headerLines: string[] = [];
    let header: TsvHeader | null = null;

    for await (const line of rl) {
      if (line.startsWith("#")) {
        headerLines.push(line);
        header = parseTsvHeader(headerLines);
        continue;
      }

      if (!header) continue;

      const record = parseTsvRecord(line, header);
      if (record) {
        records.push(record);
      }
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

export async function queryLog(
  config: ZeekConfig,
  logType: LogType,
  timeFrom?: string,
  timeTo?: string,
): Promise<ZeekRecord[]> {
  const dates = getDateRange(timeFrom, timeTo);
  const allRecords: ZeekRecord[] = [];

  if (dates.length === 0) {
    const paths = resolveLogPath(config, logType);
    for (const p of paths) {
      try {
        const records = await readLogFile(p, config.logFormat);
        allRecords.push(...records);
      } catch {
        // log file not readable or doesn't exist
      }
    }
  } else {
    for (const date of dates) {
      const paths = resolveLogPath(config, logType, date);
      for (const p of paths) {
        try {
          const records = await readLogFile(p, config.logFormat);
          allRecords.push(...records);
        } catch {
          // skip unreadable logs
        }
      }
    }

    const currentPaths = resolveLogPath(config, logType);
    for (const p of currentPaths) {
      try {
        const records = await readLogFile(p, config.logFormat);
        allRecords.push(...records);
      } catch {
        // skip
      }
    }
  }

  const fromTs = timeFrom ? new Date(timeFrom).getTime() / 1000 : undefined;
  const toTs = timeTo ? new Date(timeTo).getTime() / 1000 : undefined;

  return allRecords.filter((r) => {
    if (fromTs !== undefined && r.ts < fromTs) return false;
    if (toTs !== undefined && r.ts > toTs) return false;
    return true;
  });
}

function getDateRange(timeFrom?: string, timeTo?: string): string[] {
  if (!timeFrom && !timeTo) return [];

  const dates: string[] = [];
  const start = timeFrom ? new Date(timeFrom) : new Date();
  const end = timeTo ? new Date(timeTo) : new Date();

  start.setHours(0, 0, 0, 0);
  end.setHours(23, 59, 59, 999);

  const current = new Date(start);
  while (current <= end) {
    const y = current.getFullYear();
    const m = String(current.getMonth() + 1).padStart(2, "0");
    const d = String(current.getDate()).padStart(2, "0");
    dates.push(`${y}-${m}-${d}`);
    current.setDate(current.getDate() + 1);
  }

  return dates;
}
