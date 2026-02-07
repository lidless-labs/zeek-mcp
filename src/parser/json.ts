import type { ZeekRecord } from "../types.js";

export function parseJsonLine(line: string): ZeekRecord | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("//")) {
    return null;
  }

  try {
    const record = JSON.parse(trimmed) as Record<string, unknown>;

    if (record.ts !== undefined) {
      record.ts = normalizeTimestamp(record.ts);
    }

    return record as ZeekRecord;
  } catch {
    return null;
  }
}

export function parseJsonLines(content: string): ZeekRecord[] {
  const records: ZeekRecord[] = [];
  const lines = content.split("\n");

  for (const line of lines) {
    const record = parseJsonLine(line);
    if (record) {
      records.push(record);
    }
  }

  return records;
}

function normalizeTimestamp(value: unknown): number {
  if (typeof value === "number") {
    return value;
  }
  if (typeof value === "string") {
    const num = parseFloat(value);
    if (!isNaN(num)) {
      return num;
    }
    const date = new Date(value);
    if (!isNaN(date.getTime())) {
      return date.getTime() / 1000;
    }
  }
  return 0;
}
