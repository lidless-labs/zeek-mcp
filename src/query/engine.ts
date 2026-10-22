import type { ZeekRecord, LogType } from "../types.js";
import type { ZeekConfig } from "../config.js";
import { scanLogs, type LogRecords } from "../parser/index.js";
import { BoundedBuffer } from "./bounded-buffer.js";
import { getNestedValue } from "./aggregation.js";

export interface QueryOptions {
  logType: LogType;
  filters?: FilterDef[];
  timeFrom?: string;
  timeTo?: string;
  sortBy?: string;
  sortOrder?: "asc" | "desc";
  limit?: number;
}

export interface FilterDef {
  field: string;
  op: "eq" | "neq" | "gt" | "gte" | "lt" | "lte" | "contains" | "wildcard" | "cidr" | "in" | "exists";
  value: unknown;
}

export async function executeQuery(
  config: ZeekConfig,
  options: QueryOptions,
): Promise<LogRecords> {
  const sortField = options.sortBy ?? "ts";
  const sortOrder = options.sortOrder ?? "desc";
  const limit = Math.floor(Math.max(0, Math.min(options.limit ?? 100, config.maxResults)));
  const compare = (a: ZeekRecord, b: ZeekRecord): number => {
    const aVal = getNestedValue(a, sortField);
    const bVal = getNestedValue(b, sortField);
    if (aVal === undefined && bVal === undefined) return 0;
    if (aVal === undefined) return 1;
    if (bVal === undefined) return -1;
    const cmp = typeof aVal === "number" && typeof bVal === "number"
      ? aVal - bVal : String(aVal).localeCompare(String(bVal));
    return sortOrder === "desc" ? -cmp : cmp;
  };
  type Entry = { record: ZeekRecord; sequence: number };
  const newest = new BoundedBuffer<Entry>(limit, (a, b) => compare(a.record, b.record) || a.sequence - b.sequence);
  const boundedSort = sortField === "ts" && sortOrder === "desc";
  const filtered: ZeekRecord[] = [];
  let sequence = 0;
  const scan = await scanLogs(config, options.logType, options.timeFrom, options.timeTo, (record) => {
    if (options.filters && !options.filters.every((filter) => applyFilter(record, filter))) return;
    if (boundedSort) newest.add({ record, sequence: sequence++ });
    else filtered.push(record);
  });
  const records: LogRecords = boundedSort
    ? newest.sorted().map((entry) => entry.record)
    : filtered.sort(compare).slice(0, limit);
  if (scan.truncated) records.truncated = true;
  return records;
}

// Tools must keep this metadata when formatting or aggregating the record arrays.
export function queryMetadata(...results: ZeekRecord[][]): { truncated?: true } {
  return results.some((records) => (records as LogRecords).truncated) ? { truncated: true } : {};
}

function applyFilter(record: ZeekRecord, filter: FilterDef): boolean {
  const value = getNestedValue(record, filter.field);

  switch (filter.op) {
    case "eq":
      return value === filter.value || String(value) === String(filter.value);

    case "neq":
      return value !== filter.value && String(value) !== String(filter.value);

    case "gt":
      return typeof value === "number" && value > (filter.value as number);

    case "gte":
      return typeof value === "number" && value >= (filter.value as number);

    case "lt":
      return typeof value === "number" && value < (filter.value as number);

    case "lte":
      return typeof value === "number" && value <= (filter.value as number);

    case "contains":
      if (typeof value === "string") {
        return value.toLowerCase().includes(String(filter.value).toLowerCase());
      }
      if (Array.isArray(value)) {
        return value.some(
          (v) =>
            String(v).toLowerCase().includes(String(filter.value).toLowerCase()),
        );
      }
      return false;

    case "wildcard":
      return matchWildcard(String(value ?? ""), String(filter.value));

    case "cidr":
      return matchCidr(String(value ?? ""), String(filter.value));

    case "in":
      if (Array.isArray(filter.value)) {
        return filter.value.includes(value) ||
          filter.value.map(String).includes(String(value));
      }
      return false;

    case "exists":
      return value !== undefined && value !== null;

    default:
      return true;
  }
}

function matchWildcard(value: string, pattern: string): boolean {
  if (!pattern.includes("*")) {
    return value.toLowerCase() === pattern.toLowerCase();
  }

  const regex = new RegExp(
    "^" +
      pattern
        .split("*")
        .map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
        .join(".*") +
      "$",
    "i",
  );

  return regex.test(value);
}

function matchCidr(ip: string, cidr: string): boolean {
  if (!cidr.includes("/")) {
    return ip === cidr;
  }

  const [network, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr, 10);

  const ipNum = ipv4ToNum(ip);
  const netNum = ipv4ToNum(network);

  if (ipNum === null || netNum === null) return false;

  const mask = prefix === 0 ? 0 : ~0 << (32 - prefix);
  return (ipNum & mask) === (netNum & mask);
}

function ipv4ToNum(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;

  let num = 0;
  for (const part of parts) {
    const octet = parseInt(part, 10);
    if (isNaN(octet) || octet < 0 || octet > 255) return null;
    num = (num << 8) | octet;
  }
  return num >>> 0;
}
