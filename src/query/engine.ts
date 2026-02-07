import type { ZeekRecord, LogType } from "../types.js";
import type { ZeekConfig } from "../config.js";
import { queryLog } from "../parser/index.js";
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
): Promise<ZeekRecord[]> {
  const records = await queryLog(
    config,
    options.logType,
    options.timeFrom,
    options.timeTo,
  );

  let filtered = records;
  if (options.filters && options.filters.length > 0) {
    filtered = records.filter((record) =>
      options.filters!.every((filter) => applyFilter(record, filter)),
    );
  }

  const sortField = options.sortBy ?? "ts";
  const sortOrder = options.sortOrder ?? "desc";

  filtered.sort((a, b) => {
    const aVal = getNestedValue(a, sortField);
    const bVal = getNestedValue(b, sortField);

    if (aVal === undefined && bVal === undefined) return 0;
    if (aVal === undefined) return 1;
    if (bVal === undefined) return -1;

    let cmp: number;
    if (typeof aVal === "number" && typeof bVal === "number") {
      cmp = aVal - bVal;
    } else {
      cmp = String(aVal).localeCompare(String(bVal));
    }

    return sortOrder === "desc" ? -cmp : cmp;
  });

  const limit = Math.min(options.limit ?? 100, config.maxResults);
  return filtered.slice(0, limit);
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
