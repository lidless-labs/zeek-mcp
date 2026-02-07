import type { ZeekRecord } from "../types.js";

export interface AggregationResult {
  field: string;
  groups: GroupResult[];
  total: number;
}

export interface GroupResult {
  key: string;
  count: number;
  percentage: number;
}

export function groupBy(
  records: ZeekRecord[],
  field: string,
  limit = 20,
): AggregationResult {
  const counts = new Map<string, number>();

  for (const record of records) {
    const value = getNestedValue(record, field);
    const key = value !== undefined && value !== null ? String(value) : "(unset)";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  const sorted = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit);

  const total = records.length;

  return {
    field,
    total,
    groups: sorted.map(([key, count]) => ({
      key,
      count,
      percentage: total > 0 ? Math.round((count / total) * 10000) / 100 : 0,
    })),
  };
}

export function sumField(records: ZeekRecord[], field: string): number {
  let total = 0;
  for (const record of records) {
    const value = getNestedValue(record, field);
    if (typeof value === "number" && !isNaN(value)) {
      total += value;
    }
  }
  return total;
}

export function avgField(records: ZeekRecord[], field: string): number {
  let total = 0;
  let count = 0;
  for (const record of records) {
    const value = getNestedValue(record, field);
    if (typeof value === "number" && !isNaN(value)) {
      total += value;
      count++;
    }
  }
  return count > 0 ? total / count : 0;
}

export function countUnique(records: ZeekRecord[], field: string): number {
  const values = new Set<string>();
  for (const record of records) {
    const value = getNestedValue(record, field);
    if (value !== undefined && value !== null) {
      values.add(String(value));
    }
  }
  return values.size;
}

export function topN(
  records: ZeekRecord[],
  field: string,
  n = 10,
): Array<{ value: string; count: number }> {
  const counts = new Map<string, number>();
  for (const record of records) {
    const value = getNestedValue(record, field);
    if (value !== undefined && value !== null) {
      const key = String(value);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
  }

  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([value, count]) => ({ value, count }));
}

export function getNestedValue(
  record: ZeekRecord,
  field: string,
): unknown {
  if (field in record) {
    return record[field];
  }

  const parts = field.split(".");
  let current: unknown = record;
  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    if (typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}
