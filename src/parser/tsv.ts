import type { ZeekRecord } from "../types.js";

export interface TsvHeader {
  separator: string;
  setSeparator: string;
  emptyField: string;
  unsetField: string;
  path: string;
  open: string;
  fields: string[];
  types: string[];
}

export function parseTsvHeader(lines: string[]): TsvHeader | null {
  const header: Partial<TsvHeader> = {
    separator: "\t",
    setSeparator: ",",
    emptyField: "(empty)",
    unsetField: "-",
  };

  for (const line of lines) {
    if (!line.startsWith("#")) break;

    const parts = line.substring(1).split(/\t| {2,}/);
    const directive = parts[0]?.trim();
    const value = parts.slice(1).join("\t").trim();

    switch (directive) {
      case "separator":
        header.separator = parseSeparator(value);
        break;
      case "set_separator":
        header.setSeparator = value;
        break;
      case "empty_field":
        header.emptyField = value;
        break;
      case "unset_field":
        header.unsetField = value;
        break;
      case "path":
        header.path = value;
        break;
      case "open":
        header.open = value;
        break;
      case "fields":
        header.fields = value.split(header.separator ?? "\t");
        break;
      case "types":
        header.types = value.split(header.separator ?? "\t");
        break;
    }
  }

  if (!header.fields || !header.types) {
    return null;
  }

  return header as TsvHeader;
}

function parseSeparator(value: string): string {
  if (value === "\\x09") return "\t";
  if (value === "\\x20") return " ";
  if (value.startsWith("\\x")) {
    const code = parseInt(value.substring(2), 16);
    return String.fromCharCode(code);
  }
  return value;
}

export function parseTsvRecord(
  line: string,
  header: TsvHeader,
): ZeekRecord | null {
  if (line.startsWith("#") || !line.trim()) {
    return null;
  }

  const values = line.split(header.separator);
  const record: Record<string, unknown> = {};

  for (let i = 0; i < header.fields.length && i < values.length; i++) {
    const field = header.fields[i];
    const type = header.types[i];
    const raw = values[i];

    if (raw === header.unsetField) {
      continue;
    }

    if (raw === header.emptyField) {
      record[field] = getEmptyValue(type);
      continue;
    }

    record[field] = convertValue(raw, type, header.setSeparator);
  }

  if (record.ts !== undefined) {
    record.ts =
      typeof record.ts === "number"
        ? record.ts
        : parseFloat(record.ts as string);
  }

  return record as ZeekRecord;
}

export function parseTsvContent(content: string): ZeekRecord[] {
  const lines = content.split("\n");
  const header = parseTsvHeader(lines);

  if (!header) {
    return [];
  }

  const records: ZeekRecord[] = [];
  for (const line of lines) {
    const record = parseTsvRecord(line, header);
    if (record) {
      records.push(record);
    }
  }

  return records;
}

function getEmptyValue(type: string): unknown {
  if (type.startsWith("set[") || type.startsWith("vector[")) {
    return [];
  }
  if (type === "string") return "";
  if (type === "count" || type === "int" || type === "port") return 0;
  if (type === "double" || type === "time" || type === "interval") return 0;
  if (type === "bool") return false;
  return "";
}

function convertValue(
  raw: string,
  type: string,
  setSeparator: string,
): unknown {
  if (type.startsWith("set[") || type.startsWith("vector[")) {
    if (!raw) return [];
    const innerType = type.replace(/^(set|vector)\[/, "").replace(/\]$/, "");
    return raw
      .split(setSeparator)
      .map((item) => convertScalar(item, innerType));
  }

  return convertScalar(raw, type);
}

function convertScalar(raw: string, type: string): unknown {
  switch (type) {
    case "time":
    case "double":
    case "interval":
      return parseFloat(raw);
    case "count":
    case "int":
    case "port":
      return parseInt(raw, 10);
    case "bool":
      return raw === "T" || raw === "true";
    case "addr":
    case "subnet":
    case "string":
    case "enum":
    default:
      return raw;
  }
}
