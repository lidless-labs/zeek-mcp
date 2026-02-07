import { describe, it, expect } from "vitest";
import { parseJsonLine, parseJsonLines } from "../src/parser/json.js";
import {
  parseTsvHeader,
  parseTsvRecord,
  parseTsvContent,
} from "../src/parser/tsv.js";
import { readLogFile } from "../src/parser/index.js";
import * as path from "node:path";

const TEST_DATA_DIR = path.join(process.cwd(), "test-data");

describe("JSON parser", () => {
  it("should parse a valid JSON log line", () => {
    const line =
      '{"ts":1706745600.0,"uid":"C1a2b3","id.orig_h":"192.168.1.100","id.resp_h":"93.184.216.34","proto":"tcp"}';
    const record = parseJsonLine(line);

    expect(record).not.toBeNull();
    expect(record!.ts).toBe(1706745600.0);
    expect(record!.uid).toBe("C1a2b3");
    expect(record!["id.orig_h"]).toBe("192.168.1.100");
    expect(record!.proto).toBe("tcp");
  });

  it("should return null for empty lines", () => {
    expect(parseJsonLine("")).toBeNull();
    expect(parseJsonLine("   ")).toBeNull();
  });

  it("should return null for comment lines", () => {
    expect(parseJsonLine("// this is a comment")).toBeNull();
  });

  it("should return null for invalid JSON", () => {
    expect(parseJsonLine("{invalid json}")).toBeNull();
    expect(parseJsonLine("not json at all")).toBeNull();
  });

  it("should parse multiple JSON lines", () => {
    const content = [
      '{"ts":1706745600.0,"uid":"C1","proto":"tcp"}',
      '{"ts":1706745601.0,"uid":"C2","proto":"udp"}',
      "",
      '{"ts":1706745602.0,"uid":"C3","proto":"icmp"}',
    ].join("\n");

    const records = parseJsonLines(content);
    expect(records).toHaveLength(3);
    expect(records[0].uid).toBe("C1");
    expect(records[1].uid).toBe("C2");
    expect(records[2].uid).toBe("C3");
  });

  it("should normalize string timestamps", () => {
    const line = '{"ts":"1706745600.0","uid":"C1"}';
    const record = parseJsonLine(line);
    expect(record!.ts).toBe(1706745600.0);
  });

  it("should read a JSON log file", async () => {
    const records = await readLogFile(
      path.join(TEST_DATA_DIR, "conn.log"),
      "json",
    );

    expect(records.length).toBeGreaterThan(0);
    expect(records[0].uid).toBe("C1a2b3c4d5");
    expect(records[0]["id.orig_h"]).toBe("192.168.1.100");
  });
});

describe("TSV parser", () => {
  const headerLines = [
    "#separator \\x09",
    "#set_separator\t,",
    "#empty_field\t(empty)",
    "#unset_field\t-",
    "#path\tconn",
    "#open\t2024-02-01-00-00-00",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval",
  ];

  it("should parse TSV header", () => {
    const header = parseTsvHeader(headerLines);

    expect(header).not.toBeNull();
    expect(header!.separator).toBe("\t");
    expect(header!.setSeparator).toBe(",");
    expect(header!.emptyField).toBe("(empty)");
    expect(header!.unsetField).toBe("-");
    expect(header!.path).toBe("conn");
    expect(header!.fields).toEqual([
      "ts",
      "uid",
      "id.orig_h",
      "id.orig_p",
      "id.resp_h",
      "id.resp_p",
      "proto",
      "service",
      "duration",
    ]);
    expect(header!.types).toEqual([
      "time",
      "string",
      "addr",
      "port",
      "addr",
      "port",
      "enum",
      "string",
      "interval",
    ]);
  });

  it("should parse a TSV data record", () => {
    const header = parseTsvHeader(headerLines)!;
    const line =
      "1706745600.000000\tC1a2b3c4d5\t192.168.1.100\t52341\t93.184.216.34\t443\ttcp\tssl\t1.234";

    const record = parseTsvRecord(line, header);

    expect(record).not.toBeNull();
    expect(record!.ts).toBe(1706745600.0);
    expect(record!.uid).toBe("C1a2b3c4d5");
    expect(record!["id.orig_h"]).toBe("192.168.1.100");
    expect(record!["id.orig_p"]).toBe(52341);
    expect(record!["id.resp_h"]).toBe("93.184.216.34");
    expect(record!["id.resp_p"]).toBe(443);
    expect(record!.proto).toBe("tcp");
    expect(record!.service).toBe("ssl");
    expect(record!.duration).toBe(1.234);
  });

  it("should handle unset fields", () => {
    const header = parseTsvHeader(headerLines)!;
    const line =
      "1706745600.000000\tC1a2b3c4d5\t192.168.1.100\t52341\t93.184.216.34\t443\ttcp\t-\t-";

    const record = parseTsvRecord(line, header);

    expect(record).not.toBeNull();
    expect(record!.service).toBeUndefined();
    expect(record!.duration).toBeUndefined();
  });

  it("should skip comment and empty lines", () => {
    const header = parseTsvHeader(headerLines)!;

    expect(parseTsvRecord("#close\t2024-02-01", header)).toBeNull();
    expect(parseTsvRecord("", header)).toBeNull();
  });

  it("should parse a complete TSV file", () => {
    const content = [
      ...headerLines,
      "1706745600.000000\tC1\t192.168.1.100\t52341\t93.184.216.34\t443\ttcp\tssl\t1.234",
      "1706745601.000000\tC2\t10.0.0.25\t12345\t192.168.1.100\t80\ttcp\thttp\t0.05",
      "#close\t2024-02-01-00-01-00",
    ].join("\n");

    const records = parseTsvContent(content);
    expect(records).toHaveLength(2);
    expect(records[0].uid).toBe("C1");
    expect(records[1].uid).toBe("C2");
  });

  it("should handle set/vector types", () => {
    const setHeader = parseTsvHeader([
      "#separator \\x09",
      "#set_separator\t,",
      "#empty_field\t(empty)",
      "#unset_field\t-",
      "#path\ttest",
      "#fields\tts\ttags\tports",
      "#types\ttime\tset[string]\tvector[port]",
    ])!;

    const record = parseTsvRecord(
      "1706745600.000000\tHTTP,SSL\t80,443,8080",
      setHeader,
    );

    expect(record).not.toBeNull();
    expect(record!.tags).toEqual(["HTTP", "SSL"]);
    expect(record!.ports).toEqual([80, 443, 8080]);
  });

  it("should read a TSV log file", async () => {
    const records = await readLogFile(
      path.join(TEST_DATA_DIR, "conn.tsv.log"),
      "tsv",
    );

    expect(records).toHaveLength(3);
    expect(records[0].uid).toBe("C1a2b3c4d5");
    expect(records[0]["id.orig_h"]).toBe("192.168.1.100");
    expect(records[0]["id.resp_p"]).toBe(443);
    expect(records[1].service).toBe("ssh");
  });

  it("should handle boolean types correctly", () => {
    const boolHeader = parseTsvHeader([
      "#separator \\x09",
      "#set_separator\t,",
      "#empty_field\t(empty)",
      "#unset_field\t-",
      "#path\ttest",
      "#fields\tts\tauth_success\trejected",
      "#types\ttime\tbool\tbool",
    ])!;

    const record = parseTsvRecord("1706745600.000000\tT\tF", boolHeader);

    expect(record).not.toBeNull();
    expect(record!.auth_success).toBe(true);
    expect(record!.rejected).toBe(false);
  });
});
