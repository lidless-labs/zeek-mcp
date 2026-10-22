import { describe, it, expect, vi, afterEach } from "vitest";
import { parseJsonLine, parseJsonLines } from "../src/parser/json.js";
import {
  parseTsvHeader,
  parseTsvRecord,
  parseTsvContent,
} from "../src/parser/tsv.js";
import * as fs from "node:fs";
import * as os from "node:os";
import { gzipSync } from "node:zlib";
import { getConfig } from "../src/config.js";
import { readLogFile, queryLog } from "../src/parser/index.js";
import * as path from "node:path";

vi.mock("node:fs", async (original) => ({ ...await original<typeof import("node:fs")>() }));

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


describe("streaming log bounds", () => {
  const roots: string[] = [];
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
  });
  function fixture() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "example-zeek-parser-"));
    roots.push(root);
    return root;
  }

  it.each([false, true])("filters JSON records before retaining at most the cap (gzip=%s)", async (gzip) => {
    const root = fixture();
    const file = path.join(root, gzip ? "conn.log.gz" : "conn.log");
    const lines = Array.from({ length: 30 }, (_, ts) => JSON.stringify({ ts, uid: `example-${ts}` })).join("\n");
    fs.writeFileSync(file, gzip ? gzipSync(lines) : lines);
    const streams = vi.spyOn(fs, "createReadStream");
    const predicate = vi.fn((r: { ts: number }) => r.ts >= 10);
    const records = await readLogFile(file, "json", predicate, 3);
    expect(records.map((r) => r.ts)).toEqual([10, 11, 12]);
    expect(predicate).toHaveBeenCalledTimes(13);
    expect(streams.mock.results[0].value.destroyed).toBe(true);
  });

  it("applies the same streaming predicate and cap to TSV", async () => {
    const root = fixture();
    const file = path.join(root, "conn.log");
    fs.writeFileSync(file, "#fields\tts\tuid\n#types\ttime\tstring\n" + Array.from({ length: 30 }, (_, ts) => `${ts}\texample-${ts}`).join("\n"));
    const predicate = vi.fn((r: { ts: number }) => r.ts >= 10);
    expect((await readLogFile(file, "tsv", predicate, 3)).map((r) => r.ts)).toEqual([10, 11, 12]);
    expect(predicate).toHaveBeenCalledTimes(13);
  });

  it("charges malformed and comment lines against the scan budget", async () => {
    const root = fixture();
    fs.writeFileSync(path.join(root, "conn.log"), "invalid\n// comment\n".repeat(10) + JSON.stringify({ ts: 1 }));
    const records = await queryLog({ logDir: root, logArchive: root, logFormat: "json", maxResults: 100, maxScan: 10 }, "conn");
    expect(records).toHaveLength(0);
    expect(records.truncated).toBe(true);
  });

  describe("query budgets", () => {
    it.each(["ZEEK_MAX_SCAN", "ZEEK_MAX_DATE_RANGE_DAYS"])("validates %s", (name) => {
      for (const invalid of ["0", "-1", "1.5", "nope", "9007199254740992"]) {
        vi.stubEnv(name, invalid);
        expect(() => getConfig()).toThrow(name);
      }
      vi.stubEnv(name, "7");
      expect(getConfig()[name === "ZEEK_MAX_SCAN" ? "maxScan" : "maxDateRangeDays"]).toBe(7);
    });
  });

  it("rejects a five-year range before filesystem access", async () => {
    const exists = vi.spyOn(fs, "existsSync");
    const read = vi.spyOn(fs, "readdirSync");
    await expect(queryLog({ logDir: "example", logArchive: "example", logFormat: "json", maxResults: 100 }, "conn", "2020-01-01", "2025-01-01")).rejects.toThrow("31 days");
    expect(exists).not.toHaveBeenCalled();
    expect(read).not.toHaveBeenCalled();
  });

  it("retains later rotations containing connections that started in the window", async () => {
    const root = fixture();
    const archive = path.join(root, "2024-02-01");
    fs.mkdirSync(archive);
    const ts = new Date("2024-02-01T12:10:00").getTime() / 1000;
    fs.writeFileSync(path.join(archive, "conn.13:00:00-14:00:00.log.gz"), gzipSync(JSON.stringify({ ts, duration: 3900 })));
    const records = await queryLog({ logDir: root, logArchive: root, logFormat: "json", maxResults: 100 }, "conn", new Date("2024-02-01T12:00:00").toISOString(), new Date("2024-02-01T12:30:00").toISOString());
    expect(records.map((r) => r.ts)).toEqual([ts]);
  });

  it("marks an incomplete gzip read as truncated", async () => {
    const root = fixture();
    const compressed = gzipSync(Array.from({ length: 10000 }, (_, ts) => JSON.stringify({ ts, uid: `example-${ts}` })).join("\n"));
    compressed[compressed.length - 8] ^= 255;
    fs.writeFileSync(path.join(root, "conn.log.gz"), compressed);
    const records = await queryLog({ logDir: root, logArchive: root, logFormat: "json", maxResults: 100 }, "conn");
    expect(records.truncated).toBe(true);
  });

  it("skips rotated files outside the window before opening them", async () => {
    const root = fixture();
    const archive = path.join(root, "2024-02-01");
    fs.mkdirSync(archive);
    const skipped = path.join(archive, "conn.00:00:00-01:00:00.log.gz");
    const kept = path.join(archive, "conn.12:00:00-13:00:00.log.gz");
    fs.writeFileSync(skipped, gzipSync(JSON.stringify({ ts: 1706745600 })));
    fs.writeFileSync(kept, gzipSync(JSON.stringify({ ts: new Date("2024-02-01T12:00:00").getTime() / 1000 })));
    const open = vi.spyOn(fs, "createReadStream");
    const records = await queryLog({ logDir: root, logArchive: root, logFormat: "json", maxResults: 100 }, "conn", new Date("2024-02-01T12:00:00").toISOString(), new Date("2024-02-01T12:30:00").toISOString());
    expect(records.map((r) => r.ts)).toEqual([new Date("2024-02-01T12:00:00").getTime() / 1000]);
    expect(open.mock.calls.map(([file]) => file)).toEqual([kept]);
  });
});
