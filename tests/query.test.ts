import { describe, it, expect, vi, afterEach } from "vitest";
import {
  matchCidr,
  matchWildcard,
  matchPartial,
  inRange,
  matchIp,
} from "../src/query/filters.js";
import {
  groupBy,
  sumField,
  avgField,
  countUnique,
  topN,
  getNestedValue,
} from "../src/query/aggregation.js";
import { gzipSync } from "node:zlib";
import { execFileSync } from "node:child_process";
import { BoundedBuffer } from "../src/query/bounded-buffer.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { executeQuery } from "../src/query/engine.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerBaselineTools } from "../src/tools/baseline.js";
import { registerInvestigationTools } from "../src/tools/investigation.js";
import { registerConnectionTools } from "../src/tools/connections.js";
import type { ZeekRecord } from "../src/types.js";

describe("CIDR matching", () => {
  it("should match exact IP", () => {
    expect(matchCidr("192.168.1.100", "192.168.1.100")).toBe(true);
    expect(matchCidr("192.168.1.100", "192.168.1.101")).toBe(false);
  });

  it("should match /24 CIDR", () => {
    expect(matchCidr("192.168.1.100", "192.168.1.0/24")).toBe(true);
    expect(matchCidr("192.168.1.255", "192.168.1.0/24")).toBe(true);
    expect(matchCidr("192.168.2.1", "192.168.1.0/24")).toBe(false);
  });

  it("should match /16 CIDR", () => {
    expect(matchCidr("10.0.5.100", "10.0.0.0/16")).toBe(true);
    expect(matchCidr("10.1.0.1", "10.0.0.0/16")).toBe(false);
  });

  it("should match /8 CIDR", () => {
    expect(matchCidr("10.255.255.255", "10.0.0.0/8")).toBe(true);
    expect(matchCidr("11.0.0.1", "10.0.0.0/8")).toBe(false);
  });

  it("should handle /32 CIDR (exact match)", () => {
    expect(matchCidr("192.168.1.1", "192.168.1.1/32")).toBe(true);
    expect(matchCidr("192.168.1.2", "192.168.1.1/32")).toBe(false);
  });

  it("should handle /0 CIDR (match all)", () => {
    expect(matchCidr("1.2.3.4", "0.0.0.0/0")).toBe(true);
    expect(matchCidr("255.255.255.255", "0.0.0.0/0")).toBe(true);
  });

  it("should return false for invalid IPs", () => {
    expect(matchCidr("not-an-ip", "192.168.1.0/24")).toBe(false);
    expect(matchCidr("192.168.1.1", "not-a-cidr/24")).toBe(false);
  });
});

describe("Wildcard matching", () => {
  it("should match exact strings", () => {
    expect(matchWildcard("example.com", "example.com")).toBe(true);
    expect(matchWildcard("example.com", "example.org")).toBe(false);
  });

  it("should be case insensitive", () => {
    expect(matchWildcard("Example.COM", "example.com")).toBe(true);
  });

  it("should match leading wildcard", () => {
    expect(matchWildcard("sub.evil.com", "*.evil.com")).toBe(true);
    expect(matchWildcard("deep.sub.evil.com", "*.evil.com")).toBe(true);
    expect(matchWildcard("evil.com", "*.evil.com")).toBe(false);
  });

  it("should match trailing wildcard", () => {
    expect(matchWildcard("api.example.com", "api.*")).toBe(true);
    expect(matchWildcard("web.example.com", "api.*")).toBe(false);
  });

  it("should match middle wildcard", () => {
    expect(matchWildcard("www.example.com", "www.*.com")).toBe(true);
    expect(matchWildcard("www.test.com", "www.*.com")).toBe(true);
  });
});

describe("Partial matching", () => {
  it("should match substrings", () => {
    expect(matchPartial("Mozilla/5.0 (Windows)", "mozilla")).toBe(true);
    expect(matchPartial("python-requests/2.28", "python")).toBe(true);
    expect(matchPartial("curl/7.68.0", "wget")).toBe(false);
  });

  it("should be case insensitive", () => {
    expect(matchPartial("User-Agent", "user-agent")).toBe(true);
  });
});

describe("Range checking", () => {
  it("should check minimum value", () => {
    expect(inRange(100, 50)).toBe(true);
    expect(inRange(50, 100)).toBe(false);
  });

  it("should check maximum value", () => {
    expect(inRange(50, undefined, 100)).toBe(true);
    expect(inRange(150, undefined, 100)).toBe(false);
  });

  it("should check both bounds", () => {
    expect(inRange(75, 50, 100)).toBe(true);
    expect(inRange(25, 50, 100)).toBe(false);
    expect(inRange(150, 50, 100)).toBe(false);
  });

  it("should handle undefined values", () => {
    expect(inRange(undefined, 50)).toBe(false);
  });
});

describe("matchIp", () => {
  it("should match exact IP", () => {
    expect(matchIp("192.168.1.1", "192.168.1.1")).toBe(true);
    expect(matchIp("192.168.1.2", "192.168.1.1")).toBe(false);
  });

  it("should match CIDR ranges", () => {
    expect(matchIp("192.168.1.100", "192.168.1.0/24")).toBe(true);
    expect(matchIp("10.0.0.1", "192.168.1.0/24")).toBe(false);
  });
});

describe("Aggregation", () => {
  const testRecords: ZeekRecord[] = [
    { ts: 1, "id.orig_h": "192.168.1.1", "id.resp_p": 80, service: "http", orig_bytes: 100 },
    { ts: 2, "id.orig_h": "192.168.1.1", "id.resp_p": 443, service: "ssl", orig_bytes: 200 },
    { ts: 3, "id.orig_h": "192.168.1.2", "id.resp_p": 80, service: "http", orig_bytes: 300 },
    { ts: 4, "id.orig_h": "192.168.1.2", "id.resp_p": 22, service: "ssh", orig_bytes: 50 },
    { ts: 5, "id.orig_h": "192.168.1.3", "id.resp_p": 80, service: "http", orig_bytes: 150 },
  ];

  it("should group by field", () => {
    const result = groupBy(testRecords, "service");
    expect(result.total).toBe(5);
    expect(result.groups[0].key).toBe("http");
    expect(result.groups[0].count).toBe(3);
    expect(result.groups[0].percentage).toBe(60);
  });

  it("should sum a numeric field", () => {
    const total = sumField(testRecords, "orig_bytes");
    expect(total).toBe(800);
  });

  it("should average a numeric field", () => {
    const avg = avgField(testRecords, "orig_bytes");
    expect(avg).toBe(160);
  });

  it("should count unique values", () => {
    expect(countUnique(testRecords, "id.orig_h")).toBe(3);
    expect(countUnique(testRecords, "service")).toBe(3);
  });

  it("should get top N values", () => {
    const top = topN(testRecords, "service", 2);
    expect(top).toHaveLength(2);
    expect(top[0].value).toBe("http");
    expect(top[0].count).toBe(3);
  });

  it("should get nested values using dot notation", () => {
    const record: ZeekRecord = {
      ts: 1,
      "id.orig_h": "192.168.1.1",
      nested: { deep: { value: "found" } },
    };

    expect(getNestedValue(record, "id.orig_h")).toBe("192.168.1.1");
    expect(getNestedValue(record, "ts")).toBe(1);
  });

  it("should limit group results", () => {
    const result = groupBy(testRecords, "id.orig_h", 2);
    expect(result.groups).toHaveLength(2);
  });
});


describe("bounded streaming queries", () => {
  const roots: string[] = [];
  afterEach(() => {
    vi.restoreAllMocks();
    for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
  });
  function fixture(records: ZeekRecord[]) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "example-zeek-query-"));
    roots.push(root);
    fs.writeFileSync(path.join(root, "conn.log"), records.map((r) => JSON.stringify(r)).join("\n"));
    return { logDir: root, logArchive: root, logFormat: "json" as const, maxResults: 1000 };
  }

  it("keeps at most 10 records while querying a generated 200000-record log", async () => {
    const config = fixture([]);
    execFileSync(process.execPath, ["--import", "tsx", "scripts/generate-zeek-logs.ts", `--output=${config.logDir}`, "--fixture-count=200000"], { stdio: "ignore" });
    let peak = 0;
    const add = BoundedBuffer.prototype.add;
    let offered = 0;
    BoundedBuffer.prototype.add = function (item) {
      add.call(this, item);
      offered++;
      peak = Math.max(peak, this.size);
    };
    try {
      const records = await executeQuery(config, { logType: "conn", limit: 10 });
      expect(offered).toBe(200000);
      expect(peak).toBe(10);
      expect(records.map((r) => r.ts)).toEqual(Array.from({ length: 10 }, (_, i) => 199999 - i));
      expect(records.truncated).toBeUndefined();
    } finally {
      BoundedBuffer.prototype.add = add;
    }
  }, 15000);

  it("scans current data and later archive rotations first within a global budget", async () => {
    const base = new Date("2024-02-01T12:00:00").getTime() / 1000;
    const config = fixture([{ ts: base + 100, uid: "example-current" }]);
    const archive = path.join(config.logArchive, "2024-02-01");
    fs.mkdirSync(archive);
    fs.writeFileSync(path.join(archive, "conn.12:00:00-13:00:00.log"), JSON.stringify({ ts: base + 50, uid: "example-later" }));
    fs.writeFileSync(path.join(archive, "conn.11:00:00-12:00:00.log"), JSON.stringify({ ts: base, uid: "example-earlier" }));
    const records = await executeQuery({ ...config, maxScan: 2 }, { logType: "conn", timeFrom: new Date(base * 1000).toISOString(), timeTo: new Date((base + 1800) * 1000).toISOString(), limit: 10 });
    expect(records.truncated).toBe(true);
    expect(records.map((r) => r.uid)).toEqual(["example-current", "example-later"]);
    fs.writeFileSync(path.join(config.logDir, "conn.log.gz"), gzipSync(JSON.stringify({ ts: base, uid: "example-compressed" })));
    const current = await executeQuery({ ...config, maxScan: 1 }, { logType: "conn", limit: 10 });
    expect(current.map((r) => r.uid)).toEqual(["example-current"]);
  });

  it.each([undefined, "duration"])("stops at the scan cap before filtering and exposes truncation (sort=%s)", async (sortBy) => {
    const config = fixture(Array.from({ length: 30 }, (_, i) => ({ ts: i, duration: 30 - i, proto: i >= 10 ? "udp" : "tcp" })));
    const records = await executeQuery({ ...config, maxScan: 10 }, { logType: "conn", limit: 3, sortBy, filters: [{ field: "proto", op: "eq", value: "udp" }] });
    expect(records).toHaveLength(0);
    expect(records.truncated).toBe(true);
  });

  it("preserves stable ordering, filters, and all sort modes on small inputs", async () => {
    const input = [{ ts: 3, duration: 2, uid: "example-a" }, { ts: 1, uid: "example-b" }, { ts: 3, duration: 4, uid: "example-c" }, { ts: 2, duration: 1, uid: "example-d" }];
    const config = fixture(input);
    expect((await executeQuery(config, { logType: "conn", limit: 2 })).map((r) => r.uid)).toEqual(["example-a", "example-c"]);
    expect((await executeQuery(config, { logType: "conn", sortOrder: "asc" })).map((r) => r.uid)).toEqual(["example-b", "example-d", "example-a", "example-c"]);
    expect((await executeQuery(config, { logType: "conn", sortBy: "duration" })).map((r) => r.uid)).toEqual(["example-c", "example-a", "example-d", "example-b"]);
    expect((await executeQuery(config, { logType: "conn", filters: [{ field: "duration", op: "gte", value: 2 }] })).map((r) => r.uid)).toEqual(["example-a", "example-c"]);
  });

  it("reports scan truncation in the MCP tool response even with no matches", async () => {
    const config = fixture(Array.from({ length: 30 }, (_, ts) => ({ ts, proto: "tcp" })));
    const server = new McpServer({ name: "example", version: "1.0.0" });
    registerConnectionTools(server, { ...config, maxScan: 10 });
    registerBaselineTools(server, { ...config, maxScan: 10 });
    registerInvestigationTools(server, { ...config, maxScan: 10 });
    const client = new Client({ name: "example-client", version: "1.0.0" });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await server.connect(b);
    await client.connect(a);
    try {
      const result = await client.callTool({ name: "zeek_query_connections", arguments: { proto: "udp", limit: 10 } });
      expect(result.isError).not.toBe(true);
      expect(JSON.parse((result.content as Array<{ text: string }>)[0].text)).toEqual({ count: 0, connections: [], truncated: true });
      for (const [name, args] of [
        ["zeek_network_baseline", { timeFrom: "2024-02-01T12:00:00Z", timeTo: "2024-02-01T12:30:00Z" }],
        ["zeek_investigate_host", { ip: "192.0.2.1" }],
        ["zeek_investigate_uid", { uid: "example-missing" }],
      ] as const) {
        const analysis = await client.callTool({ name, arguments: args });
        expect(analysis.isError).not.toBe(true);
        expect(JSON.parse((analysis.content as Array<{ text: string }>)[0].text).truncated).toBe(true);
      }
    } finally {
      await client.close();
      await server.close();
    }
  });
});
