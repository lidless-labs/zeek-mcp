import { describe, it, expect, vi, beforeEach } from "vitest";
import * as path from "node:path";
import type { ZeekConfig } from "../src/config.js";
import { executeQuery } from "../src/query/engine.js";

const TEST_DATA_DIR = path.join(process.cwd(), "test-data");

const testConfig: ZeekConfig = {
  logDir: TEST_DATA_DIR,
  logArchive: TEST_DATA_DIR,
  logFormat: "json",
  maxResults: 1000,
};

describe("Query engine with test data", () => {
  it("should query connection logs", async () => {
    const records = await executeQuery(testConfig, {
      logType: "conn",
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    expect(records[0]).toHaveProperty("uid");
    expect(records[0]).toHaveProperty("id.orig_h");
  });

  it("should filter connections by source IP", async () => {
    const records = await executeQuery(testConfig, {
      logType: "conn",
      filters: [{ field: "id.orig_h", op: "eq", value: "192.168.1.100" }],
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    for (const record of records) {
      expect(record["id.orig_h"]).toBe("192.168.1.100");
    }
  });

  it("should filter connections by CIDR", async () => {
    const records = await executeQuery(testConfig, {
      logType: "conn",
      filters: [{ field: "id.orig_h", op: "cidr", value: "192.168.1.0/24" }],
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    for (const record of records) {
      expect(String(record["id.orig_h"])).toMatch(/^192\.168\.1\./);
    }
  });

  it("should filter connections by protocol", async () => {
    const records = await executeQuery(testConfig, {
      logType: "conn",
      filters: [{ field: "proto", op: "eq", value: "tcp" }],
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    for (const record of records) {
      expect(record.proto).toBe("tcp");
    }
  });

  it("should filter by minimum duration", async () => {
    const records = await executeQuery(testConfig, {
      logType: "conn",
      filters: [{ field: "duration", op: "gte", value: 3600 }],
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    for (const record of records) {
      expect(record.duration as number).toBeGreaterThanOrEqual(3600);
    }
  });

  it("should sort by timestamp descending by default", async () => {
    const records = await executeQuery(testConfig, {
      logType: "conn",
      limit: 100,
    });

    for (let i = 1; i < records.length; i++) {
      expect(records[i - 1].ts).toBeGreaterThanOrEqual(records[i].ts);
    }
  });

  it("should sort by specified field ascending", async () => {
    const records = await executeQuery(testConfig, {
      logType: "conn",
      sortBy: "duration",
      sortOrder: "asc",
      limit: 100,
    });

    for (let i = 1; i < records.length; i++) {
      const prev = records[i - 1].duration;
      const curr = records[i].duration;
      if (prev !== undefined && curr !== undefined) {
        expect(prev as number).toBeLessThanOrEqual(curr as number);
      }
    }
  });

  it("should respect limit parameter", async () => {
    const records = await executeQuery(testConfig, {
      logType: "conn",
      limit: 3,
    });

    expect(records.length).toBeLessThanOrEqual(3);
  });

  it("should query DNS logs", async () => {
    const records = await executeQuery(testConfig, {
      logType: "dns",
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    expect(records[0]).toHaveProperty("query");
  });

  it("should filter DNS by domain wildcard", async () => {
    const records = await executeQuery(testConfig, {
      logType: "dns",
      filters: [{ field: "query", op: "wildcard", value: "*.example.com" }],
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    for (const record of records) {
      expect(String(record.query).toLowerCase()).toContain("example.com");
    }
  });

  it("should filter DNS by response code", async () => {
    const records = await executeQuery(testConfig, {
      logType: "dns",
      filters: [{ field: "rcode_name", op: "eq", value: "NXDOMAIN" }],
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    for (const record of records) {
      expect(record.rcode_name).toBe("NXDOMAIN");
    }
  });

  it("should query HTTP logs", async () => {
    const records = await executeQuery(testConfig, {
      logType: "http",
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    expect(records[0]).toHaveProperty("method");
  });

  it("should filter HTTP by user agent substring", async () => {
    const records = await executeQuery(testConfig, {
      logType: "http",
      filters: [{ field: "user_agent", op: "contains", value: "python" }],
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    for (const record of records) {
      expect(String(record.user_agent).toLowerCase()).toContain("python");
    }
  });

  it("should query SSL logs", async () => {
    const records = await executeQuery(testConfig, {
      logType: "ssl",
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    expect(records[0]).toHaveProperty("version");
  });

  it("should filter SSL by validation status", async () => {
    const records = await executeQuery(testConfig, {
      logType: "ssl",
      filters: [
        { field: "validation_status", op: "contains", value: "self signed" },
      ],
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    for (const record of records) {
      expect(String(record.validation_status)).toContain("self signed");
    }
  });

  it("should query notice logs", async () => {
    const records = await executeQuery(testConfig, {
      logType: "notice",
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    expect(records[0]).toHaveProperty("note");
  });

  it("should query SSH logs", async () => {
    const records = await executeQuery(testConfig, {
      logType: "ssh",
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    expect(records[0]).toHaveProperty("auth_success");
  });

  it("should filter SSH by auth failure", async () => {
    const records = await executeQuery(testConfig, {
      logType: "ssh",
      filters: [{ field: "auth_success", op: "eq", value: false }],
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    for (const record of records) {
      expect(record.auth_success).toBe(false);
    }
  });

  it("should query file logs", async () => {
    const records = await executeQuery(testConfig, {
      logType: "files",
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    expect(records[0]).toHaveProperty("fuid");
  });

  it("should filter files by MIME type", async () => {
    const records = await executeQuery(testConfig, {
      logType: "files",
      filters: [{ field: "mime_type", op: "contains", value: "dosexec" }],
      limit: 100,
    });

    expect(records.length).toBeGreaterThan(0);
    for (const record of records) {
      expect(String(record.mime_type)).toContain("dosexec");
    }
  });

  it("should combine multiple filters (AND logic)", async () => {
    const records = await executeQuery(testConfig, {
      logType: "conn",
      filters: [
        { field: "proto", op: "eq", value: "tcp" },
        { field: "id.orig_h", op: "eq", value: "192.168.1.100" },
      ],
      limit: 100,
    });

    for (const record of records) {
      expect(record.proto).toBe("tcp");
      expect(record["id.orig_h"]).toBe("192.168.1.100");
    }
  });
});

describe("Config", () => {
  it("should load config with defaults", async () => {
    const { getConfig } = await import("../src/config.js");

    delete process.env.ZEEK_LOG_DIR;
    delete process.env.ZEEK_LOG_ARCHIVE;
    delete process.env.ZEEK_LOG_FORMAT;
    delete process.env.ZEEK_MAX_RESULTS;

    const config = getConfig();

    expect(config.logDir).toBe("/opt/zeek/logs/current");
    expect(config.logArchive).toBe("/opt/zeek/logs");
    expect(config.logFormat).toBe("json");
    expect(config.maxResults).toBe(1000);
  });

  it("should load config from environment", async () => {
    const { getConfig } = await import("../src/config.js");

    process.env.ZEEK_LOG_DIR = "/custom/logs";
    process.env.ZEEK_LOG_ARCHIVE = "/custom/archive";
    process.env.ZEEK_LOG_FORMAT = "tsv";
    process.env.ZEEK_MAX_RESULTS = "500";

    const config = getConfig();

    expect(config.logDir).toBe("/custom/logs");
    expect(config.logArchive).toBe("/custom/archive");
    expect(config.logFormat).toBe("tsv");
    expect(config.maxResults).toBe(500);

    delete process.env.ZEEK_LOG_DIR;
    delete process.env.ZEEK_LOG_ARCHIVE;
    delete process.env.ZEEK_LOG_FORMAT;
    delete process.env.ZEEK_MAX_RESULTS;
  });
});
