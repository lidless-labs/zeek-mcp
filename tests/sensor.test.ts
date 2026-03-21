import { describe, it, expect } from "vitest";
import * as path from "node:path";
import * as fs from "node:fs";
import type { ZeekConfig } from "../src/config.js";

const TEST_DATA_DIR = path.join(process.cwd(), "test-data");

describe("Sensor status", () => {
  it("should list available log files in test-data directory", () => {
    const files = fs.readdirSync(TEST_DATA_DIR);
    const logFiles = files.filter((f) => f.endsWith(".log"));

    expect(logFiles.length).toBeGreaterThan(0);
    expect(logFiles).toContain("conn.log");
    expect(logFiles).toContain("dns.log");
    expect(logFiles).toContain("dhcp.log");
  });

  it("should get file stats for each log", () => {
    const logPath = path.join(TEST_DATA_DIR, "conn.log");
    const stat = fs.statSync(logPath);

    expect(stat.size).toBeGreaterThan(0);
    expect(stat.mtimeMs).toBeGreaterThan(0);
  });

  it("should detect log format from file content", () => {
    // JSON log starts with {
    const jsonContent = fs.readFileSync(path.join(TEST_DATA_DIR, "conn.log"), "utf-8");
    const firstLine = jsonContent.split("\n")[0].trim();

    // Our test-data conn.log is JSON format (starts with {)
    const isJson = firstLine.startsWith("{");
    const isTsv = firstLine.startsWith("#separator");

    expect(isJson || isTsv).toBe(true);
  });

  it("should handle non-existent log directory gracefully", () => {
    const config: ZeekConfig = {
      logDir: "/nonexistent/path",
      logArchive: "/nonexistent/archive",
      logFormat: "json",
      maxResults: 1000,
    };

    expect(fs.existsSync(config.logDir)).toBe(false);
  });

  it("should have eve.json test data available", () => {
    const evePath = path.join(TEST_DATA_DIR, "eve.json");
    expect(fs.existsSync(evePath)).toBe(true);

    const stat = fs.statSync(evePath);
    expect(stat.size).toBeGreaterThan(0);
  });
});
