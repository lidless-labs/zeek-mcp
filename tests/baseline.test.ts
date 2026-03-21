import { describe, it, expect } from "vitest";
import * as path from "node:path";
import { executeQuery } from "../src/query/engine.js";
import type { ZeekConfig } from "../src/config.js";
import type { ZeekRecord } from "../src/types.js";

const TEST_DATA_DIR = path.join(process.cwd(), "test-data");

const testConfig: ZeekConfig = {
  logDir: TEST_DATA_DIR,
  logArchive: TEST_DATA_DIR,
  logFormat: "json",
  maxResults: 1000,
};

describe("Baseline generation", () => {
  it("should calculate basic statistics", () => {
    const values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];

    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
    const stdDev = Math.sqrt(variance);

    expect(mean).toBe(55);
    expect(stdDev).toBeCloseTo(28.72, 1);
  });

  it("should have enough test data for baseline", async () => {
    const records = await executeQuery(testConfig, {
      logType: "conn",
      limit: 1000,
    });

    expect(records.length).toBeGreaterThan(5);
  });

  it("should classify internal vs external IPs", () => {
    const internalPrefixes = ["10.", "172.16.", "192.168.", "fe80:"];
    const isInternal = (ip: string) => internalPrefixes.some((p) => ip.startsWith(p));

    expect(isInternal("192.168.1.100")).toBe(true);
    expect(isInternal("10.0.0.1")).toBe(true);
    expect(isInternal("172.16.0.1")).toBe(true);
    expect(isInternal("93.184.216.34")).toBe(false);
    expect(isInternal("8.8.8.8")).toBe(false);
    expect(isInternal("fe80::1")).toBe(true);
  });

  it("should compute hourly distribution from timestamps", () => {
    const timestamps = [
      1706745600,  // 2024-02-01 00:00 UTC
      1706749200,  // 2024-02-01 01:00 UTC
      1706749200,  // 2024-02-01 01:00 UTC
      1706752800,  // 2024-02-01 02:00 UTC
    ];

    const hourCounts: number[] = new Array(24).fill(0);
    for (const ts of timestamps) {
      const hour = new Date(ts * 1000).getUTCHours();
      hourCounts[hour]++;
    }

    expect(hourCounts[0]).toBe(1);
    expect(hourCounts[1]).toBe(2);
    expect(hourCounts[2]).toBe(1);
    expect(hourCounts[3]).toBe(0);
  });
});

describe("Outlier detection", () => {
  it("should detect byte volume outliers", () => {
    // 10 normal hosts at ~1KB, 1 outlier at 100MB
    const srcBytes = new Map<string, number>();
    for (let i = 0; i < 10; i++) {
      srcBytes.set(`192.168.1.${i + 10}`, 1024 + Math.floor(Math.random() * 512));
    }
    srcBytes.set("192.168.1.200", 104857600); // 100MB outlier

    const values = [...srcBytes.values()];
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
    const stdDev = Math.sqrt(variance);

    const outliers = [...srcBytes.entries()].filter(([, bytes]) => {
      const devs = (bytes - mean) / stdDev;
      return devs >= 3;
    });

    expect(outliers.length).toBe(1);
    expect(outliers[0][0]).toBe("192.168.1.200");
  });

  it("should detect connection count outliers", () => {
    const srcConns = new Map<string, number>();
    for (let i = 0; i < 10; i++) {
      srcConns.set(`10.0.0.${i}`, 5 + Math.floor(Math.random() * 5));
    }
    srcConns.set("10.0.0.99", 500); // Outlier

    const values = [...srcConns.values()];
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
    const stdDev = Math.sqrt(variance);

    const outliers = [...srcConns.entries()].filter(([, count]) => {
      return stdDev > 0 && (count - mean) / stdDev >= 3;
    });

    expect(outliers.length).toBe(1);
    expect(outliers[0][0]).toBe("10.0.0.99");
  });

  it("should detect port diversity outliers (potential scanning)", () => {
    const srcPorts = new Map<string, Set<number>>();

    // Normal hosts hit 2-5 ports
    for (let i = 0; i < 10; i++) {
      const ports = new Set<number>();
      const count = 2 + Math.floor(Math.random() * 4);
      for (let j = 0; j < count; j++) {
        ports.add([80, 443, 8080, 3000, 8443][j % 5]);
      }
      srcPorts.set(`192.168.1.${i}`, ports);
    }

    // Scanner hits 200 ports
    const scannerPorts = new Set<number>();
    for (let p = 1; p <= 200; p++) scannerPorts.add(p);
    srcPorts.set("192.168.1.99", scannerPorts);

    const values = [...srcPorts.values()].map((s) => s.size);
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
    const stdDev = Math.sqrt(variance);

    const outliers = [...srcPorts.entries()].filter(([, ports]) => {
      return stdDev > 0 && (ports.size - mean) / stdDev >= 3 && ports.size > 20;
    });

    expect(outliers.length).toBe(1);
    expect(outliers[0][0]).toBe("192.168.1.99");
    expect(outliers[0][1].size).toBe(200);
  });

  it("should not flag when all hosts are similar", () => {
    const srcBytes = new Map<string, number>();
    for (let i = 0; i < 10; i++) {
      srcBytes.set(`10.0.0.${i}`, 1000 + Math.floor(Math.random() * 100));
    }

    const values = [...srcBytes.values()];
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
    const stdDev = Math.sqrt(variance);

    const outliers = [...srcBytes.entries()].filter(([, bytes]) => {
      return stdDev > 0 && (bytes - mean) / stdDev >= 3;
    });

    expect(outliers.length).toBe(0);
  });
});
