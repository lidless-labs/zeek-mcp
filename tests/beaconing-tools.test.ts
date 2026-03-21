import { describe, it, expect } from "vitest";
import { detectBeaconing } from "../src/analytics/beaconing.js";
import { detectConnectionAnomalies } from "../src/analytics/anomaly.js";
import type { ZeekRecord } from "../src/types.js";

describe("Beaconing detection (tool-level)", () => {
  it("should score perfectly regular beaconing as CRITICAL", () => {
    const records: ZeekRecord[] = [];
    const baseTime = 1706745600;

    // Perfect 60-second beacon
    for (let i = 0; i < 30; i++) {
      records.push({
        ts: baseTime + i * 60,
        uid: `C${i}`,
        "id.orig_h": "192.168.1.50",
        "id.orig_p": 50000 + i,
        "id.resp_h": "185.100.87.202",
        "id.resp_p": 443,
        proto: "tcp",
        orig_bytes: 256,
        resp_bytes: 512,
      });
    }

    const candidates = detectBeaconing(records, 10, 30);

    expect(candidates.length).toBeGreaterThan(0);
    const top = candidates[0];
    // Score formula: regularity*0.7 + volume*0.3. 30 conns = volume 15, regularity ~100
    // So score ~74.5 for perfect regularity with 30 connections
    expect(top.score).toBeGreaterThanOrEqual(70);
    expect(top.jitter).toBeLessThan(1);
    expect(top.avgInterval).toBeCloseTo(60, 0);
    expect(top.connectionCount).toBe(30);
  });

  it("should detect beaconing with slight jitter", () => {
    const records: ZeekRecord[] = [];
    const baseTime = 1706745600;

    // 300-second beacon with +-15 seconds jitter
    for (let i = 0; i < 20; i++) {
      const jitter = (Math.random() - 0.5) * 30;
      records.push({
        ts: baseTime + i * 300 + jitter,
        uid: `C${i}`,
        "id.orig_h": "10.0.0.25",
        "id.orig_p": 50000 + i,
        "id.resp_h": "203.0.113.50",
        "id.resp_p": 8443,
        proto: "tcp",
        orig_bytes: 128,
        resp_bytes: 64,
      });
    }

    const candidates = detectBeaconing(records, 10, 30);

    expect(candidates.length).toBeGreaterThan(0);
    expect(candidates[0].avgInterval).toBeCloseTo(300, -1);
    expect(candidates[0].score).toBeGreaterThan(50);
  });

  it("should not flag legitimate web browsing as beaconing", () => {
    const records: ZeekRecord[] = [];
    const baseTime = 1706745600;

    // Random browsing pattern to multiple destinations
    for (let i = 0; i < 50; i++) {
      records.push({
        ts: baseTime + Math.random() * 3600,
        uid: `C${i}`,
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 50000 + i,
        "id.resp_h": `93.184.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
        "id.resp_p": 443,
        proto: "tcp",
        orig_bytes: Math.floor(Math.random() * 10000),
        resp_bytes: Math.floor(Math.random() * 100000),
      });
    }

    // Each dst is unique, so no pair should have enough connections
    const candidates = detectBeaconing(records, 10, 10);
    expect(candidates.length).toBe(0);
  });

  it("should handle multiple beacon pairs in same dataset", () => {
    const records: ZeekRecord[] = [];
    const baseTime = 1706745600;

    // Beacon 1: 60-second interval
    for (let i = 0; i < 15; i++) {
      records.push({
        ts: baseTime + i * 60,
        uid: `CA${i}`,
        "id.orig_h": "192.168.1.10",
        "id.orig_p": 50000 + i,
        "id.resp_h": "10.10.10.10",
        "id.resp_p": 443,
        proto: "tcp",
        orig_bytes: 100,
        resp_bytes: 200,
      });
    }

    // Beacon 2: 120-second interval
    for (let i = 0; i < 15; i++) {
      records.push({
        ts: baseTime + i * 120,
        uid: `CB${i}`,
        "id.orig_h": "192.168.1.20",
        "id.orig_p": 60000 + i,
        "id.resp_h": "10.10.10.20",
        "id.resp_p": 8080,
        proto: "tcp",
        orig_bytes: 50,
        resp_bytes: 100,
      });
    }

    const candidates = detectBeaconing(records, 10, 30);

    expect(candidates.length).toBe(2);
    const ips = candidates.map((c) => c.srcIp);
    expect(ips).toContain("192.168.1.10");
    expect(ips).toContain("192.168.1.20");
  });
});

describe("Anomaly detection (tool-level)", () => {
  it("should detect port scanning across many ports", () => {
    const records: ZeekRecord[] = [];

    for (let port = 1; port <= 200; port++) {
      records.push({
        ts: 1706745600 + port,
        uid: `Cscan${port}`,
        "id.orig_h": "10.0.0.99",
        "id.orig_p": 40000 + port,
        "id.resp_h": "192.168.1.1",
        "id.resp_p": port,
        proto: "tcp",
        conn_state: "S0",
      });
    }

    const anomalies = detectConnectionAnomalies(records);
    const scans = anomalies.filter((a) => a.type === "port_scan");

    expect(scans.length).toBe(1);
    // 200 ports is medium (>200 is high threshold in anomaly.ts)
    expect(["medium", "high"]).toContain(scans[0].severity);
    expect(scans[0].details.portsScanned).toBe(200);
  });

  it("should detect data exfiltration outliers", () => {
    const records: ZeekRecord[] = [];

    // 20 normal hosts with ~1KB each
    for (let i = 0; i < 20; i++) {
      records.push({
        ts: 1706745600 + i,
        uid: `Cnorm${i}`,
        "id.orig_h": `192.168.1.${i + 10}`,
        "id.orig_p": 50000,
        "id.resp_h": "93.184.216.34",
        "id.resp_p": 443,
        proto: "tcp",
        orig_bytes: 1024,
        conn_state: "SF",
      });
    }

    // 1 host sending 500MB (exfiltration)
    records.push({
      ts: 1706745620,
      uid: "Cexfil",
      "id.orig_h": "192.168.1.200",
      "id.orig_p": 50000,
      "id.resp_h": "203.0.113.50",
      "id.resp_p": 443,
      proto: "tcp",
      orig_bytes: 524288000, // 500MB
      conn_state: "SF",
    });

    const anomalies = detectConnectionAnomalies(records);
    const exfil = anomalies.filter((a) => a.type === "data_exfiltration");

    expect(exfil.length).toBe(1);
    expect(exfil[0].details.sourceIp).toBe("192.168.1.200");
  });

  it("should detect unusual ports with high connection counts", () => {
    const records: ZeekRecord[] = [];

    // 50 connections to unusual port 31337 with no service
    for (let i = 0; i < 50; i++) {
      records.push({
        ts: 1706745600 + i,
        uid: `Cweird${i}`,
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 50000 + i,
        "id.resp_h": "10.0.0.1",
        "id.resp_p": 31337,
        proto: "tcp",
        conn_state: "SF",
      });
    }

    const anomalies = detectConnectionAnomalies(records);
    const unusual = anomalies.filter((a) => a.type === "unusual_port");

    expect(unusual.length).toBeGreaterThan(0);
    expect(unusual[0].details.port).toBe(31337);
  });

  it("should not flag common ports as unusual", () => {
    const records: ZeekRecord[] = [];

    // Many connections to port 443 (common)
    for (let i = 0; i < 100; i++) {
      records.push({
        ts: 1706745600 + i,
        uid: `Cnorm${i}`,
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 50000 + i,
        "id.resp_h": "93.184.216.34",
        "id.resp_p": 443,
        proto: "tcp",
        service: "ssl",
        conn_state: "SF",
      });
    }

    const anomalies = detectConnectionAnomalies(records);
    const unusual = anomalies.filter((a) => a.type === "unusual_port");

    expect(unusual.length).toBe(0);
  });
});
