import { describe, it, expect } from "vitest";
import {
  shannonEntropy,
  domainLabelEntropy,
  detectEncoding,
} from "../src/analytics/entropy.js";
import { detectBeaconing } from "../src/analytics/beaconing.js";
import { detectConnectionAnomalies } from "../src/analytics/anomaly.js";
import type { ZeekRecord } from "../src/types.js";

describe("Shannon entropy", () => {
  it("should return 0 for empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("should return 0 for single character repeated", () => {
    expect(shannonEntropy("aaaaaaa")).toBe(0);
  });

  it("should return 1 for two equally distributed characters", () => {
    const entropy = shannonEntropy("ab");
    expect(entropy).toBeCloseTo(1.0, 5);
  });

  it("should return higher entropy for more random strings", () => {
    const lowEntropy = shannonEntropy("aaaaabbbbb");
    const highEntropy = shannonEntropy("xk2jf9a3mz");

    expect(highEntropy).toBeGreaterThan(lowEntropy);
  });

  it("should detect high entropy in base64-like strings", () => {
    const b64 = shannonEntropy(
      "aGVsbG8td29ybGQtdGhpcy1pcy1hLXZlcnktbG9uZy1zdWJkb21haW4",
    );
    expect(b64).toBeGreaterThan(3.5);
  });

  it("should show normal English text has moderate entropy", () => {
    const english = shannonEntropy("thequickbrownfoxjumpsoverthelazydog");
    expect(english).toBeGreaterThan(3.0);
    expect(english).toBeLessThan(5.0);
  });
});

describe("Domain label entropy", () => {
  it("should calculate entropy of subdomain labels", () => {
    const normalEntropy = domainLabelEntropy("www.example.com");
    const suspiciousEntropy = domainLabelEntropy(
      "xk2jf9a3mz.badsite.net",
    );

    expect(suspiciousEntropy).toBeGreaterThan(normalEntropy);
  });

  it("should handle domains with no subdomain", () => {
    const entropy = domainLabelEntropy("example.com");
    expect(entropy).toBeGreaterThan(0);
  });
});

describe("Encoding detection", () => {
  it("should detect base64", () => {
    expect(
      detectEncoding("aGVsbG8td29ybGQtdGhpcw=="),
    ).toBe("base64");
  });

  it("should detect hex", () => {
    expect(detectEncoding("48656c6c6f576f726c64")).toBe("hex");
  });

  it("should return null for normal strings", () => {
    expect(detectEncoding("hello")).toBeNull();
    expect(detectEncoding("www")).toBeNull();
  });

  it("should return null for short strings", () => {
    expect(detectEncoding("abc")).toBeNull();
    expect(detectEncoding("0a1b")).toBeNull();
  });
});

describe("Beaconing detection", () => {
  it("should detect regular interval connections", () => {
    const records: ZeekRecord[] = [];
    const baseTime = 1706745600;

    for (let i = 0; i < 20; i++) {
      records.push({
        ts: baseTime + i * 60,
        uid: `C${i}`,
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 50000 + i,
        "id.resp_h": "45.33.32.156",
        "id.resp_p": 443,
        proto: "tcp",
        orig_bytes: 100,
        resp_bytes: 200,
      });
    }

    const candidates = detectBeaconing(records, 10, 30);

    expect(candidates.length).toBeGreaterThan(0);
    expect(candidates[0].srcIp).toBe("192.168.1.100");
    expect(candidates[0].dstIp).toBe("45.33.32.156");
    expect(candidates[0].avgInterval).toBeCloseTo(60, 0);
    expect(candidates[0].jitter).toBeLessThan(1);
  });

  it("should not flag random connections", () => {
    const records: ZeekRecord[] = [];
    const baseTime = 1706745600;

    for (let i = 0; i < 15; i++) {
      records.push({
        ts: baseTime + Math.random() * 86400,
        uid: `C${i}`,
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 50000 + i,
        "id.resp_h": "93.184.216.34",
        "id.resp_p": 80,
        proto: "tcp",
        orig_bytes: 100,
        resp_bytes: 200,
      });
    }

    const candidates = detectBeaconing(records, 10, 5);
    const highScore = candidates.filter((c) => c.score > 90);
    expect(highScore.length).toBe(0);
  });

  it("should require minimum connection count", () => {
    const records: ZeekRecord[] = [
      {
        ts: 1706745600,
        uid: "C1",
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 50000,
        "id.resp_h": "10.0.0.1",
        "id.resp_p": 443,
        proto: "tcp",
      },
      {
        ts: 1706745660,
        uid: "C2",
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 50001,
        "id.resp_h": "10.0.0.1",
        "id.resp_p": 443,
        proto: "tcp",
      },
    ];

    const candidates = detectBeaconing(records, 10, 30);
    expect(candidates.length).toBe(0);
  });
});

describe("Anomaly detection", () => {
  it("should detect port scanning", () => {
    const records: ZeekRecord[] = [];

    for (let port = 1; port <= 100; port++) {
      records.push({
        ts: 1706745600 + port,
        uid: `C${port}`,
        "id.orig_h": "192.168.1.50",
        "id.orig_p": 40000 + port,
        "id.resp_h": "10.0.0.1",
        "id.resp_p": port,
        proto: "tcp",
        conn_state: "S0",
      });
    }

    const anomalies = detectConnectionAnomalies(records);
    const portScans = anomalies.filter((a) => a.type === "port_scan");

    expect(portScans.length).toBeGreaterThan(0);
    expect(portScans[0].details.sourceIp).toBe("192.168.1.50");
    expect(portScans[0].details.portsScanned).toBe(100);
  });

  it("should not flag normal connection patterns", () => {
    const records: ZeekRecord[] = [
      {
        ts: 1706745600,
        uid: "C1",
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 52341,
        "id.resp_h": "93.184.216.34",
        "id.resp_p": 443,
        proto: "tcp",
        conn_state: "SF",
        orig_bytes: 512,
      },
      {
        ts: 1706745601,
        uid: "C2",
        "id.orig_h": "192.168.1.100",
        "id.orig_p": 52342,
        "id.resp_h": "93.184.216.34",
        "id.resp_p": 80,
        proto: "tcp",
        conn_state: "SF",
        orig_bytes: 256,
      },
    ];

    const anomalies = detectConnectionAnomalies(records);
    const portScans = anomalies.filter((a) => a.type === "port_scan");
    expect(portScans.length).toBe(0);
  });
});
