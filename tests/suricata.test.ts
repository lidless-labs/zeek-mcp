import { describe, it, expect, beforeAll } from "vitest";
import * as path from "node:path";

const TEST_DATA_DIR = path.join(process.cwd(), "test-data");

// Set environment before importing modules
beforeAll(() => {
  process.env.SURICATA_EVE_LOG = path.join(TEST_DATA_DIR, "eve.json");
  process.env.SURICATA_FAST_LOG = path.join(TEST_DATA_DIR, "fast.log");
  process.env.SURICATA_RULES_DIR = path.join(TEST_DATA_DIR, "rules");
});

describe("Suricata eve.json parsing", () => {
  it("should read and filter alert events", async () => {
    const { getSuricataConfig } = await import("../src/tools/suricata.js");
    const config = getSuricataConfig();
    expect(config.eveLogPath).toBe(path.join(TEST_DATA_DIR, "eve.json"));
  });

  it("should parse alert events from eve.json", async () => {
    const fs = await import("fs");
    const readline = await import("readline");

    const filePath = path.join(TEST_DATA_DIR, "eve.json");
    const stream = fs.createReadStream(filePath);
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    const alerts: any[] = [];
    for await (const line of rl) {
      if (!line.trim()) continue;
      const event = JSON.parse(line);
      if (event.event_type === "alert") {
        alerts.push(event);
      }
    }

    expect(alerts.length).toBe(7);
    expect(alerts[0].alert.signature).toBe("GPL ATTACK_RESPONSE id check returned root");
    expect(alerts[0].src_ip).toBe("10.0.0.50");
  });

  it("should parse stats events from eve.json", async () => {
    const fs = await import("fs");
    const readline = await import("readline");

    const filePath = path.join(TEST_DATA_DIR, "eve.json");
    const stream = fs.createReadStream(filePath);
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    const stats: any[] = [];
    for await (const line of rl) {
      if (!line.trim()) continue;
      const event = JSON.parse(line);
      if (event.event_type === "stats") {
        stats.push(event);
      }
    }

    expect(stats.length).toBe(1);
    expect(stats[0].stats.detect.alert).toBe(42);
  });

  it("should filter alerts by severity", async () => {
    const fs = await import("fs");
    const readline = await import("readline");

    const filePath = path.join(TEST_DATA_DIR, "eve.json");
    const stream = fs.createReadStream(filePath);
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    const criticalAlerts: any[] = [];
    for await (const line of rl) {
      if (!line.trim()) continue;
      const event = JSON.parse(line);
      if (event.event_type === "alert" && event.alert?.severity === 1) {
        criticalAlerts.push(event);
      }
    }

    expect(criticalAlerts.length).toBe(3);
    // All severity 1 should be the C2 and EternalBlue alerts
    const sigs = criticalAlerts.map((a: any) => a.alert.signature);
    expect(sigs).toContain("ET MALWARE Possible C2 Activity");
    expect(sigs).toContain("ET EXPLOIT MS17-010 EternalBlue Attempt");
  });

  it("should filter alerts by source IP", async () => {
    const fs = await import("fs");
    const readline = await import("readline");

    const filePath = path.join(TEST_DATA_DIR, "eve.json");
    const stream = fs.createReadStream(filePath);
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    const fromSrc: any[] = [];
    for await (const line of rl) {
      if (!line.trim()) continue;
      const event = JSON.parse(line);
      if (event.event_type === "alert" && event.src_ip === "192.168.1.50") {
        fromSrc.push(event);
      }
    }

    expect(fromSrc.length).toBe(2);
    expect(fromSrc.every((a: any) => a.alert.signature_id === 2024897)).toBe(true);
  });

  it("should extract TLS metadata from alerts", async () => {
    const fs = await import("fs");
    const readline = await import("readline");

    const filePath = path.join(TEST_DATA_DIR, "eve.json");
    const stream = fs.createReadStream(filePath);
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    const tlsAlerts: any[] = [];
    for await (const line of rl) {
      if (!line.trim()) continue;
      const event = JSON.parse(line);
      if (event.event_type === "alert" && event.tls) {
        tlsAlerts.push(event);
      }
    }

    expect(tlsAlerts.length).toBe(2);
    expect(tlsAlerts[0].tls.sni).toBe("evil-domain.xyz");
    expect(tlsAlerts[0].tls.ja3.hash).toBe("a0e9f5d64349fb13191bc781f81f42e1");
  });

  it("should extract HTTP metadata from alerts", async () => {
    const fs = await import("fs");
    const readline = await import("readline");

    const filePath = path.join(TEST_DATA_DIR, "eve.json");
    const stream = fs.createReadStream(filePath);
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    const httpAlerts: any[] = [];
    for await (const line of rl) {
      if (!line.trim()) continue;
      const event = JSON.parse(line);
      if (event.event_type === "alert" && event.http) {
        httpAlerts.push(event);
      }
    }

    expect(httpAlerts.length).toBe(1);
    expect(httpAlerts[0].http.url).toBe("/uid/index.html");
    expect(httpAlerts[0].http.http_user_agent).toBe("curl/7.81.0");
  });
});
