import { describe, it, expect } from "vitest";
import { getTheHiveConfig } from "../src/tools/thehive.js";

describe("TheHive integration", () => {
  it("should load config from defaults", () => {
    delete process.env.THEHIVE_URL;
    delete process.env.THEHIVE_API_KEY;

    const config = getTheHiveConfig();

    expect(config.url).toBe("http://localhost:9000");
    expect(config.apiKey).toBe("");
  });

  it("should load config from environment", () => {
    process.env.THEHIVE_URL = "http://192.0.2.94:9000";
    process.env.THEHIVE_API_KEY = "test-key-123";

    const config = getTheHiveConfig();

    expect(config.url).toBe("http://192.0.2.94:9000");
    expect(config.apiKey).toBe("test-key-123");

    delete process.env.THEHIVE_URL;
    delete process.env.THEHIVE_API_KEY;
  });

  it("should construct correct alert payload", () => {
    const alert = {
      title: "Suspicious C2 Activity Detected",
      description: "Host 192.168.1.50 communicating with known C2 at 45.33.32.156",
      severity: 3,
      tlp: 2,
      pap: 2,
      type: "nids-alert",
      source: "zeek-mcp",
      sourceRef: "SID-2024897",
      tags: ["nids", "c2", "zeek-mcp"],
    };

    expect(alert.title).toContain("C2");
    expect(alert.severity).toBe(3);
    expect(alert.tags).toContain("nids");
    expect(alert.sourceRef).toBe("SID-2024897");
  });

  it("should construct correct case payload with tasks", () => {
    const casePayload = {
      title: "C2 Communication Investigation",
      description: "Investigating potential C2 beaconing from internal host",
      severity: 3,
      tlp: 2,
      pap: 2,
      tags: ["nids", "investigation"],
      tasks: [
        { title: "Verify Zeek connection logs", group: "analysis" },
        { title: "Check DNS queries for DGA", group: "analysis" },
        { title: "Review Suricata alerts", group: "correlation" },
        { title: "MISP IOC lookup", group: "threat-intel" },
      ],
    };

    expect(casePayload.tasks.length).toBe(4);
    expect(casePayload.tasks[0].title).toContain("Zeek");
  });

  it("should format observables correctly", () => {
    const observables = [
      { dataType: "ip" as const, data: "192.168.1.50", message: "Source of C2 traffic", ioc: true },
      { dataType: "ip" as const, data: "45.33.32.156", message: "C2 server", ioc: true },
      { dataType: "domain" as const, data: "evil-domain.xyz", message: "C2 domain from SNI", ioc: true },
      { dataType: "hash" as const, data: "a0e9f5d64349fb13191bc781f81f42e1", message: "JA3 fingerprint", ioc: false },
    ];

    expect(observables.length).toBe(4);
    expect(observables.filter((o) => o.ioc).length).toBe(3);
    expect(observables.map((o) => o.dataType)).toEqual(["ip", "ip", "domain", "hash"]);
  });
});
