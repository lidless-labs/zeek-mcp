import { describe, it, expect } from "vitest";
import { getMispConfig } from "../src/tools/misp.js";

describe("MISP integration", () => {
  it("should load config from defaults", () => {
    delete process.env.MISP_URL;
    delete process.env.MISP_API_KEY;
    delete process.env.MISP_VERIFY_SSL;

    const config = getMispConfig();

    expect(config.url).toBe("https://localhost");
    expect(config.apiKey).toBe("");
    expect(config.verifySsl).toBe(true);
  });

  it("should load config from environment", () => {
    process.env.MISP_URL = "https://192.0.2.97";
    process.env.MISP_API_KEY = "test-misp-key";
    process.env.MISP_VERIFY_SSL = "false";

    const config = getMispConfig();

    expect(config.url).toBe("https://192.0.2.97");
    expect(config.apiKey).toBe("test-misp-key");
    expect(config.verifySsl).toBe(false);

    delete process.env.MISP_URL;
    delete process.env.MISP_API_KEY;
    delete process.env.MISP_VERIFY_SSL;
  });

  it("should construct IOC search payload", () => {
    const searchBody = {
      returnFormat: "json",
      value: "45.33.32.156",
      limit: 20,
      includeEventTags: true,
    };

    expect(searchBody.value).toBe("45.33.32.156");
    expect(searchBody.returnFormat).toBe("json");
    expect(searchBody.includeEventTags).toBe(true);
  });

  it("should construct bulk lookup payloads", () => {
    const indicators = [
      { value: "192.168.1.50", type: "ip-src", context: "Zeek conn.log source" },
      { value: "evil-domain.xyz", type: "domain", context: "Zeek SSL SNI" },
      { value: "a0e9f5d64349fb13191bc781f81f42e1", type: "md5", context: "JA3 hash" },
    ];

    expect(indicators.length).toBe(3);
    expect(indicators.map((i) => i.type)).toEqual(["ip-src", "domain", "md5"]);
  });

  it("should construct MISP event payload", () => {
    const event = {
      Event: {
        info: "NIDS Detection: Possible C2 Activity",
        threat_level_id: "1",
        analysis: "1",
        distribution: "0",
        Tag: [{ name: "tlp:amber" }, { name: "type:OSINT" }],
        Attribute: [
          { type: "ip-dst", value: "45.33.32.156", category: "Network activity", to_ids: true },
          { type: "domain", value: "evil-domain.xyz", category: "Network activity", to_ids: true },
        ],
      },
    };

    expect(event.Event.info).toContain("C2");
    expect(event.Event.Attribute.length).toBe(2);
    expect(event.Event.Tag.length).toBe(2);
  });

  it("should correctly infer categories for attribute types", () => {
    const categoryMap: Record<string, string> = {
      "ip-src": "Network activity",
      "ip-dst": "Network activity",
      "domain": "Network activity",
      "hostname": "Network activity",
      "url": "Network activity",
      "md5": "Payload delivery",
      "sha256": "Payload delivery",
      "filename": "Payload delivery",
    };

    expect(categoryMap["ip-src"]).toBe("Network activity");
    expect(categoryMap["md5"]).toBe("Payload delivery");
    expect(categoryMap["domain"]).toBe("Network activity");
  });
});
